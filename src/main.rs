use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc};
use std::time::Duration;
use config::ConfigSection;
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, Body, StatusCode};
use rand::random;
use tokio::net::TcpListener;
use docopt::Docopt;

use async_recursion::async_recursion;

use ldap3::{LdapConnAsync, SearchEntry, ResultEntry};
use sha2::{Sha256, Digest};
use lru_time_cache::LruCache;
use tokio::sync::{Mutex, RwLock};
use secrecy::ExposeSecret;

mod config;

const USAGE: &'static str = r#"
ldap_authz_proxy -- HTTP proxy server for LDAP authorization, mainly for Nginx
This program is a HTTP proxy server that checks the authorization of an
already authenticated user against an LDAP server. It can be used to return
attributes from LDAP (or user custom) to the Nginx in HTTP headers.

Usage:
  ldap_authz_proxy [options] <config_file>
  ldap_authz_proxy -t | --test [options] <config_file> <username> <uri_path>
  ldap_authz_proxy -h | --help
  ldap_authz_proxy -H | --help-config
  ldap_authz_proxy -v | --version

Required:
  <config_file>  Path to the configuration file (e.g. /etc/ldap_authz_proxy.conf)

Options:
    -b --bind=<bind>     Bind address [default: 127.0.0.1]
    -p --port=<port>     Port to listen on [default: 10567]

    -l FILE --log FILE   Log to file instead of stdout
    -j --json            Log in JSON format
    -d --debug           Enable debug logging

    --dump-config        Check configuration file, dump parsed
                         values to stdout if successful, and exit.

    -t --test            Test mode. Query LDAP for given username and URI,
                         then exit with 0 if the user is authorized (HTTP 200)
                         or with HTTP status code (e.g. 403) otherwise.

    -h --help            Show this screen.
    -H --help-config     Show help for the configuration file.
    -v --version         Show version.
"#;

type Sha256Hash = sha2::digest::generic_array::GenericArray<u8, sha2::digest::generic_array::typenum::U32>;
type LdapSearchRes = Option<HashMap<String, Vec<String>>>;
type LdapCache = LruCache<Sha256Hash, LdapSearchRes>;

struct ReqContext {
    config: Arc<Vec<ConfigSection>>,
    cache: HashMap<String, Arc<Mutex<LdapCache>>>,  // section_name -> cache. Mutex instead of RwLock because get() can modify the cache
    req_id: Arc<AtomicU64>
}

struct LdapAnswer {
    ldap_res: LdapSearchRes,
    cached: bool,
    seen_sections: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubQueryJoin {
    Any,
    All,
    Main
}

/// Perform LDAP query/queries for given config section and username.
///
/// TODO: Pool connections. Currently a new LDAP connection is created for every request unless cache is hit.
#[async_recursion]
async fn ldap_query(
        req_id: u64,
        section: String,
        username: String,
        confs: Arc<Vec<ConfigSection>>,
        cache: Arc<Mutex<LdapCache>>,
        seen_sections: Arc<RwLock<HashSet<String>>>,
    ) -> ldap3::result::Result<LdapAnswer>
{
    let span = tracing::info_span!("ldap",
        req_id = req_id,
        user = &username,
        section = &section);

    let conf = confs.iter()
        .find(|conf| conf.section == section)
        .expect("BUG: ldap_query() called with unknown section name");

    let mut query = conf.ldap_query.replace("%USERNAME%", &ldap3::ldap_escape(&username));
    for (key, val) in conf.query_vars.iter() {
        query = query.replace(&format!("%{key}%"), val);
    }

    span.in_scope(|| { tracing::debug!("LDAP query: {}", query); });

    seen_sections.write().await.insert(conf.section.clone());

    // Check cache
    let cache_key = {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", conf.section, query));
        let cache_key = hasher.finalize();

        if let Some(res) = cache.lock().await.get(&cache_key) {
            span.in_scope(|| { tracing::debug!("Cache hit. Skipping LDAP. Result: {:?}", res); });
            return Ok(LdapAnswer {
                ldap_res: res.clone(),
                cached: true,
                seen_sections: seen_sections.read().await.clone() });
        } else {
            span.in_scope(|| { tracing::debug!("Not cached. Performing real query."); });
        }
        cache_key
    };

    async fn do_query(conf: &ConfigSection, query: &str) ->
        ldap3::result::Result<Vec<ResultEntry>>
    {
        let settings = ldap3::LdapConnSettings::new().set_conn_timeout(Duration::from_millis((conf.ldap_conn_timeout*1000.0) as u64));
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, conf.ldap_server_url.as_str()).await?;
        ldap3::drive!(conn);

        let bind_dn = conf.ldap_bind_dn.as_str();
        let bind_pw = conf.ldap_bind_password.expose_secret().as_str();

        ldap.simple_bind(bind_dn, bind_pw).await?.success()?;

        match ldap.search(
            conf.ldap_search_base.as_str(),
            conf.ldap_scope,
            query,
            &conf.ldap_attribs).await?.success()
        {
            Ok((rows, _)) => {
                ldap.unbind().await.ok();
                Ok(rows)
            },
            Err(e) => { ldap.unbind().await.ok(); Err(e) }
        }
    }

    // Try execute the query, with 1 second delay between each attempt
    const MAX_RETRY: i32 = 3;
    let res = async {
        for i in 0..MAX_RETRY {
            match do_query(conf, query.as_str()).await {
                Ok(rs) => {
                    return Ok(rs);
                },
                Err(e) => {
                    use ldap3::LdapError::*;
                    if i < MAX_RETRY-1 && matches!(e, ResultRecv{..} | Io{..} | EndOfStream{..} | Timeout{..}) {
                        let wait_time = 1.0 + (i as f32) * 0.5 * random::<f32>();
                        span.in_scope(|| { tracing::warn!("Temporary LDAP error: {:?}. Retry ({}/{}) in {wait_time} second.", e, i+1, MAX_RETRY, wait_time=wait_time); });
                        tokio::time::sleep(Duration::from_secs_f32(wait_time)).await;
                    } else {
                        if i == MAX_RETRY-1 {
                            span.in_scope(|| { tracing::error!("Max retries ({MAX_RETRY}) exhausted, LDAP error persists: {:?}", e); });
                        } else {
                            span.in_scope(|| { tracing::error!("Non-temporary LDAP error, giving up: {:?}", e); });
                        }
                        return Err(e);
                    }
                }
            };
        };
        unreachable!();
    }.await;

    let result_entries = match res {
        Ok(rs) => rs,
        Err(e) => {
            span.in_scope(|| { tracing::error!("LDAP error: {}", e); });
            return Err(e);
        }
    };

    let mut res_attribs = HashMap::new();

    // Store first row in a HashMap and log all other rows
    let row_i = 0;
    for row in result_entries {
        let se = SearchEntry::construct(row);
        if row_i > 0 {
            span.in_scope(|| { tracing::debug!("Skipped additional result row #{}: {:?}", row_i, se); });
        } else {
            span.in_scope(|| { tracing::debug!("First result row: {:?}", se); });
            // Store attribs from LDAP
            for (key, vals) in se.attrs {
                res_attribs.entry(key).or_insert_with(Vec::new).extend(vals);
            }
            // Store (manual) attribs from config
            for (key, vals) in &conf.set_attribs_on_success {
                res_attribs.entry(key.clone()).or_insert_with(Vec::new).extend(vals.clone());
            }
        }
    }

    // Recurse into sub-sections if necessary
    let mut authorized = !res_attribs.is_empty();
    if authorized || conf.sub_query_join == SubQueryJoin::Any
    {
        // Spawn sub-queries for all sub-sections that haven't been queried yet
        let futs = {
            let seen = seen_sections.read().await;
            conf.sub_queries.iter()
                .filter(|s| !seen.contains(*s))
                .map(|s| {
                    span.in_scope(|| { tracing::debug!("Recursing into [{}] (rule {:?})", s, conf.sub_query_join); });
                    let (s, username, confs, cache, seen_sections) = (s.clone(), username.clone(), confs.clone(), cache.clone(), seen_sections.clone());
                    tokio::spawn(async move {
                        // Random delay to avoid thundering herd
                        tokio::time::sleep(Duration::from_secs_f32(random::<f32>() * 0.05)).await;
                        ldap_query(req_id, s, username, confs, cache, seen_sections).await
                    })
                }).collect::<Vec<_>>()
        };
        
        // Wait for all sub-queries to finish and join results
        for fut in futs {
            let sub_res = fut.await
                .map_err(|e| ldap3::LdapError::AdapterInit(format!("JoinError: {}", e.to_string())))??;
            if let Some(sub_attribs) = sub_res.ldap_res {
                let sub_authz = !sub_attribs.is_empty();
                let old_authz = authorized;
                authorized = match conf.sub_query_join {
                    SubQueryJoin::Any => authorized || sub_authz,
                    SubQueryJoin::All => authorized && sub_authz,
                    SubQueryJoin::Main => authorized,
                };
                span.in_scope(|| {
                    if old_authz != authorized {
                        tracing::info!("Authz changed from '{}' to '{}' by sub-query result '{}' with rule: {:?})", old_authz, authorized, sub_authz, conf.sub_query_join);
                    }
                });
                for (key, vals) in sub_attribs {
                    res_attribs.entry(key).or_insert_with(Vec::new).extend(vals);
                }
            }
            seen_sections.write().await.extend(sub_res.seen_sections);
        }
    }

    // Sort and deduplicate values
    res_attribs.values_mut().for_each(|v| {
        v.sort();
        if conf.deduplicate_attribs { v.dedup() };
    });

    // Update cache and return
    let ldap_res = if !authorized || res_attribs.is_empty() { None } else { Some(res_attribs) };
    span.in_scope(|| { tracing::debug!("Query result: {:?}", ldap_res); });
    cache.lock().await.insert(cache_key, ldap_res.clone());
    Ok(LdapAnswer { 
        ldap_res,
        cached: false,
        seen_sections: seen_sections.read().await.clone() })
}


/// Unified HTTP handeler for all URI paths.
/// Matches path against regexp in every config section and uses the first match.
async fn http_handler(req: Request<Body>, ctx: Arc<ReqContext>) -> Result<Response<Body>, hyper::http::Error>
{
    let req_id = ctx.req_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let span = tracing::info_span!("http",
        method = %req.method(),
        path = %req.uri().path(),
        section = tracing::field::Empty,
        user = tracing::field::Empty,
        query_ms = tracing::field::Empty,
        cached = tracing::field::Empty);

    let conf = match ctx.config.iter().find(|c|
        matches!(c.http_path, Some(ref re) if re.is_match(req.uri().path())))
    {
        Some(conf) => conf,
        None => {
            let msg = format!("404 Not Found - No matching config section for: {}", req.uri().path());
            span.in_scope(|| { tracing::error!(msg); });
            return Ok(Response::builder().status(StatusCode::NOT_FOUND).body(Body::from(msg))?)
        }
    };
    let span = span.record("section", conf.section.as_str());

    // Get username from HTTP header
    let username = match req.headers().get(conf.username_http_header.as_str()) {
        Some(username) => {
            match username.to_str() {
                Ok(username) => username,
                Err(_) => {
                    let msg = format!("400 Bad Request - Invalid HTTP header: {}", conf.username_http_header);
                    span.in_scope(|| { tracing::error!("{}", msg); });
                    return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(msg))
                }
            }
        },
        None => {
            let msg = format!("400 Bad Request - Missing HTTP header: {}", conf.username_http_header);
            span.in_scope(|| { tracing::error!("{}", msg); });
            return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(msg))
        }
    };
    let span = span.record("user", username);

    // Check LDAP (and cache)
    let cache = ctx.cache.get(conf.section.as_str()).unwrap().clone();
    let query_start = tokio::time::Instant::now();
    let ldap_res = span.in_scope(|| async {
        ldap_query(
            req_id,
            conf.section.clone(), 
            username.into(), 
            ctx.config.clone(),
            cache, 
            Arc::new(RwLock::new(HashSet::new()))).await }).await;
    let span = span.record("query_ms", query_start.elapsed().as_millis());

    match ldap_res {
        Err(e) => {
            span.in_scope(|| { tracing::error!("LDAP error: {:?}", e); });
            return Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::from("LDAP error"))
        },
        Ok(la) => {
            let span = span.record("cached", &la.cached);
            if let Some(ldap_res) = la.ldap_res {
                span.in_scope(|| { tracing::info!("Authorized Ok"); });
                let mut resp = Response::new(Body::from("200 OK - LDAP result found"));

                // Store LDAP result attributes to response HTTP headers
                for (key, val) in ldap_res {

                    let val = val.join(&conf.attrib_delimiter);
                    let hname = match HeaderName::from_str(format!("X-LDAP-RES-{}", key).as_str()) {
                        Ok(hname) => hname,
                        Err(_) => {
                            span.in_scope(|| { tracing::error!("Invalid LDAP result key: {}", key); });
                            return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Invalid LDAP result key"))
                        }
                    };
                    let hval = match HeaderValue::from_str(val.as_str()) {
                        Ok(hval) => hval,
                        Err(_) => {
                            span.in_scope(|| { tracing::error!("Invalid LDAP result value: {}", val); });
                            return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Body::from("Invalid LDAP result value"))
                        }
                    };
                    span.in_scope(|| { tracing::debug!("Adding  header: {:?} = {:?}", hname, hval); });
                    resp.headers_mut().insert(hname, hval);
                }
                resp.headers_mut().insert("X-LDAP-CACHED", HeaderValue::from_str(if la.cached { "1" } else { "0" }).unwrap());
                Ok(resp)
            } else {
                span.in_scope(|| { tracing::info!("Authorization denied"); });
                Response::builder().status(StatusCode::FORBIDDEN)
                .header("X-LDAP-CACHED", HeaderValue::from_str(if la.cached { "1" } else { "0" }).unwrap())
                .body(Body::from(format!("403 Forbidden - Empty LDAP result for user '{:?}'", username)))
            }
        }
    }
}


/// Configure logging with tracing
/// Returns a guard that must be kept alive for the logging to work.
fn setup_logging(log_file: &str, debug: bool, json_log: bool) -> anyhow::Result<Box<dyn Send>> {
    let log_to_stdout = log_file == "" || log_file == "-";
    let (log_writer, guard) = if log_to_stdout {
            tracing_appender::non_blocking(std::io::stdout())
        } else {
            let f = std::fs::OpenOptions::new().create(true).append(true).open(log_file)?;
            tracing_appender::non_blocking(f)
        };

    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", if debug {"debug"} else {"info"});
    };
    let log_sbsc = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_file(false)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_target(false)
        //.pretty() // for debugging
        .with_writer(log_writer)
        .with_ansi(log_to_stdout);

    if json_log {
        tracing::subscriber::set_global_default(log_sbsc.json().finish())
    } else {
        tracing::subscriber::set_global_default(log_sbsc.finish())
    }.expect("tracing::subscriber::set_global_default failed");
    println!("Logging to: {}", if log_to_stdout {"stdout"} else {log_file});
    tracing::info!("Logging initialized");
    Ok(Box::new(guard))
}


/// Main function
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // Parse command line arguments
    let argv = std::env::args;
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(argv().into_iter()).parse())
        .unwrap_or_else(|e| e.exit());
    let log_file = args.get_str("--log").to_string();
    let json_log = args.get_bool("--json");
    let debug = args.get_bool("--debug");

    if args.get_bool("--help-config") {
        println!("{}", config::get_config_help());
        return Ok(());
    }
    if args.get_bool("--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let config_file = args.get_str("<config_file>");
    let conf = Arc::new(match config::parse_config(config_file) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("CONFIG ERROR: {}", e);   // stderr
            std::process::exit(2);
        }
    });


    let _logging_guard = setup_logging(&log_file, debug, json_log)?;

    if args.get_bool("--dump-config") {
        for c in conf.as_ref() {
            println!("{}", config::dump_config(c));
        }
        return Ok(());
    }

    // Create a cache for each section
    let mut caches = HashMap::new();
    for sect in conf.as_ref() {
        tracing::debug!("CONFIG DUMP: {:?}", sect);
        let ttl = Duration::from_secs_f32(sect.cache_time);
        let cache = LdapCache::with_expiry_duration_and_capacity(ttl, sect.cache_size);
        caches.insert(sect.section.clone(), Arc::new(Mutex::new(cache)));
    }
    let request_context = Arc::new(ReqContext { 
        config: conf,
        cache: caches,
        req_id: Arc::new(AtomicU64::new(0)),
    });

    let port: u16 = args.get_str("--port").parse()?;

    if !args.get_bool("--test")
    {
        // Start listening
        let bind = args.get_str("--bind");
        let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("Listening on http://{}", addr);
        loop {
            let (stream, _) = listener.accept().await?;
            let ctx = request_context.clone();
            tokio::task::spawn(async move   {
                if let Err(err) = hyper::server::conn::Http::new()
                    .serve_connection(stream, service_fn(|req| http_handler(req, Arc::clone(&ctx))))
                    .await {
                        tracing::error!("server error: {}", err);
                }
            });
        }
    }
    else
    {
        tracing::info!("RUNNING IN --test MODE");
        let username = args.get_str("<username>");
        let uri_path = args.get_str("<uri_path>");
        let ctx = request_context.clone();

        let conf = ctx.config.iter()
            .find(|conf| matches!(conf.http_path, Some(ref re) if re.is_match(uri_path)))
            .unwrap_or_else(|| {
                tracing::error!("No matching section found for uri_path '{}'", uri_path);
                println!("Test result: HTTP 404");
                exit(404);
            });

        let req = Request::builder()
            .method("GET")
            .uri(format!("http://localhost:{}/{}", port, uri_path))
            .header(conf.username_http_header.clone() , username)
            .body(Body::empty())?;

        match http_handler(req, ctx).await {
            Ok(resp) => {
                println!("Test result: HTTP {}", resp.status());
                for (k, v) in resp.headers() {
                    println!("{}: {}", k, v.to_str().unwrap());
                }
                let code = resp.status().as_u16() as i32;
                match code {
                    0 => panic!("BUG: HTTP 0 is invalid!"),
                    200 => { exit(0); },
                    _ => { exit(code); },
                }
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }

        Ok(())
    }
}
