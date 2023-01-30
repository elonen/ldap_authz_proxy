use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use config::ConfigSection;
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, Body, StatusCode};
use tokio::net::TcpListener;
use docopt::Docopt;

use ldap3::{LdapConnAsync, Scope, SearchEntry};
use sha2::{Sha256, Digest};
use lru_time_cache::LruCache;
use tokio::sync::Mutex;

mod config;

const USAGE: &'static str = r#"
ldap_authz_proxy -- HTTP proxy server for LDAP authorization, mainly for Nginx
This program is a HTTP proxy server that checks the authorization of an
already authenticated user against an LDAP server.

Usage:
ldap_authz_proxy [options] <config_file>
ldap_authz_proxy -h | --help

Required:
  <config_file>  Path to the configuration file (e.g. /etc/ldap_authz_proxy.conf)

Options:
    -b --bind=<bind>    Bind address [default: 127.0.0.1]
    -p --port=<port>    Port to listen on [default: 10567]

    -l FILE --log FILE     Log to file instead of stdout
    -j --json              Log in JSON format
    -d --debug             Enable debug logging

    -h --help      Show this screen.
"#;

type Sha256Hash = sha2::digest::generic_array::GenericArray<u8, sha2::digest::generic_array::typenum::U32>;
type LdapSearchRes = Option<Vec<(String, String)>>; // HashMap<attr_name, attr_value> or None if not found
type LdapCache = LruCache<Sha256Hash, LdapSearchRes>;

struct ReqContext {
    config: Vec<ConfigSection>,
    cache: HashMap<String, Arc<Mutex<LdapCache>>>,  // <section_name, cache>
}

struct LdapAnswer {
    ldap_res: LdapSearchRes,
    cached: bool,
}

/// Perform LDAP query for given config section and username.
/// Returns true if the query returns at least one result.
/// Caches the result for the next time.
///
/// TODO: Pool connections. Currently a new LDAP connection is created for every request unless cache is hit.
async fn ldap_query(conf: &ConfigSection, username: &str, cache: &Arc<Mutex<LdapCache>>) -> ldap3::result::Result<LdapAnswer> {
    let query = conf.ldap_query.replace("%USERNAME%", &ldap3::ldap_escape(username));
    tracing::debug!("LDAP string: {}", query);

    // Check cache
    let cache_key = {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}", conf.ldap_server_url, query));
        let cache_key = hasher.finalize();
        if let Some(res) = cache.lock().await.get(&cache_key) {
            tracing::debug!("Cache hit. Skipping LDAP.");
            return Ok(LdapAnswer { ldap_res: res.clone(), cached: true });
        } else {
            tracing::debug!("Not cached. Performing real query.");
        }
        cache_key
    };

    let settings = ldap3::LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_millis((conf.ldap_conn_timeout*1000.0) as u64));
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, conf.ldap_server_url.as_str()).await?;
    ldap3::drive!(conn);

    let bind_dn = conf.ldap_bind_dn.as_str();
    let bind_pw = conf.ldap_bind_password.as_str();
    ldap.simple_bind(bind_dn, bind_pw).await?.success()?;

    let (rs, _res) = match ldap.search(
            conf.ldap_search_base.as_str(),
            Scope::Subtree,
            query.as_str(),
            &conf.ldap_return_attribs
        ).await?.success()
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("LDAP error: {}", e);
            return Err(e)
        }
    };
    ldap.unbind().await?;

    // Store first row in a HashMap and log all other rows
    let row_i = 0;
    let mut attribs = Vec::new();
    for row in rs {
        let se = SearchEntry::construct(row);
        if row_i > 0 {
            tracing::debug!("Skipped additional result row #{}: {:?}", row_i, se);
        } else {
            tracing::debug!("First result row: {:?}", se);
            for (key, vals) in se.attrs {
                let vals_comb = vals.iter().map(|v| v.as_str()).collect::<Vec<&str>>().join(";");
                attribs.push((key, vals_comb));
            }
        }
    }

    // Update cache and return
    let ldap_res = if attribs.is_empty() { None } else { Some(attribs) };
    cache.lock().await.insert(cache_key, ldap_res.clone());
    Ok(LdapAnswer { ldap_res, cached: false })
}


/// Unified HTTP handeler for all URI paths.
/// Matches path against regexp in every config section and uses the first match.
async fn http_handler(req: Request<Body>, ctx: Arc<ReqContext>) -> Result<Response<Body>, hyper::http::Error>
{
    let span = tracing::info_span!("http_handler",
        method = %req.method(),
        path = %req.uri().path(),
        config = tracing::field::Empty,
        username = tracing::field::Empty,
        cached = tracing::field::Empty);

    // Find config section matching the request URI
    let conf = ctx.config.iter().find(|conf| conf.http_path_re.is_match(req.uri().path()));
    let conf = match conf {
        Some(conf) => conf,
        None => {
            let msg = format!("404 Not Found - No matching config section for: {}", req.uri().path());
            span.in_scope(|| { tracing::error!(msg); });
            return Response::builder().status(StatusCode::NOT_FOUND).body(Body::from(msg))
        }
    };
    let span = span.record("config", conf.section.as_str());

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
    let span = span.record("username", username);

    // Check LDAP (and cache)
    let cache = ctx.cache.get(conf.section.as_str()).unwrap();
    match ldap_query(&conf, username, cache).await {
        Err(e) => {
            span.in_scope(|| { tracing::error!("LDAP error: {:?}", e); });
            return Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::from("LDAP error"))
        },
        Ok(la) => {
            let span = span.record("cached", &la.cached);
            if let Some(ldap_res) = la.ldap_res {
                span.in_scope(|| { tracing::info!("User authorized Ok"); });
                let mut resp = Response::new(Body::from("200 OK - LDAP result found"));
                // Store LDAP result attributes to response HTTP headers
                for (key, val) in ldap_res.iter() {
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
                    span.in_scope(|| { tracing::debug!("Adding result HTTP header: {:?} = {:?}", hname, hval); });
                    resp.headers_mut().insert(hname, hval);
                }
                resp.headers_mut().insert("X-LDAP-CACHED", HeaderValue::from_str(if la.cached { "1" } else { "0" }).unwrap());
                Ok(resp)
            } else {
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

    let _logging_guard = setup_logging(&log_file, debug, json_log)?;

    let config_file = args.get_str("<config_file>");
    let conf = config::parse_config(config_file)?;

    // Create a cache for each section
    let mut caches = HashMap::new();
    for sect in &conf {
        tracing::debug!("CONFIG DUMP: {:?}", sect);
        let ttl = ::std::time::Duration::from_secs(sect.ldap_cache_time as u64);
        let cache = LdapCache::with_expiry_duration_and_capacity(ttl, sect.ldap_cache_size);
        caches.insert(sect.section.clone(), Arc::new(Mutex::new(cache)));
    }
    let request_context = Arc::new(ReqContext { 
        config: conf,
        cache: caches
    });

    // Start listening
    let port: u16 = args.get_str("--port").parse()?;
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
