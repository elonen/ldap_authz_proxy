use std::collections::HashMap;
use std::collections::HashSet;

use anyhow::bail;
use anyhow::anyhow;
use ini::Ini;
use anyhow::Error;
use anyhow::Result;
use regex::Regex;
use secrecy::SecretString;

use crate::SubQueryJoin;


macro_rules! config_options {
    ($($name:ident $([$multi:tt])? : $type:ty = $default:expr ; $help:expr),*) => {

        #[derive(Debug, Clone)]
        pub(crate) struct ConfigSection {
            $(
                pub(crate) $name: $type,
            )*
        }

        const CONFIG_OPTIONS: &[&str] = &[ $(stringify!($name),)* ];

        fn option_is_list(opt: &str) -> bool {
            match opt {
                $( $( stringify!($name) => { assert!(stringify!($multi) == "MULTILINE"); true } )? )*
                _ => false,
            }
        }

        fn help_for_option(key: &str) -> &str {
            match key {
                $( stringify!($name) => $help, )*
                _ => "<Unknown option>",
            }
        }

        fn default_for_option(key: &str) -> Option<&str> {
            match key {
                $( stringify!($name) => $default, )*
                _ => None,
            }
        }

        const CONFIG_HELP_INTRO: &str = r##"
Configuration file in in INI format:

    [default]
    ; Default values for all other sections
    option1 = value1
    option2 = value2
    ...


    [section1]
    ; (any options that differ from [default])

    [section2]
    ; (any options that differ from [default])

    ...

Every section must have a unique name.

Options containing a comma separated list (marked (+)) can be specified
multiple times. These examples are equivalent:

    ldap_attribs = CN, displayName, givenName, sn, mail

    ldap_attribs = CN, displayName, givenName
    ldap_attribs = sn, mail

Config options:
"##;

        pub fn get_config_help() -> String {
            fn fmt_def(def: &Option<&str>) -> String {
                match def {
                    Some(def) => format!("[default: '{}']", def),
                    None => "[REQUIRED]".to_string(),
                }
            }
            CONFIG_HELP_INTRO.to_string() + &CONFIG_OPTIONS.iter()
                .filter(|key| **key != "section")
                .map(|key| format!("  {}{}  {}\n\n    {}\n\n\n",
                    key,
                    if option_is_list(key) { " (+)" } else { "" },
                    fmt_def( &default_for_option( &key )),
                    help_for_option(key).replace("\n", "\n    ")
                ))
                .collect::<String>()
        }

        pub (crate) fn dump_config(conf: &ConfigSection) -> String {
            let mut res = format!("[{}]\n", conf.section);
            $(
                res += &format!("{}: {:?}\n", stringify!($name), conf.$name);
            )*
            res
        }
    };
}

// Define the config options:
config_options! {
    section: String = None ; "Section name. Mostly for documentation, optionally used in extra_attrib_queries.",
    http_path: Option<Regex> = Some(""); concat!(
        "Regular expression to match the HTTP path against (e.g. '^/api/v1/.*').\n",
        "Never matched if empty. If you need to match all paths, use '^'.\n",
        "If multiple sections match, the first one is used."),
    username_http_header: String = Some("X-Ldap-Authz-Username"); "HTTP header to use for the username",

    ldap_server_url: String = None; "URL of the LDAP server (e.g. 'ldaps://ldap.example.com:636')",
    ldap_conn_timeout: f32 = Some("10.0"); "LDAP connection timeout in seconds",
    ldap_bind_dn: String = None; "DN of the LDAP user to bind as (e.g. 'CN=proxyuser,OU=users,DC=example,DC=com')",
    ldap_bind_password: SecretString = None; "Password of the LDAP user to bind as",
    ldap_search_base: String = None; "LDAP base DN to search in (e.g. 'OU=users,DC=example,DC=com')",
    ldap_scope: ldap3::Scope = Some("subtree"); "LDAP search scope. Must be 'subtree', 'onelevel' or 'base')",
    ldap_query: String = None; "LDAP query to use. May contain '%USERNAME%', which will be quoted and replaced.\nExample: '(&(objectClass=person)(sAMAccountName=%USERNAME%))",
    ldap_attribs [MULTILINE]: Vec<String> = Some("CN"); "LDAP attributes to return (e.g. 'displayName, givenName, sn, mail'). Must not be empty.",

    query_vars [MULTILINE]: HashMap<String, String> = Some(""); concat!(
        "Extra variables to use in the query, in addition to %USERNAME%.\n",
        "You can use these to avoid repeating long query strings in different sections.\n",
        "\n",
        "Unlike %USERNAME%, these are NOT quoted, so you can also use them to add\n",
        "extra filters to the query (e.g. '(memberOf=group1)').",
        "\n",
        "Example: 'MY_GROUP_NAME=group1, MY_USER_ATTRIB=sAMAccountName'\n",
        "...would turn '(&(objectClass=person)(%MY_USER_ATTRIB%=%USERNAME%)(memberOf=%MY_GROUP_NAME%))'\n",
        "into '(&(objectClass=person)(sAMAccountName=%USERNAME%)(memberOf=group1))'"
    ),

    cache_size: usize = Some("512") ; "Maximum number of entries to cache (per section)",
    cache_time: f32 = Some("30.0"); "Maximum age of entries in the cache (in seconds)",

    attrib_delimiter: String = Some(";"); "Delimiter to use when concatenating multiple values of an attribute",
    deduplicate_attribs: bool = Some("true"); "Whether to deduplicate attribute values.\nExample: 'someAttr=foo,bar,foo,foo' becomes 'someAttr=foo,bar')",

    set_attribs_on_success [MULTILINE] : Vec<(String, Vec<String>)> = Some(""); concat!(
        "Attributes to set manually if the main query succeeds.\n",
        "If empty, only the attributes returned by LDAP queries are set.\n",
        "Format: 'attribute=value1, attribute=value2, attribute2= ...'"),
    sub_queries [MULTILINE]: Vec<String> = Some(""); concat!(
        "Section names of optional sub-queries.'.\n",
        "\n",
        "Sub-queries can check for additional conditions and/or set additional attributes.\n",
        "See also 'sub_query_join for details.\n",
        "\n",
        "Recursions and duplicates are removed.\n",
        "Sub-queries are cached in the same way as the main query, and\n",
        "caching is hierarchical: if main query is cached, sub-queries are not executed.\n",
        "\n",
        "Format: 'extra_section_1, extra_section_2'"),
    sub_query_join: SubQueryJoin = Some("Main"); concat!(
        "How sub-queries affect authorization.\n",
        "Regardless of this, if any sub-query throws an LDAP error, the request is NOT authorized.\n",
        "\n",
        "Possible values:\n",
        " - 'Any': If main query or any sub-queries returns non-empty, request is authorized.\n",
        " - 'All': All sub-queries must return non-empty, otherwise request is NOT authorized.\n",
        " - 'Main': If main query authorizes, use sub-requests to add attributes.\n")
}

/// Parse the configuration file
/// 
/// Returns a vector of ConfigSections, excluding the [default] section, which
/// is used to fill in missing values in the other sections.
pub(crate) fn parse_config(config_file: &str) -> Result<Vec<ConfigSection>, Error>
{
    let mut ini = Ini::load_from_file(config_file)?;

    // Collect defaults
    let mut defaults = HashMap::new();
    // ...from the [default] section
    if let Some(default_sect) = ini.section(Some("default")) {
        defaults = default_sect.iter().map(|(key, _)|
            (key.to_string(), Some(
                // Join values from multiple config lines with a comma
                default_sect.get_all(key)
                    .map(|v| v.trim()).filter(|v| !v.is_empty()).collect::<Vec<_>>()
                    .join(", ").trim().to_string()
                ))).collect();
    }
    // ..from built-in defaults
    for key in CONFIG_OPTIONS.iter() {
        if !defaults.contains_key(*key) {
            if let Some(def) = default_for_option(key) {
                defaults.insert(key.to_string(), Some(def.to_string()));
            }
        }
    }

    let mut seen_sections = HashSet::new();
    let mut res = Vec::new();

    // Walk through the sections
    for (section_name, sect_props) in ini.iter_mut() {
        let section_name = match section_name {
            Some(name) => name,
            None => { bail!("Options outside of a section are not allowed"); }
        };

        if seen_sections.contains(&section_name) {
            bail!("Duplicate section [{}]", section_name);
        } else {
            seen_sections.insert(section_name);
        }

        // Check that no unknown keys are set
        let unknown_keys = sect_props.iter()
            .map(|(key, _)| key)
            .filter(|key| !CONFIG_OPTIONS.iter().any(|k| k == key))
            .collect::<Vec<_>>();
        if !unknown_keys.is_empty() {
            bail!("Unknown key(s) in section [{}]: {}", &section_name, unknown_keys.join(", "));
        }

        // Only allow certain keys to appear multiple times
        for (key, _) in sect_props.iter() {
            if sect_props.get_all(key).count() > 1 && !option_is_list(key) {
                bail!("Key '{}' (in section [{}]) defined mutiple times. This is allowed only for list options.", key, section_name);
            }
        }
        
        if section_name == "default" {
            continue;
        }

        // Apply defaults
        for (key, value) in &defaults {
            if sect_props.get(key).is_none() {
                if let Some(value) = value {
                    sect_props.insert(key.clone(), value.clone());
                }
            }
        }

        // Check that all required keys are set
        let missing_keys = CONFIG_OPTIONS.iter()
            .filter(|key| !sect_props.contains_key(*key))
            .map(|key| *key)
            .filter(|key| key != &"section")
            .collect::<Vec<_>>();
        if !missing_keys.is_empty() {
            bail!("Config option(s) not set in section [{}]: {}", section_name, missing_keys.join(", "));
        }

        // Helper function to get a value from the section. Combines multiple values with a comma.
        let get = |key: &str| sect_props.get_all(key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>().join(", ").trim().to_string();

        // Compile regex
        let http_path = get("http_path");
        let http_path_re = if http_path.trim().is_empty() { None } else {
            Some(Regex::new(&http_path).map_err(|e| anyhow!("Invalid regex in http_path: {}", e))?) };

        let parse_err = |key: &str| -> Error {
            anyhow!("Invalid value for option '{key}' in section [{section_name}]: {}.\n -- {}", get(key), help_for_option(key))
        };

        /// Parse a comma-separated list of assignments.
        /// E.g. "key1=value1, key2=value2, key3=value3"
        fn split_assignments(s: &str) -> Result<Vec<(String, String)>, Error> {
            let mut res = Vec::new();
            for assignment in s.split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                let mut parts = assignment.splitn(2, '=');
                let (key, value) = match (parts.next(), parts.next()) {
                    (Some(key), Some(value)) => (key.trim(), value.trim()),
                    _ => bail!("Invalid assignment: '{assignment}'. Complete line: '{s}'"),
                };
                if key.is_empty() {
                    bail!("Empty key in assignment: '{assignment}'. Complete line: '{s}'");
                }
                res.push((key.to_string(), value.to_string()));
            }
            Ok(res)
        }

        // Store result
        res.push(ConfigSection {
            section: section_name.to_string(),
            http_path: http_path_re,
            username_http_header: get("username_http_header"),

            ldap_server_url: get("ldap_server_url"),
            ldap_conn_timeout: get("ldap_conn_timeout").parse().or_else(|_| Err(parse_err("ldap_conn_timeout")))?,
            ldap_bind_dn: get("ldap_bind_dn"),
            ldap_bind_password: get("ldap_bind_password").into(),
            ldap_search_base: get("ldap_search_base"),
            ldap_scope: match get("ldap_scope").as_str() {
                "subtree" => ldap3::Scope::Subtree,
                "onelevel" => ldap3::Scope::OneLevel,
                "base" => ldap3::Scope::Base,
                _ => return Err(parse_err("ldap_scope")),
            },
            ldap_query: get("ldap_query"),
            ldap_attribs: get("ldap_attribs")
                .split(",").map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),

            query_vars: split_assignments(&get("query_vars"))?.into_iter().collect(),

            cache_size: get("cache_size").parse().or_else(|_| {
                    Err(anyhow!("Invalid value for cache_size: {}. Help: ", get("cache_size")))
                })?,
            cache_time: get("cache_time").parse()?,

            attrib_delimiter: get("attrib_delimiter"),
            deduplicate_attribs: get("deduplicate_attribs").parse()?,

            sub_queries: get("sub_queries")
                .split(",").map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()) // prune empty
                .collect::<HashSet<_>>().into_iter() // prune duplicates
                .filter(|s| s != &section_name) // prune self
                .collect(),

            sub_query_join: match get("sub_query_join").to_lowercase().trim() {
                "any" => SubQueryJoin::Any,
                "all" => SubQueryJoin::All,
                "main" => SubQueryJoin::Main,
                _ => return Err(parse_err("sub_query_join")),
            },

            set_attribs_on_success: split_assignments(&get("set_attribs_on_success"))?
                // Deduplicate keys with hashmap, appending values
                .into_iter()
                .fold(HashMap::<String, Vec<String>>::new(),
                    |mut acc, (key, value)| {
                        acc.entry(key).or_insert_with(Vec::new).extend(vec![value]);
                        acc
                    })
                // Turn back into Vec<(String, Vec<String>)>
                .into_iter()
                .collect(),
        });
    }

    if let Some(conf) = res.last() {
        if conf.ldap_attribs.is_empty() {
            bail!("Section [{}] has no ldap_attribs (must not be empty)", conf.section);
        }
    }

    for sect in &res {
        for extra in &sect.sub_queries {
            if !res.iter().any(|s| &s.section == extra) {
                bail!("Section [{}] references non-existent section [{}]", sect.section, extra);
            }
        }
    }

    Ok(res)
}
