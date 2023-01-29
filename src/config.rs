use anyhow::bail;
use anyhow::anyhow;
use configparser::ini::Ini;
use anyhow::Error;
use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone)]
pub(crate) struct ConfigSection {
    pub(crate) section: String,

    pub(crate) ldap_server_url: String,
    pub(crate) ldap_conn_timeout: f32,

    pub(crate) ldap_bind_dn: String,
    pub(crate) ldap_bind_password: String,
    pub(crate) ldap_search_base: String,
    pub(crate) ldap_query: String,
    pub(crate) ldap_return_attribs: Vec<String>,

    pub(crate) ldap_cache_size: usize,
    pub(crate) ldap_cache_time: u32,

    pub(crate) username_http_header: String,

    pub(crate) http_path_re: Regex,
}

/// Parse the configuration file
/// 
/// Returns a vector of ConfigSections, excluding the DEFAULT section, which
/// is used to fill in missing values in the other sections.
/// 
/// TODO: Maybe macroize this to avoid code duplication?
pub(crate) fn parse_config(config_file: &str) -> Result<Vec<ConfigSection>, Error>
{
    let mut config = Ini::new();
    config.load(config_file).map_err(|e| anyhow!("Error loading config file: {}", e))?;
    let map = config.get_map_ref();

    // Get the DEFAULT section
    let defaults = match map.get("default") {
        Some(defaults) => defaults,
        None => bail!("No 'default' section in config file"),
    };

    // Walk through the sections
    let mut res = Vec::new();
    for section_name in config.sections() {
        let mut sect_map = map.get(section_name.as_str()).unwrap().clone();

        const VALID_KEYS: [&str; 11] = ["ldap_server_url", "ldap_conn_timeout", "ldap_bind_dn", "ldap_bind_password", "ldap_search_base", "ldap_query", "ldap_return_attribs", "ldap_cache_time", "ldap_cache_size", "username_http_header", "http_path"];
        for (key, _) in sect_map.iter() {
            if !VALID_KEYS.contains(&key.as_str()) {
                bail!("Invalid key '{}' in section '{}'. Valid ones are: {}", key, section_name, VALID_KEYS.join(", "));
            }
        }

        if section_name == "default" {
            continue;
        }

        // Apply defaults
        for (key, value) in defaults {
            if let None = sect_map.get(key) {
                sect_map.insert(key.clone(), value.clone());
            }
        }

        let err_fn = |key| anyhow!("Option '{}' not defined in section '{}' (nor in DEFAULT section)", key, section_name);

        // Compile regex
        let http_path = sect_map.get("http_path").ok_or(err_fn("http_path"))?.as_ref().unwrap().clone();
        let http_path_re = Regex::new(&http_path).map_err(|e| anyhow!("Invalid regex in http_path: {}", e))?;

        // Store result
        res.push(ConfigSection {
            section: section_name.clone(),
            ldap_server_url: sect_map.get("ldap_server_url").ok_or(err_fn("ldap_server_url"))?.as_ref().unwrap().clone(),
            ldap_conn_timeout: sect_map.get("ldap_conn_timeout").ok_or(err_fn("ldap_conn_timeout"))?.as_ref().unwrap().clone().parse()?,

            ldap_bind_dn: sect_map.get("ldap_bind_dn").ok_or(err_fn("ldap_bind_dn"))?.as_ref().unwrap().clone(),
            ldap_bind_password: sect_map.get("ldap_bind_password").ok_or(err_fn("ldap_bind_password"))?.as_ref().unwrap().clone(),
            ldap_search_base: sect_map.get("ldap_search_base").ok_or(err_fn("ldap_search_base"))?.as_ref().unwrap().clone(),
            ldap_query: sect_map.get("ldap_query").ok_or(err_fn("ldap_query"))?.as_ref().unwrap().clone(),
            ldap_return_attribs: sect_map.get("ldap_return_attribs").ok_or(err_fn("ldap_return_attribs"))?.as_ref().unwrap().clone().split(",").map(|s| s.trim().to_string()).collect(),

            ldap_cache_size: sect_map.get("ldap_cache_size").ok_or(err_fn("ldap_cache_size"))?.as_ref().unwrap().clone().parse()?,
            ldap_cache_time: sect_map.get("ldap_cache_time").ok_or(err_fn("ldap_cache_time"))?.as_ref().unwrap().clone().parse()?,

            username_http_header: sect_map.get("username_http_header").ok_or(err_fn("username_http_header"))?.as_ref().unwrap().clone(),
            http_path_re: http_path_re,
        });
    }
    Ok(res)
}
