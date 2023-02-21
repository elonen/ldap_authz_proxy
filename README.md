# ldap_authz_proxy - LDAP authorization proxy for authenticated HTTP users

[![Build Status](https://app.travis-ci.com/elonen/ldap_authz_proxy.svg?branch=master)](https://app.travis-ci.com/elonen/ldap_authz_proxy)
[![Release](https://img.shields.io/github/v/release/elonen/ldap_authz_proxy?include_prereleases)]()

A helper that allows Nginx to lookup from Active Directory / LDAP
if a user is authorized to access some resource, _after_ said user
has been authenticated by some other means (Kerberos, Basic auth, Token, ...).

Optionally, it can also return user attributes (such as name, email, etc) to Nginx
in HTTP headers. If one query is not enough, it can also perform sub-queries to
allow extra conditions for authorization and/or to fetch more attributes (e.g. group memberships).

Technically it's a small HTTP server that reads usernames from request headers
and performs configured LDAP queries with them, returning status 200 if query
succeeded or 403 if it failed; an HTTP<>LDAP proxy of sorts.
Nginx can auth against such a thing with the ´auth_request`
directive. Results are cached for a configurable amount of time.

## Configuration

The server is configured with an INI file, such as:

```ini
[default]
; Which HTTP header to read the %USERNAME% from
username_http_header = X-Ldap-Authz-Username

; Example LDAP server configuration. This is for Active Directory,
; and makes a recursive membership query to given group.
ldap_server_url = ldap://dc1.example.test:389
ldap_conn_timeout = 10.0
ldap_bind_dn = CN=service,CN=Users,DC=example,DC=test
ldap_bind_password = password123
ldap_search_base = DC=example,DC=test
ldap_query = (&(objectCategory=Person)(sAMAccountName=%USERNAME%)(memberOf:1.2.840.113556.1.4.1941:=CN=%MY_CUSTOM_VAR%,CN=Users,DC=example,DC=test))
ldap_attribs = displayName, givenName, sn, mail

; Cache size (these are defaults)
cache_time = 30
cache_size = 512

; These specify how to handle multiple LDAP queries/results
deduplicate_attribs = true
sub_query_join = Main


[users]
; Regular expression to match against the request URI
http_path = /users$
; Ldap query references variable MY_CUSTOM_VAR above. Set it for this query:
query_vars = MY_CUSTOM_VAR=ACL_Users
; Fetch additional attributes from LDAP my performing additional queries
; if this one succeeds. See below for their definitions.
sub_queries = is_beta_tester, is_bug_reporter


[admins]
http_path = /admins$
query_vars = MY_CUSTOM_VAR=ACL_Admins
; Fictional example: instruct backend app to show debug info for admins
set_attribs_on_success = extraGroups=show_debug_info

; Internal sub-queries (not matched agains URI as http_path is not defined)
; These examples set additional attributes ("extraGroups") if the user is a
; member of specified groups.

[is_beta_tester]
query_vars = MY_CUSTOM_VAR=ACL_Beta_Testers
set_attribs_on_success = extraGroups=beta_tester

[is_bug_reporter]
query_vars = MY_CUSTOM_VAR=ACL_Bug_Reporters
set_attribs_on_success = extraGroups=bug_reporter, extraGroups=show_debug_info
```

The `[default]` section contains defaults that can be overridden in other sections.
Other sections specify a URL path matching rules and settings to apply if it matches.
The `http_path` value is a regular expression
that is tested against HTTP requests. If it matches, `ldap_query` from that section
is executed after replacing `%USERNAME%` with the username from HTTP header named
in `username_http_header`. If the LDAP query succeeds and returns non-empty results,
server returns status 200 (with attributes in response headers), otherwise 403.

If a section has empty `http_path`, it is considered an internal sub-query and
can only be referenced from other sections with `sub_queries` setting. Sub-queries
can be used as to allow or deny access based on additional conditions (rules
specified by `sub_query_join`), or to fetch additional attributes from LDAP.

The `ldap_attribs`, if not empty, specifies a comma-separated list of LDAP
attributes to return to Nginx in HTTP headers. The header names are prefixed with
`X-Ldap-Authz-Res-`, so for example `displayName` attribute is returned in
`X-Ldap-Authz-Res-displayName` header. Use `ldap_attribs = *` to return all
attributes (mainly useful for debugging). Attributes with multiple values are
concatenated with separator specified in `attrib_delimiter`

If an LDAP query returns multiple objects, the first one is used. To see the rest,
use `--debug` option to log them.

Corresponding **Nginx** configuration block would look roughly like this -- assuming user has already been authenticated and thus `$remote_user` variable is set:

```nginx
        auth_request     /authz_admins;
        auth_request_set $display_name  $upstream_http_x_ldap_res_displayname;

        location = /authz_admins {
            internal;
            proxy_pass              http://127.0.0.1:10567/admins;
            proxy_pass_request_body off;
            proxy_set_header        Content-Length "";
            proxy_set_header        X-Ldap-Authz-Username $remote_user;
        }
```

(See a more complete example below.)

## Cache

The server uses a simple in-memory cache to avoid performing the same LDAP queries
over and over again. Cache size is limited to `cache_size` entries, and
entries are removed in LRU order. Cache time is `cache_time` seconds.
One cache entry is created for each unique username, so ldap_cache_size should
be large enough to accommodate all users that might be accessing the server simultaneously.
A cache entry takes probably about 1kB of RAM, unless you requested all LDAP attributes.

Technically, each config section gets its own cache, so you can have different cache sizes and
retention times for different sections. If a section uses sub-queries, the cache is shared
between the main query and all sub-queries, with main query's cache size and time.

HTTP response headers contain `X-Ldap-Cached` header that is set to `1` if the response
was served from cache, and `0` if it was a fresh query.

## Building

The server is written in Rust and can be manually built with `cargo build --release`.
Resulting binary is `target/release/ldap_authz_proxy`.

If you want Debian packages, see below.

## Running

The server can be run with `ldap_authz_proxy <configfile>`. Additional
options are available (`--help`):

```
Usage:
  ldap_authz_proxy [options] <config_file>
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

    --dump-config        Dump parse configuration in debug format and exit

    -h --help            Show this screen.
    -H --help-config     Show help for the configuration file.
    -v --version         Show version.
```

The executable stays in foreground, so it's recommended to run it
with a process manager such as `systemd` or `supervisord`. Example
`systemd` service file is included in `debian/service`.

## Security

The server doesn't require any special privileges, and can be run as a
normal user; the example `systemd` service file runs it as `www-data`.

Configuration file contains LDAP bind password(s), so it shouldn't be
world-readable. The server itself doesn't need to be able to write
to the configuration file.

Usernames are quoted before being used in LDAP queries, so they (hopefully)
can't be used to inject arbitrary LDAP queries. In any case, it's recommended
to use a read-only LDAP bind user just in case.

LDAPS is supported (even though the test scripts use plain ldap://), and is
recommended in production.

The server doesn't handle user passwords at all - it only reads usernames from
HTTP headers and performs LDAP queries with them.

## Packaging

The server can be packaged for Debian variants with `./build-deb-in-docker.sh`
(or to build locally, `cargo install cargo-deb && cargo deb`).

To install, issue `dpkg -i ldap-authz-proxy_*.deb`, edit `/etc/ldap_authz_proxy.conf` to
your liking, and then enable the service by `systemctl enable ldap_authz_proxy.service`.

This is the recommended way to install this on Debian systems.

## Testing

Use `./run-tests.sh` to execute test suite. It requires `docker compose`
and `curl`. The script performs an end-to-end integratiot test with a
real Active Directory server and an Nginx reverse proxy.

It spins up necessary containers, sets up example users, and then performs
Curl HTTP requests against Nginx, comparing their HTTP response status codes
and headers to expected values.

## Nginx configuration

See `test/nginx-site.conf` for a simple example where users are authenticated
with the Basic method and then authorized with this server using _auth_request_ directive.

### Kerberos

This software was originally developed for Active Directory auth using
Nginx, so here's a complementary example on how to authenticate some API users
against AD with Kerberos (spnego-http-auth-nginx-module) and to then authorize them using
_ldap_authz_proxy_:

```nginx
server {
        listen 443 ssl;
        ssl_certificate     /etc/ssl/private/www.example.com.fullchain.pem;
        ssl_certificate_key /etc/ssl/private/www.example.com.privkey.pem;

        server_name www.example.com;


        satisfy all;    # Require 2 auths: auth_gss (Kerberos) for authn and auth_request (LDAP proxy) for authz

        auth_gss on;
        auth_gss_keytab /etc/krb5.keytab;
        auth_gss_realm EXAMPLE.COM;
        auth_gss_force_realm on;
        auth_gss_service_name HTTP/www.example.com;

        auth_request     /authz_all;
        auth_request_set $display_name  $upstream_http_x_ldap_res_displayname;
        auth_request_set $extra_groups  $upstream_http_x_ldap_res_extragroups;  # See example .INI

        location = /authz_all {
            internal;
            proxy_pass              http://127.0.0.1:10567/users;
            proxy_pass_request_body off;
            proxy_set_header        Content-Length "";
            proxy_set_header        X-Ldap-Authz-Username $remote_user;  # $remote_user is set by auth_gss
        }


        location /api {
                proxy_pass http://127.0.0.1:8095/api;

                # Pass authenticated username to backend
                proxy_set_header X-Remote-User-Id $remote_user;
                proxy_set_header X-Remote-User-Name $display_name;
                proxy_set_header X-Remote-User-ExtraGroups $extra_groups;

                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}
```

The VM running Nginx (and ldap_authz_proxy) was joined to AD domain like this:

```
	apt install krb5-user libpam-krb5 libsasl2-modules-gssapi-mit acl msktutil
        kinit <account name>
        msktutil --no-reverse-lookups -u -s host -s HTTP --dont-expire-password --computer-name WWW -h www.example.com
        setfacl -m u:www-data:r-- /etc/krb5.keytab
```

Script(s) for building Nginx Kerberos (SPNEGO) module for Debian:
https://github.com/elonen/debian-nginx-spnego

## Development

Probably the easiest way to develop this is to:

```bash	
# Start test LDAP server
cd test
docker compose up -d
cd ..

# Config, build and run
sed -i 's@ldap_server_url *=.*@ldap_server_url = ldap://127.0.0.1:3890@' example.ini
cargo run -- example.ini --debug &

# Test request directly against ldap_authz_proxy
curl http://127.0.0.1:10567/admins -H "X-Ldap-Authz-Username:alice" -I

# Cleanup
kill %1  # Or do: fg + ctrl-c
cd test
docker compose down
cd ..
git checkout -- example.ini  # Reverse the config
```

## Contributing

This software was created to scratch a persistent sysops itch.
Contributions are very welcome.

## License

Copyright 2023 by Jarno Elonen.

The project is dual licensed under the terms of the Apache License, Version 2.0, and the MIT License.
See LICENSE-APACHE and LICENSE-MIT for details.
