# ldap_authz_proxy - LDAP authorization proxy for authenticated HTTP users

[![Build Status](https://app.travis-ci.com/elonen/ldap_authz_proxy.svg?branch=master)](https://app.travis-ci.com/elonen/ldap_authz_proxy)
[![Release](https://img.shields.io/github/v/release/elonen/ldap_authz_proxy?include_prereleases)]()

A helper that allows Nginx to lookup from Active Directory / LDAP
if a user is authorized to access some resource, _after_ said user
has been authenticated by some other means (Kerberos, Basic auth, Token, ...).

Technically it's a small HTTP server that reads usernames from request headers
and performs configured LDAP queries with them, returning status 200 if query
succeeded or 403 if it failed; an HTTP->LDAP proxy of sorts.
Nginx can auth against such a thing with the ´auth_request`
directive. Results are cached for a configurable amount of time.

## Configuration

The server is configured with an INI file, such as:

```ini
[default]
ldap_server_url = ldap://dc1.example.test
ldap_conn_timeout = 10.0
ldap_bind_dn = CN=service,CN=Users,DC=example,DC=test
ldap_bind_password = password123
ldap_search_base = DC=example,DC=test

ldap_cache_size = 1024
ldap_cache_time = 30

username_http_header = X-Ldap-Authz-Username

[users]
http_path = /users$
ldap_query = (&(objectCategory=Person)(sAMAccountName=%USERNAME%)(memberOf:1.2.840.113556.1.4.1941:=CN=ACL_Users,CN=Users,DC=example,DC=test))

[admins]
http_path = /admins$
ldap_query = (&(objectCategory=Person)(sAMAccountName=%USERNAME%)(memberOf:1.2.840.113556.1.4.1941:=CN=ACL_Admins,CN=Users,DC=example,DC=test))
```

The `[default]` section contains defaults that can be overridden in other sections.
Other sections can have arbitrary names, and they each specify a URL path matching
rule and settings to apply if it matches. The `http_path` value is a regular expression
that is tested against HTTP requests. If it matches, `ldap_query` from that section
is executed after replacing `%USERNAME%` with the username from `username_http_header` HTTP header.
If the LDAP query succeeds, server returns status 200, otherwise 403.

## Building

The server is written in Rust and can be built with `cargo build --release`.
Resulting binary is `target/release/ldap_authz_proxy`.

## Running

The server can be run with `ldap_authz_proxy <configfile>`. Additional
options are available, see `--help` for details.

The executable will stay in foreground, so it's recommended to run it
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

The server can be packaged for Debian variants with `cargo install cargo-deb && cargo deb`.
This is the recommended way to install it when applicable.

## Testing

Use `./run-tests.sh` to execute test suite. It requires `docker compose`
and `curl`. The script performs an end-to-end integratiot test with a
real LDAP server (Active Directory in this case, using Samba) and an
Nginx reverse proxy. It spins up necessary containers, and then performs
Curl HTTP requests against Nginx, comparing their HTTP response status codes to
expected values.

## Ngix configuration

See `test/nginx-site.conf` for a simple example where users are authenticated
with the Basic method and then authorized with this server using _auth_request_ directive.

### Kerberos

This software was originally developed for Active Directory auth using
Nginx, so here's a complementary real-world example on how to authenticate users against AD with
Kerberos (spnego-http-auth-nginx-module) and to then authorize them using
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

        auth_request    /authz_all;

        location = /authz_all {
            internal;
            proxy_pass              http://127.0.0.1:10567/users;
            proxy_pass_request_body off;
            proxy_set_header        Content-Length "";
            proxy_set_header        X-Ldap-Authz-Username $remote_user;
        }

        location / {
                root /var/www/;
                index index.html;
                try_files $uri $uri/ =404;
        }
}
```

The VM running Nginx (and ldap_authz_proxy) was joined to AD domain like this:

```
        kinit <account name>
        msktutil -u -s host -s HTTP --dont-expire-password -b OU=Servers --computer-name WWW -h www.example.com
        setfacl -m u:www-data:r-- /etc/krb5.keytab
```

Some instructions for compiling _spnego-http-auth-nginx-module_ on Debian: https://docs.j7k6.org/sso-nginx-kerberos-spnego-debian/

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
curl http://127.0.0.1:10567/admins -H "X-Ldap-Authz-Username:alice"

# Cleanup
kill %1  # Or do: fg + ctrl-c
cd test
docker compose down
cd ..
git checkout -- example.ini  # Reverse the config
```

## Contributing

This server was created to scratch a persistent sysop itch.
Contributions are welcome.

## License

Copyright 2023 by Jarno Elonen.

The project is dual licensed under the terms of the Apache License, Version 2.0, and the MIT License.
See LICENSE-APACHE and LICENSE-MIT for details.
