FROM rust:1-slim-bookworm

RUN set -eux; \
    apt-get update; \
    apt-get install -y \
        libssl-dev pkg-config iputils-ping psmisc vim less

RUN set -eux; \
    apt-get update; \
    apt-get install -y \
        nginx curl \
        ldap-utils apache2-utils

COPY test/nginx-site.conf /etc/nginx/sites-available/default
RUN htpasswd -cb /var/www/html/.htpasswd alice alice123
RUN htpasswd -b /var/www/html/.htpasswd bob bob123
RUN htpasswd -b /var/www/html/.htpasswd charlie charlie123
RUN cp -a /var/www/html/index.nginx-debian.html /var/www/html/index.html

WORKDIR /run

COPY Cargo.toml ./
COPY src/ ./src/
RUN set -eux; \
    cargo build

COPY . .
CMD ["bash"]
