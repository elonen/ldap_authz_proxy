#!/bin/bash
set -e

IMG="ldap_authz_proxy-deb:latest"

docker build -t $IMG .
docker run --rm -iv${PWD}:/root/OUTPUT $IMG sh -s << EOF
    cd /root
    cargo deb || exit 1
    chown -v $(id -u):$(id -g) target/debian/*.deb
    cp -va target/debian/*.deb OUTPUT/
    echo "============ Done. Built for: ============="
    lsb_release -a
EOF
echo "=============== $(pwd) ==============="
ls -l *.deb
