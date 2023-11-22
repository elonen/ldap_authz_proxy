#!/bin/bash
set -e

is_arch_supported() {
    local arch=$1
    local deb=$2
    docker build --platform linux/$arch - <<EOF
    FROM rust:1-$deb
    RUN echo "Testing architecture $arch"
EOF
}

for ARCH in amd64 arm64; do
for DEBIAN_VER in bookworm bullseye; do
if  is_arch_supported $ARCH $DEBIAN_VER; then
    echo "=== Building for $DEBIAN_VER:$ARCH ==="
    IMG="ldap_authz_proxy-deb_${ARCH}:latest"
    docker build --platform linux/${ARCH} --build-arg DEBIAN_VER=${DEBIAN_VER} -t ${IMG} .
    docker run --platform linux/${ARCH} --rm -iv${PWD}:/root/OUTPUT ${IMG} bash -s << EOF
        cd /root

        cargo deb || exit 1
        chown -v $(id -u):$(id -g) target/debian/*.deb

        for x in target/debian/*.deb; do
            NEWFILE=\$(echo "\$x" | sed -E "s/(.*_)/\1${DEBIAN_VER}_/")
            mv "\$x" "\$NEWFILE"
        done

        cp -va target/debian/*.deb OUTPUT/
        echo "============ Done. Built for: ============="
        lsb_release -a
EOF
else
    echo "=== Platform availability test (is_arch_supported) failed for $DEBIAN_VER:$ARCH. Skipping it..."
fi
done
done

echo "=============== $(pwd) ==============="
ls -l *.deb
