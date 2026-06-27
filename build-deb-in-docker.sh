#!/bin/bash
set -e

# Build statically-linked (musl) .deb packages, one per architecture.
# Because the binary is fully static, a single package per arch works on any
# Debian/Ubuntu release, so there is no per-distro-version build matrix.

is_arch_supported() {
    local arch=$1
    docker build --platform linux/$arch - <<EOF
    FROM rust:1-trixie
    RUN echo "Testing architecture $arch"
EOF
}

# Build all architectures by default, or only those named on the command line
# (used by CI to build one arch per native runner, avoiding emulation).
ARCHES=("$@")
if [ ${#ARCHES[@]} -eq 0 ]; then
    ARCHES=(amd64 arm64)
fi

FAILED=()
for ARCH in "${ARCHES[@]}"; do
    case $ARCH in
        amd64) RUST_TARGET=x86_64-unknown-linux-musl ;;
        arm64) RUST_TARGET=aarch64-unknown-linux-musl ;;
    esac
    if ! is_arch_supported $ARCH; then
        echo "=== Platform $ARCH is unavailable here. Skipping it... ==="
        FAILED+=("$ARCH (platform unavailable)")
        continue
    fi
    echo "=== Building static musl .deb for $ARCH ($RUST_TARGET) ==="
    IMG="ldap_authz_proxy-deb_${ARCH}:latest"
    # A failure for one architecture (e.g. broken cross-arch emulation) must not
    # abort the others, so the build is run inside an `if` that swallows the error.
    if ! ( \
        docker build --platform linux/${ARCH} --build-arg RUST_TARGET=${RUST_TARGET} -t ${IMG} . && \
        docker run --platform linux/${ARCH} --rm -iv${PWD}:/root/OUTPUT ${IMG} bash -s << EOF
            set -e
            cd /root

            cargo deb --target ${RUST_TARGET}
            chown -v $(id -u):$(id -g) target/${RUST_TARGET}/debian/*.deb
            cp -va target/${RUST_TARGET}/debian/*.deb OUTPUT/

            echo "============ Done. Built static binary: ============"
            file target/${RUST_TARGET}/release/ldap_authz_proxy || true
EOF
    ); then
        echo "!!! Build FAILED for $ARCH"
        FAILED+=("$ARCH")
    fi
done

echo "=============== $(pwd) ==============="
ls -l *.deb 2>/dev/null || true
if [ ${#FAILED[@]} -ne 0 ]; then
    echo "WARNING: build failed for: ${FAILED[*]}"
    exit 1
fi
