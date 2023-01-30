#!/bin/bash
set -e

echo "----------------------------------------------------------------------------------"
echo "Starting Active Directory (Samba), Nginx and LDAP authz proxy in Docker Compose..."
echo "----------------------------------------------------------------------------------"

cd test
DOCKER_BUILDKIT=1 docker compose build
docker compose up -d
trap 'echo "---"; docker compose down' EXIT  #  Make sure we stop the containers when we exit, regardless of how

echo "---------------------------------------------"
echo "Waiting for services to start up..."
echo "---------------------------------------------"

function wait_for_docker_log() {
    TIMEOUT=60
    CONTAINER="$1"
    LOG="$2"
    echo "Waiting for '$LOG' in container '$CONTAINER' logs..."
    while ! docker logs $CONTAINER 2>&1 | grep -q "$LOG"; do
        TIMEOUT=$((TIMEOUT-1))
        if [ $TIMEOUT -eq 0 ]; then
            echo "ERROR: Timeout waiting for '$LOG' in container '$CONTAINER'!"
            exit 1
        fi
        sleep 1
        if [ "$(docker inspect -f '{{.State.Running}}' $CONTAINER)" != "true" ]; then
            echo "ERROR: Container '$CONTAINER' is not running!"
            exit 1
        fi
    done
}

wait_for_docker_log "dc1" "DC READY FOR TESTING" || exit 1
wait_for_docker_log "www" "Listening on http" || exit 1


echo "---------------------------------------------"
echo "Running HTTP authn + authz tests with Curl..."
echo "---------------------------------------------"

function request() {
    FOLDER="$1"
    CREDS="$2"
    # Don't remove the "/index.html", otherwise Nginx makes an internal redirect, and warms up LDAP cache prematurely
    RES=$(curl -s http://127.0.0.1:8090/$FOLDER/index.html -u "$CREDS" -I)
    # cat <<< """$RES""" >&2
    HTTP_CODE=$(grep HTTP <<< """$RES""" | awk '{print $2}' | tr -d '\r\n')
    DISPLAY_NAME=$(grep -i 'X-Display-Name' <<< """$RES""" | sed 's/^.*: //' | tr -d '\r\n') || true
    LDAP_CACHED=$(grep -i 'X-LDAP-Cached' <<< """$RES""" | sed 's/^.*: //' | tr -d '\r\n') || true
    echo "${HTTP_CODE}${DISPLAY_NAME} c${LDAP_CACHED}"
}

function test() {
    FOLDER="$1"
    CREDS="$2"
    EXPECTED="$3"
    ACTUAL="$(request $FOLDER $CREDS)"
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "Test FAILED - expected '$EXPECTED', got '$ACTUAL' for '$FOLDER' with '$CREDS'"
    else
        echo "Test OK for '$FOLDER' with '$CREDS' ($ACTUAL == $EXPECTED)"
    fi
}

function do_tests() {
    test "user-page" "alice:alice" "200Alice Alison c0"
    test "admin-page" "alice:alice" "200 c0"
    test "user-page" "alice:BADPASSWORD" "401 c"
    test "admin-page" "alice:BADPASSWORD" "401 c"

    test "user-page" "bob:bob" "200Bob Bobrikov c0"
    test "admin-page" "bob:bob" "403 c"
    test "user-page" "bob:BADPASSWORD" "401 c"
    test "admin-page" "bob:BADPASSWORD" "401 c"

    test "bad-page" "alice:alice" "404 c"
    
    echo "(Repeat and check that query came from cache)"
    test "user-page" "alice:alice" "200Alice Alison c1"
    test "admin-page" "alice:alice" "200 c1"
    test "user-page" "bob:bob" "200Bob Bobrikov c1"
}

# Run the tests and summarize
if (do_tests | tee /dev/stderr | grep -q "FAILED"); then
    echo "*** Some tests FAILED ***"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
