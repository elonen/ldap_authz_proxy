#!/bin/bash
set -e

echo "----------------------------------------------------------------------------------"
echo "Starting Active Directory (Samba), Nginx and LDAP authz proxy in Docker Compose..."
echo "----------------------------------------------------------------------------------"

cd test
docker compose build
docker compose up -d

# Make sure we stop the containers when we exit, regardless of how
trap 'echo "---"; docker compose down' EXIT


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
    RES=$(curl --write-out '%{http_code}' --silent --output /dev/null http://127.0.0.1:8090/$FOLDER/ -u "$CREDS")
    echo "$RES"
}

function test() {
    FOLDER="$1"
    CREDS="$2"
    EXPECTED="$3"
    ACTUAL="$(request $FOLDER $CREDS)"
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "Test FAILED - expected $EXPECTED, got $ACTUAL for '$FOLDER' with '$CREDS'"
    else
        echo "Test OK for '$FOLDER' with '$CREDS' ($ACTUAL == $EXPECTED)"
    fi
}

function do_tests() {
    test "user-page" "alice:alice" "200"
    test "admin-page" "alice:alice" "200"
    test "user-page" "alice:BADPASSWORD" "401"
    test "admin-page" "alice:BADPASSWORD" "401"

    test "user-page" "bob:bob" "200"
    test "admin-page" "bob:bob" "403"
    test "user-page" "bob:BADPASSWORD" "401"
    test "admin-page" "bob:BADPASSWORD" "401"

    test "bad-page" "alice:alice" "404"
}

# Run the tests and summarize
if (do_tests | tee /dev/stderr | grep -q "FAILED"); then
    echo "*** Some tests FAILED ***"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
