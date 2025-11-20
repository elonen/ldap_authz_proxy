#!/bin/bash
set -e

echo "----------------------------------------------------------------------------------"
echo "Starting Active Directory (Samba), Nginx and LDAP authz proxy in Docker Compose..."
echo "----------------------------------------------------------------------------------"

grep -q "^ *ldap_server_url *=.*dc1.example.test" example.ini || (echo "ERROR: LDAP URL is not set to 'dc1.example.test' config! Test would fail." && exit 1)

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
    EXTRA_GROUPS=$(grep -i 'X-Extra-Groups' <<< """$RES""" | sed 's/^.*: //' | tr -d '\r\n') || true
    echo "${HTTP_CODE}${DISPLAY_NAME} c${LDAP_CACHED} eg:${EXTRA_GROUPS}"
}

function test() {
    URI="$1"
    CREDS="$2"
    EXPECTED="$3"
    ACTUAL="$(request $URI $CREDS)"
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "Test FAILED - expected '$EXPECTED', got '$ACTUAL' for '$URI' with '$CREDS'"
    else
        echo "Test OK for '$URI' with '$CREDS'"
    fi
}

function test_offline() {
    URI="$1"
    USER="$2"
    EXPECTED_CODE="$3"
    EXIT_CODE=$(docker compose exec www  target/debug/ldap_authz_proxy --test example.ini "$USER" "$URI" | grep -o "HTTP [0-9]*")
    if [ "$EXIT_CODE" = "HTTP $EXPECTED_CODE" ]; then
        echo "Test OK for --test test with '$URI' with '$USER'"
    else
        echo "Test FAILED for --test test with '$URI' with '$USER' (expected $EXPECTED_CODE, got $EXIT_CODE)"
    fi
}

function do_tests() {
    test "user-page"  "alice:alice123" "200Alice Alison c0 eg:beta_tester"
    test "admin-page" "alice:alice123" "200 c0 eg:show_debug_info"
    test "user-page"  "alice:BADPASSWORD" "401 c eg:"
    test "admin-page" "alice:BADPASSWORD" "401 c eg:"

    test "user-page"  "bob:bob123" "200Bob Bobrikov c0 eg:bug_reporter;peer_support;show_debug_info"
    test "admin-page" "bob:bob123" "403 c eg:"
    test "user-page"  "bob:BADPASSWORD" "401 c eg:"
    test "admin-page" "bob:BADPASSWORD" "401 c eg:"

    test "user-page"  "charlie:charlie123" "200Charlie Chandler c0 eg:peer_support"
    test "admin-page" "charlie:charlie123" "403 c eg:"
    test "user-page"  "charlie:BADPASSWORD" "401 c eg:"

    test "bad-page"   "alice:alice123" "404 c eg:"

    # Test username quoting with malicious characters, should give 401, not 500
    test "user-page"  ")=&%)):password" "401 c eg:"

    # Test comma-separated username (simulating misconfigured proxy header forwarding)
    # The default config has username_split_on_comma=true, so it should split and use only "alice"
    echo "-- Test comma-separated username handling"
    test_offline "/users"   "alice, alice"   200
    test_offline "/admins"  "bob, bob"       403

    echo "-- Repeat and check that query came from cache"
    test "user-page"  "alice:alice123" "200Alice Alison c1 eg:beta_tester"
    test "admin-page" "alice:alice123" "200 c1 eg:show_debug_info"
    test "user-page"  "bob:bob123" "200Bob Bobrikov c1 eg:bug_reporter;peer_support;show_debug_info"

    echo "-- Test --test mode"
    test_offline "/users"   "alice"   200
    test_offline "/admins"  "alice"   200
    test_offline "/users"   "bob"     200
    test_offline "/admins"  "bob"     403
    test_offline "/users"   "charlie" 200
    test_offline "/admins"  "charlie" 403
    test_offline "/BADPAGE" "alice"   404
}

# Run the tests and summarize
if (do_tests | tee /dev/stderr | grep -q "FAILED"); then
    echo "*** Some tests FAILED ***"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
