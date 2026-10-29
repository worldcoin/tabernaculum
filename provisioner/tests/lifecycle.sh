#!/bin/bash
# Linux bootstrap/cleanup tests. AWS and Nitro are mocked.
# Direct bundle transfer and cancellation are tested in di-sandbox.
set -euo pipefail
: "${PROVISIONER_BIN:?set PROVISIONER_BIN to the compiled tabernaculum-provisioner}"
suite=$(mktemp -d)
provisioner_pid=""
cleanup() {
    if [[ -n "$provisioner_pid" ]]; then
        kill -TERM "$provisioner_pid" 2>/dev/null || true
        wait "$provisioner_pid" 2>/dev/null || true
    fi
    rm -rf -- "$suite"
}
trap cleanup EXIT
assert_not() { if "$@"; then echo "FAIL: unexpected success: $*"; exit 1; fi; }
mkdir -p "$suite/bin" "$suite/archive/release"
printf 'fixture worker\n' > "$suite/archive/release/biometric-engines-worker"
tar -czf "$suite/good.tar.gz" -C "$suite/archive" release
touch "$suite/enclave.eif"

cat > "$suite/bin/aws" <<'MOCK'
#!/bin/bash
set -euo pipefail
echo download >> "$CASE_DIR/events"
[[ "$3" == "$BUNDLE_ARTIFACT_URI" ]]
[[ "$SCENARIO" != download_fail ]] || exit 1
cp "$ARCHIVE" "$4"
MOCK
cat > "$suite/bin/readelf" <<'MOCK'
#!/bin/bash
case "$1" in
    -h) echo 'Machine: Advanced Micro Devices X86-64' ;;
    -l) if [[ "$SCENARIO" == dynamic ]]; then echo INTERP; else echo DYNAMIC; fi ;;
    -d) if [[ "$SCENARIO" == shared_library ]]; then echo '(NEEDED) libm.so'; fi ;;
esac
exit 0
MOCK
cat > "$suite/bin/nitro-cli" <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1" in
    run-enclave)
        flags=NONE
        if [[ "${ENCLAVE_DEBUG_MODE:-false}" == true ]]; then
            [[ " $* " == *' --debug-mode '* ]]
            flags=DEBUG_MODE
        else
            [[ " $* " != *' --debug-mode '* ]]
        fi
        name=""
        while (( $# > 0 )); do
            if [[ "$1" == --enclave-name ]]; then name=$2; break; fi
            shift
        done
        jq -n --arg name "$name" --arg flags "$flags" \
            '{EnclaveID:"owned",EnclaveName:$name,EnclaveCID:16,State:"RUNNING",Flags:$flags}' > "$CASE_DIR/owned"
        echo launch >> "$CASE_DIR/events"
        if [[ "$SCENARIO" == launch_fail || "$SCENARIO" == debug_launch_fail || "$SCENARIO" == measured_launch_fail || "$SCENARIO" == cleanup_fail ]]; then exit 1; fi
        if [[ "$SCENARIO" == launch_timeout || "$SCENARIO" == signal_launch ]]; then sleep 30; fi
        cat "$CASE_DIR/owned"
        ;;
    describe-enclaves)
        if [[ -f "$CASE_DIR/owned" ]]; then
            jq -s '. + [{EnclaveID:"unrelated",EnclaveName:"another-owner",State:"RUNNING",Flags:"NONE"}]' "$CASE_DIR/owned"
        else
            echo '[{"EnclaveID":"unrelated","EnclaveName":"another-owner","State":"RUNNING","Flags":"NONE"}]'
        fi
        ;;
    console)
        [[ "$2" == --enclave-id && "$3" == owned ]] || exit 99
        printf '%s\n%s\n' '{"level":"INFO","message":"from \u001benclave"}' "$(head -c 20000 /dev/zero | tr '\0' z)"
        echo console >> "$CASE_DIR/events"
        exec sleep 30
        ;;
    terminate-enclave)
        [[ "$2" == --enclave-id && "$3" == owned ]] || exit 99
        if [[ "$SCENARIO" == console ]]; then
            # The relay must stay attached until the enclave is gone.
            for ((i=0; i<100; i++)); do grep -q '^console$' "$CASE_DIR/events" && break; sleep 0.05; done
            sleep 0.5
        fi
        echo terminate-owned >> "$CASE_DIR/events"
        [[ "$SCENARIO" != cleanup_fail ]] || exit 1
        rm -f "$CASE_DIR/owned"
        ;;
    *) exit 1 ;;
esac
MOCK
chmod +x "$suite/bin/"*
export PATH="$suite/bin:$PATH"
export EIF_PATH="$suite/enclave.eif"
# An owner-selected bucket/key, without any release-name or environment convention.
export BUNDLE_ARTIFACT_URI=s3://model-artifacts/team-a/candidate.tar.gz
export BOOTSTRAP_TIMEOUT_SECONDS=2 POLL_SECONDS=1

run_case() {
    export SCENARIO=$1 CASE_DIR="$suite/$1" ARCHIVE="${2:-$suite/good.tar.gz}"
    unset ENCLAVE_DEBUG_MODE
    if [[ "$SCENARIO" == debug_launch_fail ]]; then export ENCLAVE_DEBUG_MODE=true; fi
    if [[ "$SCENARIO" == measured_launch_fail ]]; then export ENCLAVE_DEBUG_MODE=false; fi
    if [[ "$SCENARIO" == invalid_debug ]]; then export ENCLAVE_DEBUG_MODE=typo; fi
    unset ENCLAVE_CONSOLE_LOGS
    if [[ "$SCENARIO" == console_without_debug ]]; then export ENCLAVE_CONSOLE_LOGS=true; fi
    if [[ "$SCENARIO" == console ]]; then export ENCLAVE_DEBUG_MODE=true ENCLAVE_CONSOLE_LOGS=true; fi
    mkdir -p "$CASE_DIR"
    export BUNDLE_READY_FILE="$CASE_DIR/ready"
    BUNDLE_ARTIFACT_SHA256=$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)
    export BUNDLE_ARTIFACT_SHA256
    export BUNDLE_ARTIFACT_URI=s3://model-artifacts/team-a/candidate.tar.gz
    if [[ "$SCENARIO" == checksum ]]; then BUNDLE_ARTIFACT_SHA256=$(printf '%064d' 1); fi
    if [[ "$SCENARIO" == invalid_checksum ]]; then BUNDLE_ARTIFACT_SHA256=placeholder; touch "$BUNDLE_READY_FILE"; fi
    if [[ "$SCENARIO" == empty_checksum ]]; then BUNDLE_ARTIFACT_SHA256=""; touch "$BUNDLE_READY_FILE"; fi
    if [[ "$SCENARIO" == empty_uri ]]; then BUNDLE_ARTIFACT_URI=""; touch "$BUNDLE_READY_FILE"; fi
    if [[ "$SCENARIO" == missing_uri ]]; then unset BUNDLE_ARTIFACT_URI; touch "$BUNDLE_READY_FILE"; fi
    "$PROVISIONER_BIN" > "$CASE_DIR/output" 2>&1 &
    provisioner_pid=$!
}
finish_failure() {
    if wait "$provisioner_pid"; then echo "FAIL: $SCENARIO unexpectedly succeeded"; exit 1; fi
    provisioner_pid=""
    [[ ! -e "$BUNDLE_READY_FILE" ]] || { echo "FAIL: $SCENARIO left readiness"; exit 1; }
    if [[ "$SCENARIO" != cleanup_fail ]]; then [[ ! -e "$CASE_DIR/owned" ]]; fi
    echo "PASS: $SCENARIO"
}

for scenario in invalid_debug console_without_debug missing_uri empty_uri empty_checksum invalid_checksum download_fail checksum dynamic shared_library; do
    run_case "$scenario"
    finish_failure
    assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null
    if [[ "$scenario" == invalid_debug || "$scenario" == console_without_debug || "$scenario" == missing_uri || "$scenario" == empty_uri || "$scenario" == empty_checksum ]]; then
        assert_not grep -q '^download$' "$CASE_DIR/events" 2>/dev/null
    fi
done
for scenario in launch_fail measured_launch_fail debug_launch_fail launch_timeout cleanup_fail; do
    run_case "$scenario"
    finish_failure
    [[ $(grep -c '^launch$' "$CASE_DIR/events") == 1 ]]
    grep -q '^terminate-owned$' "$CASE_DIR/events"
done

# Provisioning fails without a real enclave; the relay must still copy console lines verbatim.
run_case console
finish_failure
grep -q '^terminate-owned$' "$CASE_DIR/events"
grep -qxF '{"level":"INFO","message":"from \u001benclave"}' "$CASE_DIR/output" || { echo "FAIL: console JSON not relayed"; cat "$CASE_DIR/output"; exit 1; }
grep -qx "$(head -c 16384 /dev/zero | tr '\0' z) \[truncated\]" "$CASE_DIR/output" || { echo "FAIL: long console line not cut"; exit 1; }
grep -q 'ENCLAVE_CONSOLE_LOGS requires ENCLAVE_DEBUG_MODE' "$suite/console_without_debug/output"
echo 'PASS: debug console is relayed to stdout until termination'

run_case signal_launch
for ((i=0; i<100; i++)); do
    if grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null; then break; fi
    sleep 0.01
done
grep -q '^launch$' "$CASE_DIR/events"
kill -TERM "$provisioner_pid"
wait "$provisioner_pid"
provisioner_pid=""
[[ ! -e "$BUNDLE_READY_FILE" && ! -e "$CASE_DIR/owned" ]]
grep -q '^terminate-owned$' "$CASE_DIR/events"
echo 'PASS: SIGTERM during launch cleans up only the owned enclave'

mkdir -p "$suite/bad/release"
ln -s /etc/passwd "$suite/bad/release/biometric-engines-worker"
tar -czf "$suite/link.tar.gz" -C "$suite/bad" release
run_case symlink "$suite/link.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null

tar -czf "$suite/duplicate.tar.gz" -C "$suite/archive" release/biometric-engines-worker release/biometric-engines-worker
run_case duplicate "$suite/duplicate.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null

printf 'unexpected library\n' > "$suite/archive/release/library.so"
tar -czf "$suite/extra.tar.gz" -C "$suite/archive" release
run_case extra_file "$suite/extra.tar.gz"
finish_failure
assert_not grep -q '^launch$' "$CASE_DIR/events" 2>/dev/null
echo 'All provisioner contract tests passed.'
