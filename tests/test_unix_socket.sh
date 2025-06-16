#!/bin/bash

# Test script for dirt Unix domain socket creation and handling.

# Variables
TEST_SOCKET_PATH="/tmp/dirt_test.sock"
DIRT_CMD_REL_PATH="../src/dirt" # Relative path from tests/ to src/
DIRT_CMD_ABS_PATH="" # Will be resolved
LOG_FILE="/tmp/dirt_test.log"
ERR_LOG_FILE="/tmp/dirt_test_error.log"
DIRT_PID_FILE="/tmp/dirt_test.pid"

# Default DIRT_CMD path if not overridden by environment variable
: "${DIRT_CMD_DEFAULT:=${DIRT_CMD_REL_PATH}}"

# Determine DIRT_CMD path (absolute)
# Check if DIRT_CMD environment variable is set
if [ -n "$DIRT_CMD" ]; then
    if [ -x "$DIRT_CMD" ]; then
        DIRT_CMD_ABS_PATH="$DIRT_CMD"
    else
        echo "Error: DIRT_CMD environment variable is set to '$DIRT_CMD', but it's not executable or found."
        exit 1
    fi
elif [ -x "$DIRT_CMD_DEFAULT" ]; then
    # Convert to absolute path
    DIRT_CMD_ABS_PATH="$(cd "$(dirname "$DIRT_CMD_DEFAULT")" && pwd)/$(basename "$DIRT_CMD_DEFAULT")"
    if [ ! -x "$DIRT_CMD_ABS_PATH" ]; then # Double check after resolving path
        echo "Error: Default dirt command '$DIRT_CMD_DEFAULT' resolved to '$DIRT_CMD_ABS_PATH' is not executable or not found."
        # Fallback for CI/local if structure is different, e.g. building in src/x86_64/
        ALT_DIRT_PATH="./src/x86_64/dirt"
        if [ -x "$ALT_DIRT_PATH" ]; then
             DIRT_CMD_ABS_PATH="$(cd "$(dirname "$ALT_DIRT_PATH")" && pwd)/$(basename "$ALT_DIRT_PATH")"
             echo "Using alternative path: $DIRT_CMD_ABS_PATH"
        else
             ALT_DIRT_PATH="../../src/dirt" # if script is run from tests/
             if [ -x "$ALT_DIRT_PATH" ]; then
                DIRT_CMD_ABS_PATH="$(cd "$(dirname "$ALT_DIRT_PATH")" && pwd)/$(basename "$ALT_DIRT_PATH")"
                echo "Using alternative relative path: $DIRT_CMD_ABS_PATH"
             else
                echo "Error: Could not find dirt executable at default or alternative paths."
                exit 1
             fi
        fi
    fi
else
    echo "Error: Default dirt command '$DIRT_CMD_DEFAULT' is not executable or not found, and DIRT_CMD env var not set."
    exit 1
fi

echo "Using dirt command: $DIRT_CMD_ABS_PATH"

# Counters for test results
declare -i tests_run=0
declare -i tests_passed=0
declare -i tests_failed=0

# --- Helper Functions ---

cleanup() {
    echo "Cleaning up..."
    stop_dirt_process
    rm -f "$TEST_SOCKET_PATH"
    rm -f "$LOG_FILE"
    rm -f "$ERR_LOG_FILE"
    rm -f "$DIRT_PID_FILE"
    echo "Cleanup finished."
}

# Trap EXIT signal to ensure cleanup runs
trap cleanup EXIT

start_dirt_bg() {
    # $1: arguments for dirt
    echo "Starting dirt in background with args: $1"
    # Use sudo if DIRT_CMD_ABS_PATH requires it. For simplicity, assuming sudo is needed for socket ops.
    sudo "$DIRT_CMD_ABS_PATH" -x "$TEST_SOCKET_PATH" $1 > "$LOG_FILE" 2> "$ERR_LOG_FILE" &
    echo $! > "$DIRT_PID_FILE"
    # Give dirt a moment to start, especially if it's creating a socket
    sleep 0.5
    if ! ps -p "$(cat $DIRT_PID_FILE)" > /dev/null; then
        echo "  ERROR: dirt failed to start. Check $LOG_FILE and $ERR_LOG_FILE."
        cat "$LOG_FILE"
        cat "$ERR_LOG_FILE"
        return 1
    fi
    echo "  dirt started with PID $(cat $DIRT_PID_FILE)."
    return 0
}

stop_dirt_process() {
    if [ -f "$DIRT_PID_FILE" ]; then
        local pid
        pid=$(cat "$DIRT_PID_FILE")
        if ps -p "$pid" > /dev/null; then
            echo "Stopping dirt process (PID $pid)..."
            sudo kill "$pid"
            # Wait for it to actually terminate
            for _ in {1..50}; do # Wait up to 5 seconds
                if ! ps -p "$pid" > /dev/null; then
                    echo "  dirt process $pid stopped."
                    rm -f "$DIRT_PID_FILE"
                    return 0
                fi
                sleep 0.1
            done
            echo "  Warning: dirt process $pid did not stop after 5 seconds. Forcing kill."
            sudo kill -9 "$pid"
        fi
        rm -f "$DIRT_PID_FILE"
    fi
    return 0
}

check_socket_exists() {
    # $1: socket path
    if [ -S "$1" ]; then
        return 0 # Exists and is a socket
    fi
    return 1 # Does not exist or not a socket
}

remove_socket_if_exists() {
    # $1: socket path
    if [ -e "$1" ]; then # Check if any file type exists
        echo "Removing existing file/socket at $1..."
        sudo rm -f "$1"
    fi
}

# --- Test Assertion Functions ---
# These functions increment test counters and print pass/fail messages.

# _assert_condition condition "Failure message" "Success message"
_assert_condition() {
    tests_run+=1
    local condition_met=false
    eval "$1" && condition_met=true # Evaluate the condition string

    if $condition_met; then
        echo "PASS: $3"
        tests_passed+=1
        return 0
    else
        echo "FAIL: $2"
        tests_failed+=1
        # Optionally, print more debug info here if needed for all failures
        return 1
    fi
}

assert_socket_exists() {
    # $1: socket path, $2: descriptive message for success/failure context
    _assert_condition "[ -S \"$1\" ]" "Socket $1 should exist but does not. ($2)" "Socket $1 exists as expected. ($2)"
}

assert_socket_not_exists() {
    # $1: socket path, $2: descriptive message
    _assert_condition "[ ! -S \"$1\" ]" "Socket $1 should NOT exist but it does. ($2)" "Socket $1 does NOT exist as expected. ($2)"
}

assert_file_contains() {
    # $1: file path, $2: pattern, $3: descriptive message
    _assert_condition "grep -q \"$2\" \"$1\"" "File $1 does not contain pattern '$2'. ($3)" "File $1 contains pattern '$2' as expected. ($3)"
}

assert_file_not_contains() {
    # $1: file path, $2: pattern, $3: descriptive message
    _assert_condition "! grep -q \"$2\" \"$1\"" "File $1 unexpectedly contains pattern '$2'. ($3)" "File $1 does not contain pattern '$2' as expected. ($3)"
}


# --- Test Cases ---

test_prompt_create_socket_yes() {
    echo -e "\n--- Test Case 1: Prompt for socket creation (yes input) ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    assert_socket_not_exists "$TEST_SOCKET_PATH" "Initial state"

    echo "Running dirt and piping 'y' for interactive prompt..."
    # Clear log files for this specific run
    > "$LOG_FILE"
    > "$ERR_LOG_FILE"
    # The prompt goes to stdout of dirt, so we need to capture that if we want to verify the prompt text itself.
    # For now, focusing on the outcome (socket creation).
    # `sudo` is tricky with pipes if `Defaults requiretty` is set in sudoers.
    # `echo 'y' | sudo -S "$DIRT_CMD_ABS_PATH" -x "$TEST_SOCKET_PATH"` might be needed if `sudo` is problematic.
    # Assuming dirt exits quickly after prompt if not daemonized further.
    timeout 5s sh -c "echo 'y' | sudo $DIRT_CMD_ABS_PATH -x $TEST_SOCKET_PATH -V" > "$LOG_FILE" 2> "$ERR_LOG_FILE"
    # Adding -V for verbose, which might print "Unix socket ... created successfully." to stderr

    # Check for socket creation and message
    assert_socket_exists "$TEST_SOCKET_PATH" "Socket created after 'y' prompt"
    # Check if dirt mentioned creating it (from verbose output)
    assert_file_contains "$ERR_LOG_FILE" "Unix socket $TEST_SOCKET_PATH created successfully." "Dirt reported successful socket creation"

    remove_socket_if_exists "$TEST_SOCKET_PATH"
    stop_dirt_process # Ensure it's stopped if timeout didn't get it or it self-terminated.
}

test_prompt_create_socket_no() {
    echo -e "\n--- Test Case 2: Prompt for socket creation (no input) ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    assert_socket_not_exists "$TEST_SOCKET_PATH" "Initial state"

    echo "Running dirt and piping 'n' for interactive prompt..."
    > "$LOG_FILE"
    > "$ERR_LOG_FILE"
    timeout 5s sh -c "echo 'n' | sudo $DIRT_CMD_ABS_PATH -x $TEST_SOCKET_PATH" > "$LOG_FILE" 2> "$ERR_LOG_FILE"

    assert_socket_not_exists "$TEST_SOCKET_PATH" "Socket NOT created after 'n' prompt"
    assert_file_contains "$LOG_FILE" "Proceeding without Unix socket output." "Dirt reported proceeding without socket"

    remove_socket_if_exists "$TEST_SOCKET_PATH"
    stop_dirt_process
}

test_auto_create_socket_flag() {
    echo -e "\n--- Test Case 3: Automatic socket creation with --create-socket ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    assert_socket_not_exists "$TEST_SOCKET_PATH" "Initial state"

    echo "Running dirt with -c flag..."
    # Expect dirt to start and then we'll stop it.
    start_dirt_bg "-c -q" # -q for quiet, less log noise
    if [ $? -ne 0 ]; then
      _assert_condition "false" "dirt failed to start with -c" "dirt started with -c (placeholder)"
      return
    fi

    assert_socket_exists "$TEST_SOCKET_PATH" "Socket created automatically with -c"

    stop_dirt_process
    remove_socket_if_exists "$TEST_SOCKET_PATH"
}

test_auto_create_socket_flag_daemon() {
    echo -e "\n--- Test Case 4: Automatic socket creation with --create-socket in daemon mode ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    assert_socket_not_exists "$TEST_SOCKET_PATH" "Initial state"

    echo "Running dirt with -c -d flags..."
    start_dirt_bg "-c -d -q"
     if [ $? -ne 0 ]; then
      _assert_condition "false" "dirt failed to start with -c -d" "dirt started with -c -d (placeholder)"
      return
    fi

    assert_socket_exists "$TEST_SOCKET_PATH" "Socket created automatically with -c -d"

    stop_dirt_process
    remove_socket_if_exists "$TEST_SOCKET_PATH"
}

test_socket_missing_no_flag_daemon() {
    echo -e "\n--- Test Case 5: Socket missing, no -c, in daemon mode ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    assert_socket_not_exists "$TEST_SOCKET_PATH" "Initial state"

    > "$ERR_LOG_FILE" # Clear error log for this run
    start_dirt_bg "-d -q" # Start in daemon, quiet
     if [ $? -ne 0 ]; then
      _assert_condition "false" "dirt failed to start with -d (socket missing)" "dirt started with -d (socket missing) (placeholder)"
      # If start_dirt_bg returns error, it means dirt didn't stay running, which might be expected
      # depending on dirt's behavior (e.g. if it exits on this error).
      # For now, we assume it might log and continue without socket, or exit.
      # The critical part is the socket not existing and the log message.
    fi

    assert_socket_not_exists "$TEST_SOCKET_PATH" "Socket NOT created in daemon mode without -c"
    # Check stderr for the specific message
    assert_file_contains "$ERR_LOG_FILE" "Unix socket $TEST_SOCKET_PATH missing and --create-socket not specified in daemon mode. Disabling socket output." "Daemon mode message for missing socket without -c"

    stop_dirt_process # Important to clean up, even if socket wasn't used
    remove_socket_if_exists "$TEST_SOCKET_PATH"
}

test_existing_file_not_socket() {
    echo -e "\n--- Test Case 6: Existing file at socket path is NOT a socket ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"
    echo "Creating a regular file at $TEST_SOCKET_PATH..."
    sudo touch "$TEST_SOCKET_PATH"

    > "$ERR_LOG_FILE" # Clear error log
    # Run dirt, expect it to log error and not use socket (or exit)
    # Not running in background as it might exit quickly.
    timeout 5s sudo "$DIRT_CMD_ABS_PATH" -x "$TEST_SOCKET_PATH" -c -q > "$LOG_FILE" 2> "$ERR_LOG_FILE"

    # Socket should ideally be removed or dirt should not claim it
    # For this test, the critical part is the error message.
    # We can't use assert_socket_not_exists because a *file* exists.
    _assert_condition "[ ! -S \"$TEST_SOCKET_PATH\" ]" "Path $TEST_SOCKET_PATH is a socket, but should be a regular file. ($TEST_SOCKET_PATH)" "Path $TEST_SOCKET_PATH is not a socket (it's a file). (Initial state for test)"
    assert_file_contains "$ERR_LOG_FILE" "$TEST_SOCKET_PATH exists but is not a socket" "Error message for existing non-socket file"

    sudo rm -f "$TEST_SOCKET_PATH" # Clean up the regular file
    stop_dirt_process
}

test_preexisting_valid_socket() {
    echo -e "\n--- Test Case 7: Pre-existing valid socket ---"
    remove_socket_if_exists "$TEST_SOCKET_PATH"

    echo "Manually creating a dummy socket with socat..."
    socat UNIX-LISTEN:"$TEST_SOCKET_PATH",fork,reuseaddr EXEC:'/bin/true' & # Simple listener
    SOCAT_DUMMY_PID=$!
    sleep 0.5 # Give socat a moment
    if ! ps -p $SOCAT_DUMMY_PID > /dev/null || ! check_socket_exists "$TEST_SOCKET_PATH"; then
        echo "  ERROR: Failed to create dummy socket with socat for pre-existing test."
        _assert_condition "false" "Dummy socat setup failed" "Dummy socat setup (placeholder)"
        if ps -p $SOCAT_DUMMY_PID > /dev/null; then kill $SOCAT_DUMMY_PID; fi
        return
    fi
    echo "  Dummy socket created by socat (PID $SOCAT_DUMMY_PID)."

    start_dirt_bg "-q -V" # Start dirt, quiet but verbose for startup messages
     if [ $? -ne 0 ]; then
      _assert_condition "false" "dirt failed to start with pre-existing socket" "dirt started with pre-existing socket (placeholder)"
      kill $SOCAT_DUMMY_PID
      wait $SOCAT_DUMMY_PID 2>/dev/null
      return
    fi

    # Check that dirt reports using the existing socket (from verbose output)
    assert_file_contains "$ERR_LOG_FILE" "Using existing Unix socket $TEST_SOCKET_PATH" "Dirt reported using existing socket"
    # And that the socket still exists (dirt shouldn't have deleted it)
    assert_socket_exists "$TEST_SOCKET_PATH" "Pre-existing socket still exists after dirt start"

    stop_dirt_process
    echo "Stopping dummy socat (PID $SOCAT_DUMMY_PID)..."
    kill $SOCAT_DUMMY_PID
    wait $SOCAT_DUMMY_PID 2>/dev/null
    remove_socket_if_exists "$TEST_SOCKET_PATH"
}


# --- Main Test Execution ---
echo "============================="
echo "Starting Dirt Socket Tests..."
echo "============================="
echo "Dirt executable: $DIRT_CMD_ABS_PATH"
echo "Test socket path: $TEST_SOCKET_PATH"
echo "Log file: $LOG_FILE"
echo "Error log file: $ERR_LOG_FILE"
echo "-----------------------------"

# Ensure no leftover socket from previous failed run before starting tests
remove_socket_if_exists "$TEST_SOCKET_PATH"

# Run tests
test_prompt_create_socket_yes
test_prompt_create_socket_no
test_auto_create_socket_flag
test_auto_create_socket_flag_daemon
test_socket_missing_no_flag_daemon
test_existing_file_not_socket
test_preexisting_valid_socket


echo "-----------------------------"
echo "Test Summary:"
echo "Tests Run: $tests_run"
echo "Passed: $tests_passed"
echo "Failed: $tests_failed"
echo "============================="

# Exit with error code if any test failed
if [ "$tests_failed" -gt 0 ]; then
    echo "Some tests FAILED."
    exit 1
else
    echo "All tests PASSED."
    exit 0
fi
