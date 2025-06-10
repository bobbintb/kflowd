#!/bin/bash

TEST_SOCKET_PATH="/tmp/kflowd_test.sock"
OUTPUT_FILE="/tmp/kflowd_test_output.txt"
# KFLOWD_PATH="../bin/kflowd" # Assuming script is run from tests/ directory
# Updated path to match CI build output structure when run from repo root:
KFLOWD_PATH="./src/x86_64/kflowd"

# Clean up previous test runs if any
rm -f "$TEST_SOCKET_PATH"
rm -f "$OUTPUT_FILE"

echo "Starting Unix socket output test..."

# 1. Check if socat is available
if ! command -v socat &> /dev/null; then
    echo "Error: socat is not installed. Please install socat to run this test."
    exit 1
fi
echo "socat found."

# 2. Start socat in the background
echo "Starting socat to listen on $TEST_SOCKET_PATH and write to $OUTPUT_FILE..."
socat UNIX-RECVFROM:"$TEST_SOCKET_PATH",fork OPEN:"$OUTPUT_FILE",creat,append &
SOCAT_PID=$!
echo "socat started with PID $SOCAT_PID."

# Wait for socat to start (give it a couple of seconds)
sleep 2

# Check if socat is running
if ! ps -p $SOCAT_PID > /dev/null; then
    echo "Error: socat failed to start."
    # Attempt to clean up socket file if it was created by a failed socat
    rm -f "$TEST_SOCKET_PATH"
    exit 1
fi
echo "socat is running."

# 3. Run kflowd
echo "Running kflowd to send data to $TEST_SOCKET_PATH..."
# Ensure kflowd is run with sudo if it needs root privileges
# Using timeout to ensure kflowd doesn't run indefinitely
timeout 5s sudo "$KFLOWD_PATH" -x "$TEST_SOCKET_PATH" -q

KFLOWD_EXIT_CODE=$?
if [ $KFLOWD_EXIT_CODE -eq 124 ]; then
    echo "kflowd finished due to timeout (expected for this test)."
elif [ $KFLOWD_EXIT_CODE -ne 0 ]; then
    echo "Error: kflowd exited with code $KFLOWD_EXIT_CODE."
    # kflowd might have failed, proceed to kill socat and check output anyway
fi

# 4. Kill socat
echo "Stopping socat (PID $SOCAT_PID)..."
kill $SOCAT_PID
wait $SOCAT_PID 2>/dev/null # Suppress "Terminated" message
echo "socat stopped."

# 5. Perform checks
PASSED=true

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Test Failed: Output file $OUTPUT_FILE was not created."
    PASSED=false
else
    echo "Output file $OUTPUT_FILE was created."
    if [ ! -s "$OUTPUT_FILE" ]; then
        echo "Test Failed: Output file $OUTPUT_FILE is empty."
        PASSED=false
    else
        echo "Output file $OUTPUT_FILE is not empty."
        # Check for basic JSON structure (starts with '{', ends with '}', contains "InfoTimestamp")
        # Using grep -c to count matches. Expecting at least one JSON record.
        if grep -q '^{' "$OUTPUT_FILE" && grep -q '}' "$OUTPUT_FILE" && grep -q '"InfoTimestamp"' "$OUTPUT_FILE"; then
            echo "JSON-like structure found in output file."
        else
            echo "Test Failed: Output file does not contain expected JSON structure."
            echo "--- Output File Content Start ---"
            cat "$OUTPUT_FILE"
            echo "--- Output File Content End ---"
            PASSED=false
        fi
    fi
fi

# 6. Clean up
echo "Cleaning up..."
rm -f "$TEST_SOCKET_PATH"
rm -f "$OUTPUT_FILE"
echo "Socket file $TEST_SOCKET_PATH and output file $OUTPUT_FILE removed."

# 7. Final result
if [ "$PASSED" = true ]; then
    echo "Test passed!"
    exit 0
else
    echo "Test failed."
    exit 1
fi
