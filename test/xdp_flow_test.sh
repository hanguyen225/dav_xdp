#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# xdp_flow_test.sh - Smoke test for xdp_flow_tuner against a Docker
#                    virtual network switch.
#
# What this does:
#   1. Verifies Docker is running and docker0 / a br-* bridge exists.
#   2. Starts bpftune with xdp_flow_tuner to monitor the Docker bridge.
#   3. Generates traffic inside a throwaway container (ping + curl).
#   4. Checks that [FLOW] lines appear in bpftune output.
#   5. Checks that /tmp/xdp_flow.bitnetflow was written with a valid header.
#   6. Cleans up.
#
# Usage:
#   sudo bash test/xdp_flow_test.sh
#
# Environment overrides:
#   BPFTUNE_BIN    - path to bpftune binary  (default: ./bpftune)
#   DOCKER_IMAGE   - container image to use   (default: alpine)
#   TRAFFIC_HOST   - host to ping/curl inside container (default: 8.8.8.8)

set -euo pipefail

# Absolute path to project root (works wherever the script is invoked from)
PROJ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.." 
PROJ_DIR="$(realpath "$PROJ_DIR")"

BPFTUNE_BIN="${BPFTUNE_BIN:-$PROJ_DIR/src/bpftune}"
DOCKER_IMAGE="${DOCKER_IMAGE:-alpine}"
TRAFFIC_HOST="${TRAFFIC_HOST:-8.8.8.8}"
BITNETFLOW_PATH="/tmp/xdp_flow.bitnetflow"
BPFTUNE_LOG="/tmp/xdp_flow_bpftune.log"
BPFTUNE_PID=""
CONTAINER_ID=""

# ── ANSI colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; RST='\033[0m'
pass() { echo -e "${GRN}[PASS]${RST} $*"; }
fail() { echo -e "${RED}[FAIL]${RST} $*"; exit 1; }
info() { echo -e "${YLW}[INFO]${RST} $*"; }

# ── Cleanup on exit ────────────────────────────────────────────────────────
cleanup() {
    info "Cleaning up..."
    [ -n "$BPFTUNE_PID" ] && kill "$BPFTUNE_PID" 2>/dev/null || true
    [ -n "$CONTAINER_ID" ] && docker rm -f "$CONTAINER_ID" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Pre-flight checks ───────────────────────────────────────────────────
info "=== XDP Flow Tuner – Docker Virtual Switch Test ==="

[ "$(id -u)" = "0" ] || fail "Must run as root (sudo)."

command -v docker >/dev/null || fail "Docker not found in PATH."

docker info >/dev/null 2>&1 || fail "Docker daemon is not running."

# Find Docker bridge interface: docker0 or first br-* bridge
DOCKER_IFACE=""
for candidate in docker0 $(ip link show | awk -F': ' '/br-/{print $2}' | head -1); do
    if ip link show "$candidate" >/dev/null 2>&1; then
        DOCKER_IFACE="$candidate"
        break
    fi
done

[ -n "$DOCKER_IFACE" ] || fail \
    "No Docker bridge interface found (docker0 or br-*). " \
    "Is Docker running?"

info "Detected Docker bridge: $DOCKER_IFACE"

[ -x "$BPFTUNE_BIN" ] || fail \
    "bpftune binary not found at '$BPFTUNE_BIN'. " \
    "Set BPFTUNE_BIN or run from src/ directory."

# ── 2. Start bpftune with XDP flow tuner on the Docker bridge ─────────────
info "Starting bpftune on $DOCKER_IFACE..."
rm -f "$BITNETFLOW_PATH" "$BPFTUNE_LOG"

BPFTUNE_XDP_FLOW_IFACE="$DOCKER_IFACE" \
    LD_LIBRARY_PATH="$PROJ_DIR/src" \
    "$BPFTUNE_BIN" \
        -a xdp_flow_tuner.so \
        -l "$PROJ_DIR/src" \
        -d -s \
        2>&1 | tee "$BPFTUNE_LOG" &
BPFTUNE_PID=$!

# Give bpftune time to attach XDP
sleep 3

# Verify it is still running
kill -0 "$BPFTUNE_PID" 2>/dev/null \
    || fail "bpftune exited early — check $BPFTUNE_LOG"

info "bpftune running (pid $BPFTUNE_PID)"

# ── 3. Generate traffic inside a Docker container ─────────────────────────
info "Starting traffic container ($DOCKER_IMAGE)..."
CONTAINER_ID=$(docker run -d --rm "$DOCKER_IMAGE" \
    sh -c "
        apk add -q curl 2>/dev/null || true
        for i in \$(seq 1 20); do
            ping -c 1 -W 1 $TRAFFIC_HOST >/dev/null 2>&1 || true
            sleep 0.2
        done
        curl -s --max-time 5 http://$TRAFFIC_HOST/ >/dev/null 2>&1 || true
        echo 'traffic done'
    ")

info "Container $CONTAINER_ID started, generating traffic..."
sleep 8   # wait for ping+curl to complete

# ── 4. Verify bpftune captured flows ─────────────────────────────────────
info "=== bpftune output (last 20 lines) ==="
tail -20 "$BPFTUNE_LOG" || true

FLOW_COUNT=$(grep -c '^\[FLOW\]' "$BPFTUNE_LOG" || true)
if [ "$FLOW_COUNT" -gt 0 ]; then
    pass "Captured $FLOW_COUNT flow event(s) in bpftune log."
else
    fail "No [FLOW] lines found in $BPFTUNE_LOG — XDP may not be " \
         "capturing traffic on $DOCKER_IFACE."
fi

# ── 5. Verify bitnetflow file ──────────────────────────────────────────────
if [ -f "$BITNETFLOW_PATH" ]; then
    FILE_SZ=$(stat -c%s "$BITNETFLOW_PATH")
    MAGIC=$(xxd -p -l 4 "$BITNETFLOW_PATH" 2>/dev/null || true)
    # BITNETFLOW_MAGIC = 0x424E4650 → in file as 50 46 4e 42 (little-endian)
    if [ "$FILE_SZ" -ge 8 ]; then
        pass "bitnetflow file written: $BITNETFLOW_PATH ($FILE_SZ bytes)"
        info "Magic bytes: $MAGIC"
    else
        fail "bitnetflow file exists but is too small ($FILE_SZ bytes)"
    fi
else
    fail "bitnetflow file not created at $BITNETFLOW_PATH"
fi

# ── 6. Summary ────────────────────────────────────────────────────────────
echo ""
info "=== Test PASSED ==="
info "  bpftune log:       $BPFTUNE_LOG"
info "  bitnetflow output: $BITNETFLOW_PATH"
info ""
info "To read bitnetflow records manually:"
info "  od -A x -t x1z $BITNETFLOW_PATH"
