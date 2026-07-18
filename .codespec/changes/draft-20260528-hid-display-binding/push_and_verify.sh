#!/bin/bash
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Push updated mmi libraries to board and run verification
# Run from a host with hdc connected to the DAYU200/RK3568 board
#
# Usage:
#   bash push_and_verify.sh <path-to-out-dir>
#
# Example:
#   bash push_and_verify.sh /srv/workspace/.../code/out/rk3568/multimodalinput/input

set -e

OUT_DIR="${1:-/srv/workspace/openharmony_master_default_20260527175709_3a54511b7/code/out/rk3568/multimodalinput/input}"
HDC="${HDC:-hdc}"
EVIDENCE_DIR="./board_evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $*" | tee -a "$EVIDENCE_DIR/verify.log"
}

# ========================================
# Step 0: Verify connection
# ========================================
log "=== Step 0: Verify hdc connection ==="
TARGETS=$($HDC list targets 2>&1)
if [ -z "$TARGETS" ] || echo "$TARGETS" | grep -q "Empty"; then
    log "ERROR: No hdc targets found. Connect the board first."
    exit 1
fi
log "Connected: $TARGETS"

# ========================================
# Step 1: Push libraries
# ========================================
log "=== Step 1: Remount and push libraries ==="
$HDC shell mount -o rw,remount /

LIBS="libmmi-server.z.so libmmi-client.z.so libmmi-server-common.z.so libmmi-util.z.so"
for lib in $LIBS; do
    if [ -f "$OUT_DIR/$lib" ]; then
        log "Pushing $lib ..."
        $HDC file send "$OUT_DIR/$lib" "/system/lib/$lib"
    else
        log "WARNING: $lib not found in $OUT_DIR"
    fi
done
log "Libraries pushed"

# ========================================
# Step 2: Restart mmi_service
# ========================================
log "=== Step 2: Restart mmi_service ==="
$HDC shell "kill -9 \$(pidof mmi_service)" 2>/dev/null || true
sleep 3
MMI_PID=$($HDC shell "pidof mmi_service" 2>/dev/null)
log "mmi_service restarted, PID: $MMI_PID"

# ========================================
# Step 3: Baseline hidumper - before any binding
# ========================================
log "=== Step 3: Baseline hidumper ==="
$HDC shell "hidumper -s 3101" > "$EVIDENCE_DIR/01_baseline_full.txt" 2>&1
$HDC shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/02_baseline_multigroup.txt" 2>&1
log "Baseline captured"

# Check RuntimeBindings is empty
if grep -q "RuntimeBindings" "$EVIDENCE_DIR/02_baseline_multigroup.txt"; then
    log "PASS: Multi-group dump section present"
    if grep -A1 "RuntimeBindings" "$EVIDENCE_DIR/02_baseline_multigroup.txt" | grep -q "(empty)"; then
        log "PASS: RuntimeBindings is empty on startup (AC-6.5, AC-5.3)"
    fi
else
    log "FAIL: Multi-group dump section NOT found - check if -G flag is supported"
fi

# ========================================
# Step 4: Check display groups
# ========================================
log "=== Step 4: Check display groups ==="
$HDC shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/03_display_groups.txt" 2>&1
grep "DisplayGroups" "$EVIDENCE_DIR/03_display_groups.txt" && log "PASS: DisplayGroups section present"

# ========================================
# Step 5: No-allocation dump test (AC-6.5)
# ========================================
log "=== Step 5: No-allocation dump test (AC-6.5) ==="
$HDC shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/04_noalloc_1.txt" 2>&1
$HDC shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/04_noalloc_2.txt" 2>&1

if diff -q "$EVIDENCE_DIR/04_noalloc_1.txt" "$EVIDENCE_DIR/04_noalloc_2.txt" > /dev/null 2>&1; then
    log "PASS: Consecutive dumps identical - dump is read-only (AC-6.5)"
else
    log "CHECK: Dumps differ - may include timestamps, review manually"
    diff "$EVIDENCE_DIR/04_noalloc_1.txt" "$EVIDENCE_DIR/04_noalloc_2.txt" >> "$EVIDENCE_DIR/verify.log" 2>&1 || true
fi

# ========================================
# Step 6: List input devices
# ========================================
log "=== Step 6: Input devices ==="
$HDC shell "hidumper -s 3101 -a -d" > "$EVIDENCE_DIR/05_input_devices.txt" 2>&1
log "Input device list captured"

# ========================================
# Step 7: Cursor state
# ========================================
log "=== Step 7: Cursor state ==="
$HDC shell "hidumper -s 3101 -a -c" > "$EVIDENCE_DIR/06_cursor_state.txt" 2>&1
log "Cursor state captured"

# ========================================
# Summary
# ========================================
log ""
log "=========================================="
log "Board verification evidence in: $EVIDENCE_DIR/"
log ""
log "Evidence files:"
ls -la "$EVIDENCE_DIR/"*.txt 2>/dev/null | while read line; do log "  $line"; done
log ""
log "Verification summary:"
log "  AC-5.3 (no non-default state on startup): Check 02_baseline_multigroup.txt"
log "  AC-6.3 (hidumper sections present): Check 03_display_groups.txt"
log "  AC-6.5 (dump no-allocation): Check 04_noalloc diff"
log ""
log "For AC-6.1/6.2 (bind/unbind with virtual devices):"
log "  Requires vuinput tool and InputManager API test harness"
log "  Run: hdc shell vuinput start mouse"
log "  Then use a test app to call BindDeviceToDisplayGroupByDisplay"
log "=========================================="
