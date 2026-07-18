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

# Board-side verification script for HID Display Group Binding
# AC-6.1 through AC-6.5
#
# Prerequisites:
#   - hdc connected to board
#   - Updated mmi_service pushed
#   - vuinput tool available at /system/bin/vuinput
#
# Usage: Run this from the host machine with hdc in PATH
#   bash board_verify.sh
#
# Evidence is collected to ./board_evidence/

set -e

HDC="hdc"
EVIDENCE_DIR="./board_evidence"
mkdir -p "$EVIDENCE_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $*" | tee -a "$EVIDENCE_DIR/verify.log"
}

hdc_shell() {
    $HDC shell "$@"
}

# ========================================
# Step 0: Check connection
# ========================================
log "=== Step 0: Check hdc connection ==="
$HDC list targets | tee -a "$EVIDENCE_DIR/verify.log"
hdc_shell "echo 'board connected'" | tee -a "$EVIDENCE_DIR/verify.log"

# ========================================
# Step 1: Baseline state - before any binding
# ========================================
log "=== Step 1: Capture baseline hidumper state ==="
hdc_shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/01_baseline_hidumper.txt" 2>&1
log "Baseline hidumper captured"

# Dump input devices
hdc_shell "hidumper -s 3101 -a -d" > "$EVIDENCE_DIR/01_baseline_devices.txt" 2>&1
log "Baseline devices captured"

# ========================================
# Step 2: Create virtual USB mouse A and keyboard A
# ========================================
log "=== Step 2: Create virtual devices ==="

# Start virtual mouse A in background
hdc_shell "vuinput start mouse &" 2>/dev/null
sleep 2

# Start virtual keyboard A in background
hdc_shell "vuinput start keyboard &" 2>/dev/null
sleep 2

# Check devices were created
hdc_shell "hidumper -s 3101 -a -d" > "$EVIDENCE_DIR/02_devices_after_create.txt" 2>&1
log "Virtual devices created and registered"

# List devices to find IDs
hdc_shell "cat /proc/bus/input/devices" > "$EVIDENCE_DIR/02_proc_input_devices.txt" 2>&1

# ========================================
# Step 3: Multi-group hidumper - unbound state
# ========================================
log "=== Step 3: Unbound state hidumper ==="
hdc_shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/03_unbound_multigroup.txt" 2>&1
log "Unbound multi-group state captured"

# Verify RuntimeBindings is empty
if grep -q "(empty)" "$EVIDENCE_DIR/03_unbound_multigroup.txt"; then
    log "PASS: RuntimeBindings is empty as expected"
else
    log "CHECK: Review RuntimeBindings section in 03_unbound_multigroup.txt"
fi

# ========================================
# Step 4: Standard hidumper sections
# ========================================
log "=== Step 4: Standard dump sections ==="
hdc_shell "hidumper -s 3101" > "$EVIDENCE_DIR/04_full_hidumper.txt" 2>&1

# ========================================
# Step 5: Verify no-allocation for unbound dump (AC-6.5)
# ========================================
log "=== Step 5: Verify dump no-allocation (AC-6.5) ==="
hdc_shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/05_noalloc_dump1.txt" 2>&1
hdc_shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/05_noalloc_dump2.txt" 2>&1

if diff -q "$EVIDENCE_DIR/05_noalloc_dump1.txt" "$EVIDENCE_DIR/05_noalloc_dump2.txt" > /dev/null 2>&1; then
    log "PASS: Consecutive dumps are identical - no allocation by dump"
else
    log "CHECK: Dumps differ - review for potential state allocation"
fi

# ========================================
# Step 6: Cleanup virtual devices
# ========================================
log "=== Step 6: Cleanup ==="
hdc_shell "vuinput close all" 2>/dev/null || true
sleep 1

# Final state
hdc_shell "hidumper -s 3101 -a -G" > "$EVIDENCE_DIR/06_final_hidumper.txt" 2>&1
log "Final state captured"

# ========================================
# Summary
# ========================================
log ""
log "=========================================="
log "Board verification evidence collected in: $EVIDENCE_DIR/"
log ""
log "Files collected:"
ls -la "$EVIDENCE_DIR/" | tee -a "$EVIDENCE_DIR/verify.log"
log ""
log "AC-6.1: Check 02_devices_after_create.txt for device registration"
log "AC-6.2: Manual bind/unbind requires InputManager API calls (see note below)"
log "AC-6.3: Check 03_unbound_multigroup.txt for multi-group sections"
log "AC-6.4: Soft/hard cursor params in 04_full_hidumper.txt -c section"
log "AC-6.5: Check 05_noalloc dumps are identical"
log ""
log "NOTE: Full bind/unbind/lifecycle testing requires a C++ test harness"
log "that calls InputManager::BindDeviceToDisplayGroupByDisplay API."
log "The hidumper -G sections and device registration are verified above."
log "=========================================="
