#!/system/bin/sh
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

# Multi-group binding system test orchestrator
# Runs all gtest system test binaries, captures hidumper evidence,
# and produces a pass/fail summary.

EVIDENCE_DIR="/data/local/tmp"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
SUMMARY_FILE="${EVIDENCE_DIR}/systemtest_summary_${TIMESTAMP}.txt"
TOTAL=0
PASS=0
FAIL=0

log() {
    echo "$1"
    echo "$1" >> "${SUMMARY_FILE}"
}

run_test() {
    local test_binary="$1"
    local test_name="$2"
    local evidence_before="${EVIDENCE_DIR}/${test_name}_before_${TIMESTAMP}.txt"
    local evidence_after="${EVIDENCE_DIR}/${test_name}_after_${TIMESTAMP}.txt"
    local test_log="${EVIDENCE_DIR}/${test_name}_log_${TIMESTAMP}.txt"

    log ""
    log "============================================"
    log " Running: ${test_name}"
    log "============================================"

    # Capture hidumper state before test
    log "  Capturing hidumper before test..."
    hidumper -s 3101 -a -G > "${evidence_before}" 2>&1

    # Run the test binary
    log "  Executing: ${test_binary}"
    if [ -f "${test_binary}" ]; then
        "${test_binary}" --gtest_output="xml:${EVIDENCE_DIR}/${test_name}_result_${TIMESTAMP}.xml" \
            > "${test_log}" 2>&1
        local rc=$?

        # Capture hidumper state after test
        log "  Capturing hidumper after test..."
        hidumper -s 3101 -a -G > "${evidence_after}" 2>&1

        TOTAL=$((TOTAL + 1))
        if [ ${rc} -eq 0 ]; then
            log "  RESULT: PASS (exit code 0)"
            PASS=$((PASS + 1))
        else
            log "  RESULT: FAIL (exit code ${rc})"
            FAIL=$((FAIL + 1))
            log "  Test output:"
            tail -20 "${test_log}" | while IFS= read -r line; do
                log "    ${line}"
            done
        fi
    else
        log "  SKIP: binary not found at ${test_binary}"
        TOTAL=$((TOTAL + 1))
        FAIL=$((FAIL + 1))
    fi
}

# --- Main execution ---

log "========================================================="
log " Multi-Group Binding System Test Suite"
log " Timestamp: ${TIMESTAMP}"
log " Device: $(getprop ro.product.model 2>/dev/null || echo 'unknown')"
log "========================================================="

# Capture baseline system state
log ""
log "--- Baseline hidumper state ---"
hidumper -s 3101 -a -G > "${EVIDENCE_DIR}/baseline_${TIMESTAMP}.txt" 2>&1
log "  Saved to: ${EVIDENCE_DIR}/baseline_${TIMESTAMP}.txt"

# Capture device list
hidumper -s 3101 -a -d > "${EVIDENCE_DIR}/devices_${TIMESTAMP}.txt" 2>&1
log "  Device list saved to: ${EVIDENCE_DIR}/devices_${TIMESTAMP}.txt"

# Run each system test binary
run_test "/data/local/tmp/multi_group_binding_real_service_test" "binding_real_service"
run_test "/data/local/tmp/multi_group_api_impact_test" "api_impact"
run_test "/data/local/tmp/mouse_api_hidumper_test" "mouse_api_hidumper"
run_test "/data/local/tmp/mouse_visual_movement_test" "mouse_visual_movement"

# Final hidumper capture
log ""
log "--- Final hidumper state ---"
hidumper -s 3101 -a -G > "${EVIDENCE_DIR}/final_${TIMESTAMP}.txt" 2>&1
log "  Saved to: ${EVIDENCE_DIR}/final_${TIMESTAMP}.txt"

# Summary
log ""
log "========================================================="
log " SUMMARY"
log "========================================================="
log " Total test binaries: ${TOTAL}"
log " Passed:              ${PASS}"
log " Failed:              ${FAIL}"
log ""

# List all evidence files
log " Evidence files:"
ls -la "${EVIDENCE_DIR}"/*_${TIMESTAMP}* 2>/dev/null | while IFS= read -r line; do
    log "   ${line}"
done

log ""
if [ ${FAIL} -eq 0 ]; then
    log " OVERALL: ALL PASSED"
    log "========================================================="
    exit 0
else
    log " OVERALL: ${FAIL} FAILURE(S)"
    log "========================================================="
    exit 1
fi
