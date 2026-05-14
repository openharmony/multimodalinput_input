# Cockpit Product Type Implementation Plan

## Overview

Add "cockpit" (座舱) as a new product type to multimodalinput_input that disables 6 specific features while keeping other input capabilities functional.

## Current Feature Status Analysis

### ✅ Features with Complete Conditional Compilation (4 features)

1. **anco** - `input_ext_feature_anco`
   - Defined: `multimodalinput_mini.gni:49`, default: `false`
   - Conditional compilation: ✅ `multimodalinput_mini.gni:450-471`
   - Status: **Complete** (external vendor dependency)

2. **虚拟键盘** (Virtual Keyboard) - `input_feature_virtual_keyboard`
   - Defined: `multimodalinput_mini.gni:55`, default: `false`
   - Conditional compilation: ✅ `multimodalinput_mini.gni:544-546`
   - Status: **Complete**

3. **触控笔** (Touch Pen/Stylus) - `input_feature_pen`
   - Defined: `multimodalinput_mini.gni:71`, default: `true`
   - Conditional compilation: ✅ `service/BUILD.gn:369`, `596`
   - Status: **Complete**

4. **全景多窗手势** (Panoramic Multi-window Gestures) - `input_feature_triple_finger_snapshot`
   - Defined: `multimodalinput_mini.gni:74`, default: `false`
   - Conditional compilation: ✅ `service/BUILD.gn:145`, `464`, `etc/BUILD.gn:59`
   - Status: **Complete**

### ⚠️ Features with Incomplete Conditional Compilation (2 features)

5. **旋转表冠** (Rotating Crown) - `input_feature_crown`
   - Defined: `multimodalinput_mini.gni:51`, default: `false`
   - **PROBLEM**: `service/BUILD.gn:420` compiles under `if (input_feature_mouse)`, NOT `if (input_feature_crown)`
   - **MISSING**: Needs independent `if (input_feature_crown)` conditional
   - Virtual device: `virtual_crown.cpp` exists but not conditionally controlled

6. **指纹键的手势** (Fingerprint Key Gestures) - `input_feature_fingerprint`
   - Defined: `multimodalinput_mini.gni:50`, default: `false`
   - **PROBLEM**: Virtual device sources `virtual_fingerprint_key.cpp`, `virtual_fingerprint_mouse.cpp` NOT conditionally compiled
   - **MISSING**: Need to move these files under `if (input_feature_fingerprint)` condition
   - Service layer: Only virtual device implementation, no service integration

## Implementation Phases

### Phase 1: Fix Incomplete Conditional Compilation (Current Task)

**Goal**: Ensure crown and fingerprint features have proper conditional compilation before adding cockpit logic.

#### Step 1.1: Fix Crown Conditional Compilation in service/BUILD.gn

**Problem**: Crown source is compiled under `if (input_feature_mouse)` instead of `if (input_feature_crown)`.

**File**: `service/BUILD.gn`

**Change 1** (line 87 - include_dirs):
```gni
# Current (WRONG):
include_dirs += [ "crown_transform_processor/include" ]

# Change to:
if (input_feature_crown) {
  include_dirs += [ "crown_transform_processor/include" ]
}
```

**Change 2** (line 416-422 - sources):
```gni
# Current (WRONG):
if (input_feature_mouse || input_feature_touchscreen) {
  sources += [ "touch_event_normalize/src/touch_event_normalize.cpp" ]
  if (input_feature_mouse) {
    sources += [
      "crown_transform_processor/src/crown_transform_processor.cpp",
    ]
  }
  ...
}

# Change to:
if (input_feature_mouse || input_feature_touchscreen) {
  sources += [ "touch_event_normalize/src/touch_event_normalize.cpp" ]
  if (input_feature_mouse) {
    # Remove crown from here
  }
  ...
}

# Add independent condition:
if (input_feature_crown) {
  sources += [
    "crown_transform_processor/src/crown_transform_processor.cpp",
  ]
}
```

#### Step 1.2: Make Virtual Device Sources Conditional

**Problem**: Crown, fingerprint and pen virtual device sources are not conditionally compiled.

**File**: `multimodalinput_mini.gni`
**Location**: Lines 277-310 (libmmi_virtual_device_sources array)

**Current state** (lines 277-310):
```gni
libmmi_virtual_device_sources = [
  "src/virtual_crown.cpp",                    # ❌ Not conditional
  "src/virtual_device.cpp",
  "src/virtual_finger.cpp",
  "src/virtual_fingerprint_key.cpp",          # ❌ Not conditional
  "src/virtual_fingerprint_mouse.cpp",        # ❌ Not conditional
  "src/virtual_gamepad.cpp",
  "src/virtual_joystick.cpp",
  "src/virtual_keyboard.cpp",
  # ... more files ...
  "src/virtual_pen.cpp",                      # ❌ Not conditional
  "src/virtual_pen_keyboard.cpp",             # ❌ Not conditional
  "src/virtual_pen_mouse.cpp",                # ❌ Not conditional
  # ... more files ...
]
```

**Change to**:
```gni
libmmi_virtual_device_sources = [
  "src/virtual_device.cpp",
  "src/virtual_finger.cpp",
  "src/virtual_gamepad.cpp",
  "src/virtual_joystick.cpp",
  "src/virtual_keyboard.cpp",
  "src/virtual_keyboard_consumer_ctrl.cpp",
  "src/virtual_keyboard_ext.cpp",
  "src/virtual_keyboard_sys_ctrl.cpp",
  "src/virtual_knob.cpp",
  "src/virtual_knob_consumer_ctrl.cpp",
  "src/virtual_knob_mouse.cpp",
  "src/virtual_knob_sys_ctrl.cpp",
  "src/virtual_mouse.cpp",
  "src/virtual_pc_switch.cpp",
  "src/virtual_pc_touchpad.cpp",
  "src/virtual_remote_control.cpp",
  "src/virtual_single_finger.cpp",
  "src/virtual_single_touchscreen.cpp",
  "src/virtual_stylus.cpp",
  "src/virtual_touchpad.cpp",
  "src/virtual_touchscreen.cpp",
  "src/virtual_trackball.cpp",
  "src/virtual_trackpad.cpp",
  "src/virtual_trackpad_mouse.cpp",
  "src/virtual_trackpad_sys_ctrl.cpp",
  "src/virtual_uwb_remote_control.cpp",
]

# Add feature-specific devices conditionally
if (input_feature_crown) {
  libmmi_virtual_device_sources += [ "src/virtual_crown.cpp" ]
}

if (input_feature_fingerprint) {
  libmmi_virtual_device_sources += [
    "src/virtual_fingerprint_key.cpp",
    "src/virtual_fingerprint_mouse.cpp",
  ]
}

if (input_feature_pen) {
  libmmi_virtual_device_sources += [
    "src/virtual_pen.cpp",
    "src/virtual_pen_keyboard.cpp",
    "src/virtual_pen_mouse.cpp",
  ]
}
```

#### Step 1.3: Update Test BUILD.gn for Crown

**File**: `service/crown_transform_processor/test/BUILD.gn`

**Add conditional wrapper** around test targets:
```gni
if (input_feature_crown) {
  ohos_unittest("CrownTransformProcessorTest") {
    # ... existing test configuration
  }

  ohos_unittest("CrownTransformProcessorExTest") {
    # ... existing test configuration
  }
}
```

### Phase 2: Add Cockpit Product Type

#### Step 2.1: Add Cockpit Configuration in multimodalinput_mini.gni

**File**: `multimodalinput_mini.gni`
**Location**: After line 487 (after "watch" product type check)

**Add**:
```gni
if (input_feature_product == "cockpit") {
  # Disable features not needed for cockpit product
  input_feature_crown = false
  input_ext_feature_anco = false
  input_feature_fingerprint = false
  input_feature_virtual_keyboard = false
  input_feature_pen = false
  input_feature_triple_finger_snapshot = false

  # Add cockpit-specific define
  input_default_defines += [ "OHOS_BUILD_ENABLE_COCKPIT" ]
}
```

#### Step 2.2: Update Test References

**File**: `BUILD.gn` (root)

Ensure test references to crown tests are conditionally compiled (already exists at line 278):
```gni
if (input_feature_crown) {
  "service/crown_transform_processor/test:CrownTransformProcessorTest",
}
```

## Summary of Changes

### Phase 1 - Fix Conditional Compilation (3 files)
1. `service/BUILD.gn` - Fix crown conditional (2 changes: line 87, line 416-422)
2. `multimodalinput_mini.gni` - Make virtual device sources conditional (lines 277-310)
3. `service/crown_transform_processor/test/BUILD.gn` - Wrap tests in conditional

### Phase 2 - Add Cockpit Product Type (1 file)
4. `multimodalinput_mini.gni` - Add cockpit configuration (after line 487)

## Order of Implementation

**Current task**: Phase 1 (Steps 1.1 - 1.3)
- Ensures all 6 features have proper conditional compilation
- Must be completed BEFORE adding cockpit logic
- This is the "先把已有feature的部分处理" step

**Next task**: Phase 2 (Step 2.1 - 2.2)
- Add cockpit product type configuration
- Relies on Phase 1 being complete

## Verification

### Build Test
```bash
# Generate cockpit build
gn gen out/cockpit --args='input_feature_product=cockpit'

# Build service
ninja -C out/cockpit multimodalinput_mmi_service

# Verify disabled features are absent
nm out/cockpit/libmmi-server.z.so | grep -i crown    # Should return nothing
nm out/cockpit/libmmi-server.z.so | grep -i anco     # Should return nothing
nm out/cockpit/libmmi-server.z.so | grep -i fingerprint  # Should return nothing

# Verify enabled features are present
nm out/cockpit/libmmi-server.z.so | grep -i joystick  # Should show symbols
nm out/cockpit/libmmi-server.z.so | grep -i touchpad  # Should show symbols
```

### Functional Test Checklist

- [ ] Mouse input works
- [ ] Touchpad gestures work
- [ ] Touchscreen input works
- [ ] Keyboard input works
- [ ] Joystick/gamepad works
- [ ] Distributed input (云水桥) works
- [ ] Crown APIs return appropriate errors
- [ ] Virtual keyboard creation fails gracefully
- [ ] Stylus input handled as generic touch

## Critical Files

1. `multimodalinput_mini.gni` - Add cockpit product type logic (after line 487)
2. `service/BUILD.gn` - Add conditional compilation for crown sources (lines 87, 416-422)
3. `multimodalinput_mini.gni` - Make virtual device sources conditional (lines 277-310)
4. `service/crown_transform_processor/test/BUILD.gn` - Wrap tests in conditional

## Notes

- **anco**: External vendor dependency, feature flag already guards all references. No action needed beyond setting flag to false.
- **fingerprint**: Only virtual device implementation exists. No service integration needed.
- **virtual_keyboard, pen, triple_finger_snapshot**: Already have proper conditional compilation in BUILD.gn files
- **IPC interface**: IDL already has proper `[macrodef OHOS_BUILD_ENABLE_VKEYBOARD]` guards
- **Framework layers**: Already conditionally depend on anco via `if (input_ext_feature_anco)`
- **No new feature flags needed** - reuse existing ones
- **Primary work**: Add conditional compilation for crown sources and make virtual device sources conditional
