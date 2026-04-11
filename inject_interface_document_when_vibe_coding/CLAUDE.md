# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is the **multimodalinput_input** repository - OpenHarmony's Multimodal Input Subsystem. It handles input device management and event processing for HarmonyOS, supporting touchscreens, mice, keyboards, joysticks, and other input devices.

## Build System

### Build Configuration
- **Build Tool**: GN (Generate Ninja) with Ninja as the backend
- **Main Config**: `multimodalinput_mini.gni` - Contains all feature flags and build configurations
- **Build Files**: `BUILD.gn` files throughout the directory tree define targets

### Feature Flags
The build system uses feature flags to enable/disable functionality:
- `input_feature_touchscreen` - Touch screen support
- `input_feature_mouse` - Mouse support
- `input_feature_keyboard` - Keyboard support
- `input_feature_joystick` - Joystick support
- `input_feature_touchpad` - Touchpad support
- `input_feature_pen` - Stylus/pen support
- `input_feature_pointer_drawing` - Pointer drawing
- `input_feature_touch_gesture` - Touch gestures
- `input_feature_interceptor` - Event interception
- `input_feature_monitor` - Input monitoring
- `input_feature_key_hook` - Key event hooking

### Building
```bash
# Generate build configuration
gn gen out/rk3568 --args='input_feature_touchscreen=true input_feature_mouse=true'

# Build the service
ninja -C out/rk3568 multimodalinput_mmi_service

# Build specific components
ninja -C out/rk3568 libmmi-server
ninja -C out/rk3568 uinput_inject
```

## Architecture

### Core Components

#### MMIService (`service/module_loader/src/mmi_service.cpp`)
The main system service entry point:
- Inherits from `SystemAbility` and `MultimodalInputConnectStub`
- Initializes all subsystem components on startup
- Manages IPC communication with clients
- Handles service lifecycle (OnStart/OnStop)
- Coordinates device discovery, event processing, and dispatch

Key responsibilities:
- Socket-based IPC server setup (`UDSServer`)
- Event filter management
- Input device enumeration and management
- Pointer/mouse settings control
- Keyboard repeat rate configuration
- Event injection APIs
- Subscription management (keys, switches, gestures)

#### InputWindowsManager (`service/window_manager/src/input_windows_manager.cpp`)
Manages window-to-input event routing:
- Tracks focused windows and display groups
- Handles pointer coordinate transformation between displays and windows
- Manages window visibility and focus state
- Implements capture mode for pointer events
- Handles display binding (associating input devices with displays)
- Processes window hot area detection

Key data structures:
- `WindowInfo` - Window position, pid, uid, flags, type
- `DisplayGroupInfo` - Display grouping and focus tracking
- `WindowGroupInfo` - Windows grouped by display

### Service Layer Architecture

```
┌─────────────────────────────────────────────────────┐
│                   MMIService                         │
│              (SystemAbility Entry)                   │
├─────────────────────────────────────────────────────┤
│  InputWindowsManager  │  DeviceManager  │ EventHandler│
│  (Window Routing)     │  (Device Mgmt)  │ (Processing)│
├─────────────────────────────────────────────────────┤
│  Event Dispatch  │  Event Hook  │  Event Filter      │
│  (App Routing)   │ (Intercept)  │  (Filtering)       │
├─────────────────────────────────────────────────────┤
│  libinput Adapter │  uinput  │  Virtual Devices     │
│  (Hardware Abstraction)                              │
└─────────────────────────────────────────────────────┘
```

### Key Directories

- `service/` - Core service implementation
  - `module_loader/` - Service initialization and entry point
  - `window_manager/` - Window routing and display management
  - `device_manager/` - Input device lifecycle
  - `event_handler/` - Event processing pipeline
  - `event_dispatch/` - Event routing to applications
  - `event_hook/` - Event interception framework
  - `libinput_adapter/` - Hardware abstraction layer
  - `message_handle/` - IPC message handling

- `frameworks/` - API layers for different programming models
  - `napi/` - JavaScript/Node.js bindings (N-API)
  - `ets/` - ArkTS bindings for HarmonyOS apps
  - `native/` - C++ native APIs
  - `proxy/` - IPC client-side proxies

- `interfaces/native/innerkits/` - Public API definitions

- `intention/` - Higher-level input interpretation and distributed input
  - `adapters/` - Context-aware event processing
  - `services/` - Multi-device coordination

- `uinput/` - Event injection and virtual device support

- `test/` - Test utilities and mocks
  - `facility/` - Mock implementations for testing

### Event Flow

1. **Hardware Input** → libinput captures raw events
2. **libinput_adapter** → Converts to MMI events
3. **event_handler** → Normalization and transformation
4. **event_hook** → Interceptor processing
5. **event_filter** → Filter chain processing
6. **event_dispatch** + **InputWindowsManager** → Window routing
7. **Frameworks (NAPI/ETS/Native)** → Application delivery

## API Layers

### TypeScript/ArkTS Interface Layer
- **Location**: `frameworks/ets/` and `frameworks/napi/`
- **Error Codes**: Defined in `frameworks/ets/common/include/ani_common.h`
  - `201` - Permission verification failed
  - `202` - Non-system application called system API
  - `401` - Parameter error
  - `801` - Capability not supported
  - `3800001` - Input service exception
  - `3900001` - Device does not exist
  - `4100001` - Pre-key not supported
  - `4200002` - Input occupied by system
  - `4200003` - Input occupied by other

### Event Injection APIs
- **Public API**: `interfaces/native/innerkits/proxy/include/input_manager.h`
  - `SimulateInputEvent(std::shared_ptr<PointerEvent>)` - Main injection API
  - `SimulateInputEvent(std::shared_ptr<KeyEvent>)` - Key event injection
- **Server-Side**: `service/module_loader/include/mmi_service.h`
  - `InjectPointerEvent()` - Pointer event injection with authorization
  - `InjectPointerEventExt()` - Extended version with user/pid/shell checks
- **Message Handler**: `service/message_handle/src/server_msg_handler.cpp`
  - `OnInjectPointerEvent()` - Main handler for pointer injection

## Testing

### Test Organization
- Unit tests: `*/test/unittest/` or `*/test/`
- Integration tests: `frameworks/proxy/events/test/`
- Fuzz tests: `test/fuzztest/`
- Mock facilities: `test/facility/`

### Test Execution
```bash
# Build all tests
ninja -C out/rk3568 mmi_tests

# Run specific test suite
ninja -C out/rk3568 InputManagerTest
ninja -C out/rk3568 DeviceManagerTest
```

### Key Test Components
- `InputManagerTest` - Core input management
- `DeviceManagerTest` - Device lifecycle
- `EventDispatchTest` - Event routing
- `KeyEventHookTest` - Key interception

## Development Notes

### Thread Model
- Main service thread: Event processing and dispatch
- Separate threads for device monitoring
- IPC threads for client communication
- FFRT (Foundation Function Runtime Task) for async operations

### Configuration Files
- `/etc/multimodalinput.cfg` - Main configuration
- `/etc/joystick/` - Joystick mappings
- `/data/service/el1/public/multimodalinput/display_bind.cfg` - Display binding

### Event Types
- **KeyEvent** - Keyboard and button events
- **PointerEvent** - Touch, mouse, stylus events
- **AxisEvent** - Continuous axis events (joysticks)
- **TouchEvent** - Multi-touch specific events

### Important Concepts

**Window ID and PID/UID**: Events are routed based on window ID, which maps to application PID/UID for permission checks.

**Display Groups**: Multiple displays can be grouped together, with each group having its own focus window and pointer state.

**Agent Windows**: Special windows (e.g., screenshot, voice input) that may intercept input events.

**Pointer Capture Mode**: When enabled, pointer events are locked to a specific window regardless of pointer position.

**Hot Areas**: Screen edge detection for window switching and special behaviors.

### Coding Conventions
- **Namespace**: `OHOS::MMI`
- **Logging**: `MMI_HILOG*` macros with tags (e.g., `MMI_HILOGE`, `MMI_HILOGD`)
- **Error Handling**: Return codes (`RET_OK`, `RET_ERR`)
- **Memory**: Smart pointers (`std::shared_ptr`, `std::unique_ptr`)
- **Thread Safety**: Mutexes for shared state
- **No-Copy Classes**: `DISALLOW_COPY_AND_MOVE` macro
- **Naming**:
  - CamelCase for classes
  - snake_case for variables and functions
  - UPPER_SNAKE_CASE for constants
- **Comments**: English documentation with copyright headers

### Mouse Event Data Structures

**PointerEvent** (`interfaces/native/innerkits/event/include/pointer_event.h`):
- Action types: `POINTER_ACTION_BUTTON_DOWN`, `POINTER_ACTION_BUTTON_UP`, `POINTER_ACTION_MOVE`, `POINTER_ACTION_AXIS_BEGIN/UPDATE/END`
- Source type: `SOURCE_TYPE_MOUSE`
- Tool type: `TOOL_TYPE_MOUSE`
- Button identifiers: `MOUSE_BUTTON_LEFT/RIGHT/MIDDLE`
- Coordinates: displayX, displayY
- Additional properties: pressure, tilt, etc.

### Virtual Device Implementation

**uinput** (`uinput/virtual_device.h/cpp`):
- Opens `/dev/uinput` device
- Configures device capabilities via ioctl
- Creates virtual devices with `UI_DEV_CREATE`
- Emits events via `write()` with `input_event` structure

**Virtual Mouse** (`tools/vuinput/include/virtual_mouse.h`):
- Device name: "Virtual Mouse"
- Supported events: EV_KEY, EV_REL, EV_MSC
- Keys: BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, etc.
- Relative axes: REL_X, REL_Y, REL_WHEEL

## Related Documentation

- `README.md` - Basic module overview
- `interface.md` - New interface definitions (if present)
