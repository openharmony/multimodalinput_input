/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup input
 * @{
 *
 * @brief Provides the C interface in the multi-modal input domain.
 *
 * @since 12
 */

/**
 * @file oh_input_manager.h
 *
 * @brief Provides functions such as input event injection, key state query, device hot swapping listener, event
 * interception, hotkey management, mouse cursor management, input device information query, and injection permission
 * management.
 *
 * @kit InputKit
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library liboh_input.so
 * @since 12
 */

#ifndef OH_INPUT_MANAGER_H
#define OH_INPUT_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

#include "oh_axis_type.h"
#include "oh_key_code.h"
#include "oh_pointer_style.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_PixelmapNative;
/**
 * @brief Defines the PixelMap, used to represent and manipulate pixel image data, supporting operations such as image
 * creation, reading, modification, and rendering.
 *
 * @since 22
 */
typedef struct OH_PixelmapNative OH_PixelmapNative;

/**
 * @brief Provides the enum values of the key status.
 *
 * @since 12
 */
typedef enum Input_KeyStateAction {
    /**
     * Default state.
     */
    KEY_DEFAULT = -1,
    /**
     * Key press.
     */
    KEY_PRESSED = 0,
    /**
     * Key release.
     */
    KEY_RELEASED = 1,
    /**
     * Key switch enabled.
     */
    KEY_SWITCH_ON = 2,
    /**
     * Key switch disabled.
     */
    KEY_SWITCH_OFF = 3
} Input_KeyStateAction;

/**
 * @brief Provides the enum values of the key event type.
 *
 * @since 12
 */
typedef enum Input_KeyEventAction {
    /**
     * Button action canceled.
     */
    KEY_ACTION_CANCEL = 0,
    /**
     * Key press.
     */
    KEY_ACTION_DOWN = 1,
    /**
     * Key release.
     */
    KEY_ACTION_UP = 2,
} Input_KeyEventAction;

/**
 * @brief Provides the enum values of mouse actions.
 *
 * @since 12
 */
typedef enum Input_MouseEventAction {
    /**
     * Cancellation of the mouse action.
     */
    MOUSE_ACTION_CANCEL = 0,
    /**
     * Moving of the mouse pointer.
     */
    MOUSE_ACTION_MOVE = 1,
    /**
     * Pressing of the mouse button.
     */
    MOUSE_ACTION_BUTTON_DOWN = 2,
    /**
     * Release of the mouse button.
     */
    MOUSE_ACTION_BUTTON_UP = 3,
    /**
     * Beginning of the mouse axis event.
     */
    MOUSE_ACTION_AXIS_BEGIN = 4,
    /**
     * Updating of the mouse axis event.
     */
    MOUSE_ACTION_AXIS_UPDATE = 5,
    /**
     * End of the mouse axis event.
     */
    MOUSE_ACTION_AXIS_END = 6,
} Input_MouseEventAction;

/**
 * @brief Provides the enum values of mouse axis event types.
 *
 * @since 12
 */
typedef enum InputEvent_MouseAxis {
    /**
     * Vertical scroll axis.
     */
    MOUSE_AXIS_SCROLL_VERTICAL = 0,
    /**
     * Horizontal scroll axis.
     */
    MOUSE_AXIS_SCROLL_HORIZONTAL = 1,
} InputEvent_MouseAxis;

/**
 * @brief Provides the enum values of mouse buttons.
 *
 * @since 12
 */
typedef enum Input_MouseEventButton {
    /**
     * Invalid button.
     */
    MOUSE_BUTTON_NONE = -1,
    /**
     * Left button.
     */
    MOUSE_BUTTON_LEFT = 0,
    /**
     * Middle button.
     */
    MOUSE_BUTTON_MIDDLE = 1,
    /**
     * Right button.
     */
    MOUSE_BUTTON_RIGHT = 2,
    /**
     * Forward button.
     */
    MOUSE_BUTTON_FORWARD = 3,
    /**
     * Back button.
     */
    MOUSE_BUTTON_BACK = 4,
} Input_MouseEventButton;

/**
 * @brief Provides the enum values of touch actions.
 *
 * @since 12
 */
typedef enum Input_TouchEventAction {
    /**
     * Touch cancellation.
     */
    TOUCH_ACTION_CANCEL = 0,
    /**
     * Touch press.
     */
    TOUCH_ACTION_DOWN = 1,
    /**
     * Touch moving.
     */
    TOUCH_ACTION_MOVE = 2,
    /**
     * Touch release.
     */
    TOUCH_ACTION_UP = 3,
} Input_TouchEventAction;

/**
 * @brief Provides the enum values of event source types.
 *
 * @since 12
 */
typedef enum InputEvent_SourceType {
    /**
     * Source that generates events similar to mouse pointer movement, button press and release, and wheel scrolling.
     * @since 12
     */
    SOURCE_TYPE_MOUSE = 1,
    /**
     * Source that generates a touchscreen multi-touch event.
     * @since 12
     */
    SOURCE_TYPE_TOUCHSCREEN = 2,
    /**
     * Source that generates a touchpad multi-touch event.
     * @since 12
     */
    SOURCE_TYPE_TOUCHPAD = 3
} InputEvent_SourceType;

/**
 * @brief Provides the enum values of keyboard types of the input device.
 *
 * @since 13
 */
typedef enum Input_KeyboardType {
    /**
     * Keyboard without keys.
     */
    KEYBOARD_TYPE_NONE = 0,
    /**
     * Keyboard with unknown keys.
     */
    KEYBOARD_TYPE_UNKNOWN = 1,
    /**
     * Full keyboard.
     */
    KEYBOARD_TYPE_ALPHABETIC = 2,
    /**
     * Numeric keypad.
     */
    KEYBOARD_TYPE_DIGITAL = 3,
    /**
     * Stylus.
     */
    KEYBOARD_TYPE_STYLUS = 4,
    /**
     * Remote control.
     */
    KEYBOARD_TYPE_REMOTE_CONTROL = 5,
} Input_KeyboardType;

/**
 * @brief Defines key information, which identifies a key pressing behavior.
 * For example, the Ctrl key information contains the key value and key type.
 *
 * @since 12
 */
typedef struct Input_KeyState Input_KeyState;

/**
 * @brief The key event to be injected.
 *
 * @since 12
 */
typedef struct Input_KeyEvent Input_KeyEvent;

/**
 * @brief Defines the mouse event object, which is used to represent input events generated by user mouse operations,
 * including click information, coordinates, and click action events. It can be used to process mouse event input and
 * implement mouse event response.
 *
 * @since 12
 */
typedef struct Input_MouseEvent Input_MouseEvent;

/**
 * @brief Defines the touchscreen input event object, which is used to represent detailed information about touchscreen
 * input, including the touch point position, touch state, and timestamp.
 *
 * @since 12
 */
typedef struct Input_TouchEvent Input_TouchEvent;

/**
 * @brief Defines an axis event object, which is used to represent axis event data from an input device, such as
 * joystick movement on a gamepad and mouse wheel scrolling. You can obtain axis value changes from the input device
 * through axis events to implement precise input control and enhance user interaction experience.
 *
 * @since 12
 */
typedef struct Input_AxisEvent Input_AxisEvent;

/**
 * @brief Defines mouse cursor information. It is used to manage and control the display behavior and appearance
 * properties of the mouse cursor in the input system, including cursor display state, cursor style, cursor size level,
 * and cursor color.
 *
 * @since 22
 */
typedef struct Input_CursorInfo Input_CursorInfo;

/**
 * @brief Provides return value enumerations.
 *
 * @since 12
 */
typedef enum Input_Result {
    /**
     * Operation succeeded.
     */
    INPUT_SUCCESS = 0,
    /**
     * Permission verification failed.
     */
    INPUT_PERMISSION_DENIED = 201,
    /**
     * Non-system application.
     */
    INPUT_NOT_SYSTEM_APPLICATION = 202,
    /**
     * Parameter check fails.
     */
    INPUT_PARAMETER_ERROR = 401,
    /**
     * Function not supported.
     */
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    /**
     * Service error.
     */
    INPUT_SERVICE_EXCEPTION = 3800001,
    /** No product config of specific parameter */
    INPUT_NO_PRODUCT_CONFIG = 3800002,
    /**
     * Interceptor repeatedly created.
     */
    INPUT_REPEAT_INTERCEPTOR = 4200001,
    /**
     * Input device occupied by a system application.
     * @since 14
     */
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    /**
     * Input device occupied by another application.
     * @since 14
     */
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    /**
     * Keyboard not connected.
     * @since 15
     */
    INPUT_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    /**
     * Authorization in progress.
     * @since 20
     */
    INPUT_INJECTION_AUTHORIZING = 3900005,
    /**
     * Repeated request.
     * @since 20
     */
    INPUT_INJECTION_OPERATION_FREQUENT = 3900006,
    /**
     * Permission granted to the current application.
     * @since 20
     */
    INPUT_INJECTION_AUTHORIZED = 3900007,
    /**
     * Permission granted to other applications.
     * @since 20
     */
    INPUT_INJECTION_AUTHORIZED_OTHERS = 3900008,
    /**
     * Application not in focus.
     * @since 20
     */
    INPUT_APP_NOT_FOCUSED = 3900009,
    /**
     * No mouse device.
     * @since 20
     */
    INPUT_DEVICE_NO_POINTER = 3900010,
    /**
     * Invalid window ID.
     * @since 22
     */
    INPUT_INVALID_WINDOWID = 26500001
} Input_Result;

/**
 * @brief Provides the enum values of injection permission states.
 *
 * @since 20
 */
typedef enum Input_InjectionStatus {
    /**
     * Permission not granted.
     */
    UNAUTHORIZED = 0,
    /**
     * Permission being granted.
     */
    AUTHORIZING = 1,
    /**
     * Permission granted.
     */
    AUTHORIZED = 2,
} Input_InjectionStatus;

/**
 * @brief Enumerates touch tool types of an input device.
 *
 * @since 24
 */
typedef enum Input_TouchEventToolType {
    /**
     * Finger
     * @since 24
     */
    TOOL_TYPE_FINGER = 0,

    /**
     * Pen
     * @since 24
     */
    TOOL_TYPE_PEN = 1,

    /**
     * Rubber
     * @since 24
     */
    TOOL_TYPE_RUBBER = 2,

    /**
     * Brush
     * @since 24
     */
    TOOL_TYPE_BRUSH = 3,

    /**
     * Pencil
     * @since 24
     */
    TOOL_TYPE_PENCIL = 4,

    /**
     * Air brush
     * @since 24
     */
    TOOL_TYPE_AIRBRUSH = 5,

    /**
     * Mouse
     * @since 24
     */
    TOOL_TYPE_MOUSE = 6,

    /**
     * lens
     * @since 24
     */
    TOOL_TYPE_LENS = 7,
} Input_TouchEventToolType;

/**
 * @brief Defines the hotkey struct, which describes the hotkey design logic such as the key combination, trigger
 * conditions, and callback handling. Applications can register and manage custom hotkeys.
 *
 * @since 14
 */
typedef struct Input_Hotkey Input_Hotkey;

/**
 * @brief Defines a lifecycle callback for **keyEvent**. If the callback is triggered, **keyEvent** will be destroyed.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @since 12
 */
typedef void (*Input_KeyEventCallback)(const Input_KeyEvent* keyEvent);

/**
 * @brief Defines a lifecycle callback for **mouseEvent**. If the callback is triggered, **mouseEvent** will be
 * destroyed.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @since 12
 */
typedef void (*Input_MouseEventCallback)(const Input_MouseEvent* mouseEvent);

/**
 * @brief Defines the lifecycle callback for **TouchEvent**. If the callback is triggered, **TouchEvent** will be
 * destroyed.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @since 12
 */
typedef void (*Input_TouchEventCallback)(const Input_TouchEvent* touchEvent);

/**
 * @brief Defines a lifecycle callback for **axisEvent**. If the callback is triggered, **axisEvent** will be destroyed.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @since 12
 */
typedef void (*Input_AxisEventCallback)(const Input_AxisEvent* axisEvent);

typedef void (*Input_HotkeyCallback)(Input_Hotkey* hotkey);

/**
 * @brief Callback used to receive input device hot-plug events.
 *
 * @param deviceId Unique ID of the input device. If a physical device is repeatedly reinstalled or restarted, its ID
 *     may change.
 * @since 13
 */
typedef void (*Input_DeviceAddedCallback)(int32_t deviceId);

/**
 * @brief Callback used to receive input device hot-unplug events.
 *
 * @param deviceId Unique ID of the input device. If a physical device is repeatedly reinstalled or restarted, its ID
 *     may change.
 * @since 13
 */
typedef void (*Input_DeviceRemovedCallback)(int32_t deviceId);

/**
 * @brief Defines a callback used to receive the injection permission authorization status.
 *
 * @param authorizedStatus Injection permission authorization status.
 * @since 20
 */
typedef void (*Input_InjectAuthorizeCallback)(Input_InjectionStatus authorizedStatus);

/**
 * @brief Defines the structure for the interceptor of event callbacks,
 * including mouseCallback, touchCallback, and axisCallback.
 * @since 12
 */
typedef struct Input_InterceptorEventCallback {
    /** Defines a lifecycle callback for **mouseEvent**. */
    Input_MouseEventCallback mouseCallback;
    /** Defines a lifecycle callback for **touchEvent**. */
    Input_TouchEventCallback touchCallback;
    /** Defines a lifecycle callback for **axisEvent**. */
    Input_AxisEventCallback axisCallback;
} Input_InterceptorEventCallback;

/**
 * @brief Defines the struct for listening for device hot swapping. It is applicable to applications that need to
 * respond to input device connection and disconnection in real time, such as games and music players. By listening for
 * device hot swapping events, applications can update the input status in a timely manner, improving user experience
 * and avoiding exceptions caused by device disconnection.
 *
 * @since 13
 */
typedef struct Input_DeviceListener {
    /**
     * Defines a callback used to receive device hot-plug events.
     */
    Input_DeviceAddedCallback deviceAddedCallback;
    /**
     * Defines a callback used to receive device hot-unplug events.
     */
    Input_DeviceRemovedCallback deviceRemovedCallback;
} Input_DeviceListener;

/**
 * @brief Defines event interceptor options.
 * @since 12
 */
typedef struct Input_InterceptorOptions Input_InterceptorOptions;

/**
 * @brief Defines input device information, which is used to describe the basic information and capability
 * characteristics of an input device, including attributes such as the device type and device ID. You can use this
 * struct to obtain and manage detailed information about input devices, facilitating device identification and
 * configuration management.
 *
 * @since 13
 */
typedef struct Input_DeviceInfo Input_DeviceInfo;

/**
 * @brief Defines the pixel map resource of the custom mouse pointer object.
 *
 * @since 22
 */
typedef struct Input_CustomCursor Input_CustomCursor;

/**
 * @brief Defines custom mouse cursor configuration, which is used to define and manage the display style and
 * interaction behavior of the mouse cursor in an application. It supports different cursor styles (such as default,
 * hand, and text input), providing users with more intuitive operation feedback and enhancing user experience.
 *
 * @since 22
 */
typedef struct Input_CursorConfig Input_CursorConfig;

/**
 * @brief Queries a key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @return If the operation is successful, {@link INPUT_SUCCESS} is returned; if parameter verification fails,
 *     {@link INPUT_PARAMETER_ERROR} is returned.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState);

/**
 * @brief Creates a key status enum object. You can call {@link OH_Input_DestroyKeyState()} to destroy a key status
 * enum object.
 *
 * @return If the operations is successful, {@link Input_KeyState} is returned. Otherwise, a null pointer is returned.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_KeyState* OH_Input_CreateKeyState();

/**
 * @brief Destroys a key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyKeyState(struct Input_KeyState** keyState);

/**
 * @brief Sets the key value of a key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @param keyCode Key code. For details, see {@link KeyCode}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyCode(struct Input_KeyState* keyState, int32_t keyCode);

/**
 * @brief Obtains the key value of a key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @return Key value of the key status enum object. For details, see {@link Input_KeyStateAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyCode(const struct Input_KeyState* keyState);

/**
 * @brief Sets whether the key specific to a key status enum object is pressed.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @param keyAction Whether a key is pressed. For details, see {@link Input_KeyEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyPressed(struct Input_KeyState* keyState, int32_t keyAction);

/**
 * @brief Checks whether the key specific to a key status enum object is pressed.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @return Key pressing status of the key status enum object. For details, see {@link Input_KeyStateAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyPressed(const struct Input_KeyState* keyState);

/**
 * @brief Sets the key switch of the key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @param keySwitch Key switch.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeySwitch(struct Input_KeyState* keyState, int32_t keySwitch);

/**
 * @brief Obtains the key switch of the key status enum object.
 *
 * @param keyState Key status enum object. For details, see {@link Input_KeyStateAction}.
 * @return Key switch of the key status enum object. For details, see {@link Input_KeyStateAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeySwitch(const struct Input_KeyState* keyState);

/**
 * @brief Injects a key event.
 * <br>This API does not take effect if the user has not granted authorization and the caller does not have the ohos.
 * permission.CONTROL_DEVICE permission.
 * <br>Since API version 20, you are advised to use {@link OH_Input_RequestInjection()} to request the required
 * permission before calling this API. If the status returned by {@link OH_Input_QueryAuthorizedStatus()} is
 * {@link AUTHORIZED}, then you can call this API.
 * <br>Since API version 22, if the key press event (**KEY_ACTION_DOWN**) of a modifier key (**KEYCODE_META_LEFT**, **
 * KEYCODE_META_RIGHT**, **KEYCODE_CTRL_LEFT**, **KEYCODE_CTRL_RIGHT**, **KEYCODE_ALT_LEFT**, **KEYCODE_ALT_RIGHT**, **
 * KEYCODE_SHIFT_LEFT**, **KEYCODE_SHIFT_RIGHT**, **KEYCODE_CAPS_LOCK**, **KEYCODE_SCROLL_LOCK**, or **KEYCODE_NUM_LOCK*
 * *) is injected, the release event (**KEY_ACTION_UP**) of the key needs to be injected in a timely manner to avoid
 * the key being pressed for a long time.
 * <br>Since API version 26.0.0, callers that have the ohos.permission.CONTROL_DEVICE permission can use this API
 * directly.
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}. You can call
 *     {@link OH_Input_SetKeyEventKeyCode()} and {@link OH_Input_SetKeyEventAction()} to set the key value and key
 *     event type of the key event object.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Return value of the **OH_Input_InjectKeyEvent** function.
 *     <br>- {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>- {@link INPUT_PERMISSION_DENIED} if the required permission is missing;
 *     <br>- {@link INPUT_PARAMETER_ERROR} if the input parameter is incorrect.
 * @since 12
 */
int32_t OH_Input_InjectKeyEvent(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Creates a key event object. You can call {@link OH_Input_DestroyKeyEvent()} to destroy a key event object.
 *
 * @return {@link Input_KeyEvent} pointer object if the operation is successful; a null pointer otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_KeyEvent* OH_Input_CreateKeyEvent();

/**
 * @brief Destroys a key event object.
 *
 * @param keyEvent Key event object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyKeyEvent(struct Input_KeyEvent** keyEvent);

/**
 * @brief Sets the key event type.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param action Key event type. For details, see {@link Input_KeyEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventAction(struct Input_KeyEvent* keyEvent, int32_t action);

/**
 * @brief Obtains the key event action.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Key event type. For details, see {@link Input_KeyEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyEventAction(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the key code value for a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param keyCode Key value. For details, see {@link KeyCode}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventKeyCode(struct Input_KeyEvent* keyEvent, int32_t keyCode);

/**
 * @brief Obtains the key code value of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Key code of a key event. For details, see {@link Input_KeyCode}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyEventKeyCode(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the time when a key event occurs.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param actionTime Time when the key event occurred, representing the number of microseconds elapsed since system
 *     startup, in microseconds (μs).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventActionTime(struct Input_KeyEvent* keyEvent, int64_t actionTime);

/**
 * @brief Obtains the time when a key event occurs.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Returns the time when the key event occurred, representing the number of microseconds elapsed since system
 *     startup, in microseconds (μs).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetKeyEventActionTime(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the window ID of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param windowId Window ID of the key event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetKeyEventWindowId(struct Input_KeyEvent* keyEvent, int32_t windowId);

/**
 * @brief Obtains the window ID of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Window ID of the key event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetKeyEventWindowId(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the screen ID of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param displayId Screen ID of the key event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetKeyEventDisplayId(struct Input_KeyEvent* keyEvent, int32_t displayId);

/**
 * @brief Obtains the screen ID of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @return Screen ID of the key event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetKeyEventDisplayId(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Obtains the ID of a key event.
 *
 * @param keyEvent **KeyEvent** object, which can be created through {@link OH_Input_CreateKeyEvent()}.
 *     <br>If the key event object is no longer needed, destroy it by calling {@link OH_Input_DestroyKeyEvent()}.
 * @param eventId ID of the key event.
 * @return Return value of the **OH_Input_GetKeyEventId** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 21
 */

Input_Result OH_Input_GetKeyEventId(const struct Input_KeyEvent* keyEvent, int32_t* eventId);

/**
 * @brief Adds a hook function for key event interception.
 * <br>You can call {@link OH_Input_RemoveKeyEventHook()} to remove a hook function that has been added. Multiple hook
 * functions can be set for an application, but only one hook function can be set for a process. The most recently
 * added hook function has a higher priority.
 *
 * @permission ohos.permission.HOOK_KEY_EVENT
 * @param callback Hook function, which is used to intercept all key events to be distributed.
 * @return Return value of the **OH_Input_AddKeyEventHook** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_DEVICE_NOT_SUPPORTED} if the function is not supported.
 *     <br>{@link INPUT_PERMISSION_DENIED} if the permission verification fails;
 *     <br>{@link INPUT_REPEAT_INTERCEPTOR} if the hook function is set repeatedly (only one hook function can be set
 *     for a process);
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 21
 */
Input_Result OH_Input_AddKeyEventHook(Input_KeyEventCallback callback);

/**
 * @brief Removes the hook function for key event interception.
 * <br>This API is usually used together with {@link OH_Input_AddKeyEventHook()}.
 *
 * @param callback Hook function, which is used to intercept all key events to be distributed.
 * @return Return value of the **OH_Input_RemoveKeyEventHook** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful; (if a hook is not added, a success message is also
 *     returned when the hook is removed);
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 21
 */
Input_Result OH_Input_RemoveKeyEventHook(Input_KeyEventCallback callback);

/**
 * @brief Redispatches key events.
 * <br>Only key events intercepted by the hook function can be redispatched, and these events must maintain the
 * original priority sequence.
 * <br>After this API is called, key events will be redispatched within 3 seconds. If the redispatch is not completed
 * within 3 seconds, {@link INPUT_PARAMETER_ERROR} is reported.
 * <br>Successful redispatch requires correct mapping of events. If one or more {@link KEY_ACTION_DOWN} events are
 * redispatched, the {@link KEY_ACTION_UP} or {@link KEY_ACTION_CANCEL} event can be redispatched.
 * <br>If only the {@link KEY_ACTION_UP} or {@link KEY_ACTION_CANCEL} key events are redispatched, the API call is
 * successful, but the dispatch is not actually performed.
 * <br>If the redispatched event is not intercepted by the hook function, the API call is successful, but the dispatch
 * is not actually performed.
 *
 * @param eventId ID of the key event, which can be obtained through {@link OH_Input_GetKeyEventId()}.
 * @return Return value of the **OH_Input_DispatchToNextHandler** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails; (you can call
 *     {@link OH_Input_GetKeyEventId()} to check whether the input eventId is correct);
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 21
 */
Input_Result OH_Input_DispatchToNextHandler(int32_t eventId);

/**
 * @brief Injects a mouse event by using coordinates in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 * <br>This API does not take effect if the user has not granted authorization and the caller does not have the ohos.
 * permission.CONTROL_DEVICE permission.
 * <br>Since API version 20, you are advised to use {@link OH_Input_RequestInjection()} to request the required
 * permission before calling this API. If the status returned by {@link OH_Input_QueryAuthorizedStatus()} is
 * {@link AUTHORIZED}, then you can call this API.
 * <br>Since API version 26.0.0, callers that have the ohos.permission.CONTROL_DEVICE permission can use this API
 * directly.
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Return value of the **OH_Input_InjectMouseEvent** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect;
 *     <br>{@link INPUT_PERMISSION_DENIED} if the permission is denied.
 * @since 12
 */
int32_t OH_Input_InjectMouseEvent(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Injects a mouse event by using coordinates in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 * <br>This API does not take effect if the user has not granted authorization and the caller does not have the ohos.
 * permission.CONTROL_DEVICE permission.
 * <br>Since API version 20, you are advised to use {@link OH_Input_RequestInjection()} to request the required
 * permission before calling this API. If the status returned by {@link OH_Input_QueryAuthorizedStatus()} is
 * {@link AUTHORIZED}, then you can call this API.
 * <br>Since API version 26.0.0, callers that have the ohos.permission.CONTROL_DEVICE permission can use this API
 * directly.
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Return value of the **OH_Input_InjectMouseEventGlobal** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect;
 *     <br>{@link INPUT_PERMISSION_DENIED} if the permission is denied.
 * @since 20
 */
int32_t OH_Input_InjectMouseEventGlobal(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Creates a mouse event object. You can call {@link OH_Input_DestroyMouseEvent()} to destroy a mouse event
 * object.
 *
 * @return {@link Input_MouseEvent} pointer object if the operation is successful; a null pointer otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_MouseEvent* OH_Input_CreateMouseEvent();

/**
 * @brief Destroys a mouse event object.
 *
 * @param mouseEvent Mouse event object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyMouseEvent(struct Input_MouseEvent** mouseEvent);

/**
 * @brief Sets the action for a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param action Mouse action. For details, see {@link Input_MouseEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAction(struct Input_MouseEvent* mouseEvent, int32_t action);

/**
 * @brief Obtains the action of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Mouse action.  Returns -1 if mouseEvent is NULL. For details, see {@link Input_MouseEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventAction(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the X coordinate of the mouse event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param displayX X-coordinate in the relative coordinate system with the upper left corner of the specified screen as
 *     the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventDisplayX(struct Input_MouseEvent* mouseEvent, int32_t displayX);

/**
 * @brief Obtains the X coordinate of the mouse event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return The X coordinate of the mouse event in the relative coordinate system with the upper left corner of the
 *     specified screen as the origin, in pixels (px). Returns -1 if mouseEvent is NULL.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventDisplayX(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the Y coordinate of the mouse event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param displayY Y coordinate of the mouse event in the relative coordinate system with the upper left corner of the
 *     specified screen as the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventDisplayY(struct Input_MouseEvent* mouseEvent, int32_t displayY);

/**
 * @brief Obtains the Y coordinate of the mouse event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Y-coordinate of the mouse event in the relative coordinate system with the upper left corner of the
 *     specified screen as the origin, in pixels (px). Returns -1 if mouseEvent is NULL.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventDisplayY(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the button for a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param button Mouse button. For details, see {@link Input_MouseEventButton}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventButton(struct Input_MouseEvent* mouseEvent, int32_t button);

/**
 * @brief Obtains the button of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Mouse button. Returns -1 if mouseEvent is NULL.
 *     For details, see {@link Input_MouseEventButton}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventButton(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the axis type for a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param axisType Mouse axis type, such as vertical axis and horizontal axis. For details, see
 *     {@link InputEvent_MouseAxis}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAxisType(struct Input_MouseEvent* mouseEvent, int32_t axisType);

/**
 * @brief Obtains the axis type of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Enumerates mouse axis types. Returns -1 if mouseEvent is NULL.
 *     For details, see {@link InputEvent_MouseAxis}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventAxisType(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the axis value for a mouse axis event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param axisValue Axis event value. A positive number means scrolling forward (for example, 1.0 equals one unit
 *     forward), and a negative number means scrolling backward (for example, -1.0 equals one unit backward).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAxisValue(struct Input_MouseEvent* mouseEvent, float axisValue);

/**
 * @brief Obtains the axis value of a mouse axis event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Axis event value. Returns -1 if mouseEvent is NULL.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
float OH_Input_GetMouseEventAxisValue(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the time when a mouse event occurs.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param actionTime Time when the mouse event occurred, representing the number of microseconds elapsed since system
 *     startup, in microseconds (μs).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventActionTime(struct Input_MouseEvent* mouseEvent, int64_t actionTime);

/**
 * @brief Obtains the time when a mouse event occurs.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Returns the time when the mouse event occurred, representing the number of microseconds elapsed since system
 *     startup, in microseconds (μs).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetMouseEventActionTime(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the window ID of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param windowId Window ID of the mouse event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetMouseEventWindowId(struct Input_MouseEvent* mouseEvent, int32_t windowId);

/**
 * @brief Obtains the window ID of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Window ID of the mouse event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetMouseEventWindowId(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the screen ID of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @param displayId Screen ID of the mouse event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetMouseEventDisplayId(struct Input_MouseEvent* mouseEvent, int32_t displayId);

/**
 * @brief Obtains the screen ID of a mouse event.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return Screen ID if the operation is successful; **-1** if **mouseEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetMouseEventDisplayId(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the X coordinate of the mouse event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param mouseEvent Mouse Event object, which can be created through the {@link OH_Input_CreateMouseEvent()} API.
 *     <br>After use, the Mouse Event object must be destroyed through the {@link OH_Input_DestroyMouseEvent()} API.
 * @param globalX X coordinate of the Mouse Event in the global coordinate system with the origin at the upper left
 *     corner of the primary screen, in pixels (px).
 * @since 20
 */
void OH_Input_SetMouseEventGlobalX(struct Input_MouseEvent* mouseEvent, int32_t globalX);

/**
 * @brief Obtains the X coordinate of the mouse event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return X-coordinate in the global coordinate system with the origin at the upper left corner of the primary screen,
 *     in pixels (px).
 * @since 20
 */
int32_t OH_Input_GetMouseEventGlobalX(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the Y coordinate of the mouse event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param mouseEvent Mouse Event object, which can be created through the {@link OH_Input_CreateMouseEvent()} API.
 *     <br>After use, the Mouse Event object must be destroyed through the {@link OH_Input_DestroyMouseEvent()} API.
 * @param globalY Y-coordinate of the mouse event in the global coordinate system with the origin at the upper left
 *     corner of the primary screen, in pixels (px).
 * @since 20
 */
void OH_Input_SetMouseEventGlobalY(struct Input_MouseEvent* mouseEvent, int32_t globalY);

/**
 * @brief Obtains the Y coordinate of the mouse event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param mouseEvent Mouse event object. You can call {@link OH_Input_CreateMouseEvent()} to create a mouse event
 *     object.
 *     <br>If the mouse event object is no longer needed, destroy it by calling {@link OH_Input_DestroyMouseEvent()}.
 * @return The Y coordinate of the mouse event in the global coordinate system with the origin at the upper left corner
 *     of the primary screen, in pixels (px).
 * @since 20
 */
int32_t OH_Input_GetMouseEventGlobalY(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Injects a touch event by using coordinates in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 * <br>This API does not take effect if the user has not granted authorization and the caller does not have the ohos.
 * permission.CONTROL_DEVICE permission.
 * <br>Since API version 20, you are advised to use {@link OH_Input_RequestInjection()} to request the required
 * permission before calling this API. If the status returned by {@link OH_Input_QueryAuthorizedStatus()} is
 * {@link AUTHORIZED}, then you can call this API.
 * <br>Since API version 26.0.0, callers that have the ohos.permission.CONTROL_DEVICE permission can use this API
 * directly.
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Return value of the OH_Input_InjectTouchEvent function.
 *     <br>{@link INPUT_SUCCESS} indicates successful injection.
 *     <br>{@link INPUT_PARAMETER_ERROR} indicates a parameter error.
 * @since 12
 */
int32_t OH_Input_InjectTouchEvent(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Injects a touch event by using coordinates in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 * <br>This API does not take effect if the event injection authorization is not granted and the caller does not have
 * the ohos.permission.CONTROL_DEVICE permission.
 * <br>Since API version 20, you are advised to use {@link OH_Input_RequestInjection()} to request the required
 * permission before calling this API. If the status returned by {@link OH_Input_QueryAuthorizedStatus()} is
 * {@link AUTHORIZED}, then you can call this API.
 * <br>Since API version 26.0.0, callers that have the ohos.permission.CONTROL_DEVICE permission can use this API
 * directly.
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Return value of the **OH_Input_InjectTouchEventGlobal** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect;
 *     <br>{@link INPUT_PERMISSION_DENIED} if the permission is denied.
 * @since 20
 */
int32_t OH_Input_InjectTouchEventGlobal(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Creates a **TouchEvent** object. You can call {@link OH_Input_DestroyTouchEvent()} to destroy a touch event
 * object.
 *
 * @return {@link Input_TouchEvent} pointer object if the operation is successful; a null pointer otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_TouchEvent* OH_Input_CreateTouchEvent();

/**
 * @brief Destroys a **TouchEvent** object.
 *
 * @param touchEvent **TouchEvent** object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyTouchEvent(struct Input_TouchEvent** touchEvent);

/**
 * @brief Sets the action of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param action Action of the touch event. For details, see {@link Input_TouchEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventAction(struct Input_TouchEvent* touchEvent, int32_t action);

/**
 * @brief Obtains the action of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Action of the touch event. For details, see {@link Input_TouchEventAction}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventAction(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the finger ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param id Finger ID of a touch event. The ID of the first finger touching the screen is 0, the second is 1, and so
 *     on incrementally.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventFingerId(struct Input_TouchEvent* touchEvent, int32_t id);

/**
 * @brief Obtains the finger ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Finger ID of a touch event. The ID of the first finger touching the screen is 0, the second is 1, and so on
 *     incrementally.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventFingerId(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the X coordinate of the touch event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param displayX X coordinate of the touch screen input event in the relative coordinate system with the upper left
 *     corner of the specified screen as the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventDisplayX(struct Input_TouchEvent* touchEvent, int32_t displayX);

/**
 * @brief Obtains the X coordinate of the touch event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return The X coordinate of the touch screen input event in the relative coordinate system with the upper left
 *     corner of the specified screen as the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventDisplayX(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the Y coordinate of the touch event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param displayY Y-coordinate of the touch screen input event in the relative coordinate system with the upper left
 *     corner of the specified screen as the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventDisplayY(struct Input_TouchEvent* touchEvent, int32_t displayY);

/**
 * @brief Obtains the Y coordinate of the touch event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return The Y coordinate of the touch screen input event in the relative coordinate system with the upper left
 *     corner of the specified screen as the origin, in pixels (px).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventDisplayY(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the time when the touch event occurs.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param actionTime Time when the touch screen input event occurred, indicating the number of microseconds elapsed
 *     since system startup, in microseconds (μs).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventActionTime(struct Input_TouchEvent* touchEvent, int64_t actionTime);

/**
 * @brief Obtains the time when the touch event occurs.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Time when a touch event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetTouchEventActionTime(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the window ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param windowId Window ID of a touch event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetTouchEventWindowId(struct Input_TouchEvent* touchEvent, int32_t windowId);

/**
 * @brief Obtains the window ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Window ID of a touch event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetTouchEventWindowId(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the screen ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param displayId Screen ID of a touch event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
void OH_Input_SetTouchEventDisplayId(struct Input_TouchEvent* touchEvent, int32_t displayId);

/**
 * @brief Obtains the screen ID of a touch event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Screen ID of a touch event.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
int32_t OH_Input_GetTouchEventDisplayId(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the X coordinate of the touch event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param touchEvent Touch screen input event object, which can be created through the
 *     {@link OH_Input_CreateTouchEvent()} interface.
 *     <br>After use, the touch screen input event object must be destroyed using the
 *     {@link OH_Input_DestroyTouchEvent()} interface.
 * @param globalX X coordinate of the touch screen input event in the global coordinate system with the upper left
 *     corner of the primary screen as the origin, in pixels (px).
 * @since 20
 */
void OH_Input_SetTouchEventGlobalX(struct Input_TouchEvent* touchEvent, int32_t globalX);

/**
 * @brief Obtains the X coordinate of the touch event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return The X coordinate in the global coordinate system with the upper left corner of the primary screen as the
 *     origin, in pixels (px).
 * @since 20
 */
int32_t OH_Input_GetTouchEventGlobalX(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the Y coordinate of the touch event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param touchEvent Touch screen input event object, which can be created through the
 *     {@link OH_Input_CreateTouchEvent()} interface.
 *     <br>After use, the touch screen input event object must be destroyed using the
 *     {@link OH_Input_DestroyTouchEvent()} interface.
 * @param globalY Y coordinate of the touch screen input event in the global coordinate system with the upper left
 *     corner of the primary screen as the origin, in pixels (px).
 * @since 20
 */
void OH_Input_SetTouchEventGlobalY(struct Input_TouchEvent* touchEvent, int32_t globalY);

/**
 * @brief Obtains the Y coordinate of the touch event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return The Y coordinate in the global coordinate system with the upper left corner of the primary screen as the
 *     origin for the touch screen input event, in pixels (px).
 * @since 20
 */
int32_t OH_Input_GetTouchEventGlobalY(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the pressure for a touchscreen input event. If the pressure value is not set or is not within the valid
 * range, the default value **0.0** is used.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param pressure Pressure value. The value range is [0.0, 1.0]. Currently, the minimum pressure that can be sensed by
 *     the touchscreen is 0.0, and the maximum pressure is 1.0. This value has no unit.
 * @return Return value of the **OH_Input_SetTouchEventPressure** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 24
 */
Input_Result OH_Input_SetTouchEventPressure(struct Input_TouchEvent* touchEvent, double pressure);

/**
 * @brief Obtains the pressure of a touchscreen input event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Pressure value, without a unit. When touchEvent is NULL, return the default pressure 0.0.
 * @since 24
 */
double OH_Input_GetTouchEventPressure(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the X coordinate of the touch event in the relative coordinate system with the upper-left corner of the
 * specified window as the origin. If the X coordinate is not set, the default value **0** is used.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param windowX X-coordinate in the relative coordinate system with the origin at the upper left corner of the
 *     specified window, in pixels (px).
 * @since 24
 */
void OH_Input_SetTouchEventWindowX(struct Input_TouchEvent* touchEvent, int32_t windowX);

/**
 * @brief Obtains the X coordinate of the touch event in the relative coordinate system with the upper-left corner of
 * the specified window as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return X coordinate in the relative coordinate system with the upper left corner of the specified window as the
 *     origin, in pixels (px). When touchEvent is NULL, return the default value 0.
 * @since 24
 */
int32_t OH_Input_GetTouchEventWindowX(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the Y coordinate of the touch event in the relative coordinate system with the upper-left corner of the
 * specified window as the origin. If the Y coordinate is not set, the default value **0** is used.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param windowY Y-coordinate in the relative coordinate system with the origin at the upper left corner of the window,
 *      in pixels (px).
 * @since 24
 */
void OH_Input_SetTouchEventWindowY(struct Input_TouchEvent* touchEvent, int32_t windowY);

/**
 * @brief Obtains the Y coordinate of the touch event in the relative coordinate system with the upper-left corner of
 * the specified window as the origin.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Y-coordinate in the relative coordinate system with the origin at the upper left corner of the window, in
 *     pixels (px). When touchEvent is NULL, return the default value 0.
 * @since 24
 */
int32_t OH_Input_GetTouchEventWindowY(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the time when the most recent down event occurred for the finger or other touchscreen devices associated
 * with the current touchscreen event. If the time is not set, the default value **0** is used.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param downTime The time when the most recent press event of the finger or other touch screen peripheral
 *     corresponding to the current touch screen event occurred, representing the number of microseconds elapsed since
 *     system startup, in microseconds (μs).
 * @since 24
 */
void OH_Input_SetTouchEventDownTime(struct Input_TouchEvent* touchEvent, int64_t downTime);

/**
 * @brief Obtains the time when the most recent down event occurred for the finger or other touchscreen devices
 * associated with the current touchscreen event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return The time when the most recent press event of the finger or other touch peripherals corresponding to the
 *     current touch screen input occurred, representing the number of microseconds elapsed since system startup, in
 *     microseconds (μs). When touchEvent is NULL, return 0.
 * @since 24
 */
int64_t OH_Input_GetTouchEventDownTime(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the tool type for a touchscreen input event. If **toolType** is not set, the default value **
 * Input_TouchEventToolType.TOOL_TYPE_FINGER** is used.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @param toolType Tool type.
 * @return Return value of the **OH_Input_SetTouchEventToolType** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 24
 */
Input_Result OH_Input_SetTouchEventToolType(struct Input_TouchEvent* touchEvent, Input_TouchEventToolType toolType);

/**
 * @brief Obtains the tool type of a touchscreen input event.
 *
 * @param touchEvent **TouchEvent** object, which can be created through {@link OH_Input_CreateTouchEvent()}.
 *     <br>If the **TouchEvent** object is no longer needed, destroy it by calling {@link OH_Input_DestroyTouchEvent()}.
 * @return Tool type.{@link TOOL_TYPE_FINGER} When touchEvent is NULL, return the default toolType.
 * @since 24
 */
Input_TouchEventToolType OH_Input_GetTouchEventToolType(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Stops event injection and revokes authorization.
 *
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_CancelInjection();

/**
 * @brief Creates an axis event object. You can call {@link OH_Input_DestroyAxisEvent()} to destroy an axis event
 * object.
 *
 * @return {@link Input_AxisEvent} object if the operation is successful; **null** otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_AxisEvent* OH_Input_CreateAxisEvent(void);

/**
 * @brief Destroys an axis event object.
 *
 * @param axisEvent Pointer to the axis event object.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_DestroyAxisEvent(Input_AxisEvent** axisEvent);

/**
 * @brief Sets the action for an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param action Axis event action. For details, see {@link InputEvent_AxisAction}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventAction(Input_AxisEvent* axisEvent, InputEvent_AxisAction action);

/**
 * @brief Obtains the action of an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param action Axis event action. For details, see {@link InputEvent_AxisAction}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     action** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventAction(const Input_AxisEvent* axisEvent, InputEvent_AxisAction *action);

/**
 * @brief Sets the X coordinate of the axis event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayX X coordinate in the relative coordinate system with the upper left corner of the specified screen as
 *     the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventDisplayX(Input_AxisEvent* axisEvent, float displayX);

/**
 * @brief Obtains the X coordinate of the axis event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayX Output parameter, returns the X coordinate of the axis event in the relative coordinate system with
 *     the upper left corner of the specified screen as the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     displayX** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventDisplayX(const Input_AxisEvent* axisEvent, float* displayX);

/**
 * @brief Sets the Y coordinate of the axis event in the relative coordinate system with the upper-left corner of the
 * specified screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayY Y coordinate in the relative coordinate system with the upper left corner of the specified screen as
 *     the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventDisplayY(Input_AxisEvent* axisEvent, float displayY);

/**
 * @brief Obtains the Y coordinate of the axis event in the relative coordinate system with the upper-left corner of
 * the specified screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayY Output parameter, returns the Y coordinate of the axis event in the relative coordinate system with
 *     the upper left corner of the specified screen as the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     displayY** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventDisplayY(const Input_AxisEvent* axisEvent, float* displayY);

/**
 * @brief Sets the axis value of the axis type specified by the axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param axisType Axis type. For details, see {@link InputEvent_AxisType}.
 * @param axisValue Value of the axis event. A positive value indicates scrolling forward (for example, 1.0 means
 *     scrolling forward by one unit), a negative value indicates scrolling backward (for example, -1.0 means scrolling
 *     backward by one unit), and zero indicates no scrolling.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventAxisValue(Input_AxisEvent* axisEvent,
                                            InputEvent_AxisType axisType, double axisValue);

/**
 * @brief Obtains the axis value for the specified axis type of the axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param axisType Axis type. For details, see {@link InputEvent_AxisType}.
 * @param axisValue Axis event value. A positive number means scrolling forward (for example, 1.0 equals one unit
 *     forward), and a negative number means scrolling backward (for example, -1.0 equals one unit backward).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     axisValue** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventAxisValue(const Input_AxisEvent* axisEvent,
                                            InputEvent_AxisType axisType, double* axisValue);

/**
 * @brief Sets the time when an axis event occurs.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param actionTime Time when the axis event occurred, representing the number of microseconds elapsed since system
 *     startup, in microseconds (μs).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventActionTime(Input_AxisEvent* axisEvent, int64_t actionTime);

/**
 * @brief Obtains the time when an axis event occurs.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param actionTime Output parameter, returns the time when the axis event occurred, representing the number of
 *     microseconds elapsed since system startup, in microseconds (μs).
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     actionTime** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventActionTime(const Input_AxisEvent* axisEvent, int64_t* actionTime);

/**
 * @brief Sets the axis event type.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param axisEventType Axis event type. For details, see {@link InputEvent_AxisEventType}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventType(Input_AxisEvent* axisEvent, InputEvent_AxisEventType axisEventType);

/**
 * @brief Obtains the axis event type.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param axisEventType Axis event type. For details, see {@link InputEvent_AxisEventType}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     axisEventType** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventType(const Input_AxisEvent* axisEvent, InputEvent_AxisEventType* axisEventType);

/**
 * @brief Sets the axis event source type.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param sourceType Axis event source type. For details, see {@link InputEvent_SourceType}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventSourceType(Input_AxisEvent* axisEvent, InputEvent_SourceType sourceType);

/**
 * @brief Obtains the axis event source type.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param sourceType Axis event source type. For details, see {@link InputEvent_SourceType}.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     sourceType** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventSourceType(const Input_AxisEvent* axisEvent, InputEvent_SourceType* sourceType);

/**
 * @brief Sets the window ID of an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param windowId Window ID of an axis event.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
Input_Result OH_Input_SetAxisEventWindowId(Input_AxisEvent* axisEvent, int32_t windowId);

/**
 * @brief Obtains the window ID of an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param windowId Window ID of the axis event.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     windowId** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
Input_Result OH_Input_GetAxisEventWindowId(const Input_AxisEvent* axisEvent, int32_t* windowId);

/**
 * @brief Sets the screen ID of an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayId Screen ID of an axis event.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
Input_Result OH_Input_SetAxisEventDisplayId(Input_AxisEvent* axisEvent, int32_t displayId);

/**
 * @brief Obtains the screen ID of an axis event.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param displayId Screen ID of the axis event.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PARAMETER_ERROR} if **axisEvent** or **
 *     displayId** is null.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
Input_Result OH_Input_GetAxisEventDisplayId(const Input_AxisEvent* axisEvent, int32_t* displayId);

/**
 * @brief Sets the X coordinate of the axis event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param axisEvent Axis event object, which can be created through the {@link OH_Input_CreateAxisEvent()} API.
 *     <br>After use, the axis event object must be destroyed through the {@link OH_Input_DestroyAxisEvent()} API.
 * @param globalX X coordinate of the axis event in the global coordinate system with the upper left corner of the
 *     primary screen as the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **axisEvent** is a null pointer.
 * @since 20
 */
Input_Result OH_Input_SetAxisEventGlobalX(struct Input_AxisEvent* axisEvent, int32_t globalX);

/**
 * @brief Obtains the X coordinate of the axis event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param globalX X-coordinate of the axis event in the global coordinate system with the upper left corner of the
 *     primary screen as the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **axisEvent** or **globalX** is a null pointer.
 * @since 20
 */
Input_Result OH_Input_GetAxisEventGlobalX(const Input_AxisEvent* axisEvent, int32_t* globalX);

/**
 * @brief Sets the Y coordinate of the axis event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param axisEvent Axis event object, which can be created using the {@link OH_Input_CreateAxisEvent()} interface.
 *     <br>After use, the axis event object must be destroyed using the {@link OH_Input_DestroyAxisEvent()} interface.
 * @param globalY Y-coordinate of the axis event in the global coordinate system with the origin at the upper left
 *     corner of the primary screen, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **axisEvent** is a null pointer.
 * @since 20
 */
Input_Result OH_Input_SetAxisEventGlobalY(struct Input_AxisEvent* axisEvent, int32_t globalY);

/**
 * @brief Obtains the Y coordinate of the axis event in the global coordinate system with the upper-left corner of the
 * primary screen as the origin.
 *
 * @param axisEvent Axis event object. You can call {@link OH_Input_CreateAxisEvent()} to create an axis event object.
 *     <br>If the axis event object is no longer needed, destroy it by calling {@link OH_Input_DestroyAxisEvent()}.
 * @param globalY Y-coordinate of the axis event in the global coordinate system with the upper left corner of the
 *     primary screen as the origin, in pixels (px).
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **axisEvent** or **globalY** is a null pointer.
 * @since 20
 */
Input_Result OH_Input_GetAxisEventGlobalY(const Input_AxisEvent* axisEvent, int32_t* globalY);

/**
 * @brief Adds a listener for key events. Only the initial addition takes effect. Subsequent attempts will be ignored.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback used to receive key events.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PERMISSION_DENIED} if permission
 *     verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty; {@link INPUT_SERVICE_EXCEPTION} if the service is
 *     abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddKeyEventMonitor(Input_KeyEventCallback callback);

/**
 * @brief Adds a listener for mouse events, including mouse click and movement events, but not scroll wheel events.
 * Scroll wheel events are axis events.
 * <br>This API can be called only when the screen recording scenario is in use. Otherwise, the call does not take
 * effect.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback used to receive mouse events.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PERMISSION_DENIED} if permission
 *     verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty; {@link INPUT_SERVICE_EXCEPTION} if the service is
 *     abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddMouseEventMonitor(Input_MouseEventCallback callback);

/**
 * @brief Adds a listener for touch input events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback used to receive touch events.
 * @return {@link INPUT_SUCCESS} if the operation is successful; {@link INPUT_PERMISSION_DENIED} if permission
 *     verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty; {@link INPUT_SERVICE_EXCEPTION} if the service is
 *     abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddTouchEventMonitor(Input_TouchEventCallback callback);

/**
 * @brief Adds a listener for all types of axis events, which are defined in {@link InputEvent_AxisEventType}.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback used to receive axis events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddAxisEventMonitorForAll(Input_AxisEventCallback callback);

/**
 * @brief Adds a listener for the specified type of axis events, which are defined in {@link InputEvent_AxisEventType}.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param axisEventType Axis event type, which is defined in {@link InputEvent_AxisEventType}.
 * @param callback Callback used to receive axis events of a specified type.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback);

/**
 * @brief Removes the listener for key events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback for key events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveKeyEventMonitor(Input_KeyEventCallback callback);

/**
 * @brief Removes the listener for mouse events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback for mouse events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveMouseEventMonitor(Input_MouseEventCallback callback);

/**
 * @brief Removes the listener for touch events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback for touch events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveTouchEventMonitor(Input_TouchEventCallback callback);

/**
 * @brief Removes the listener for all types of axis events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback Callback for the all types of axis events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveAxisEventMonitorForAll(Input_AxisEventCallback callback);

/**
 * @brief Removes the listener for the specified type of axis events, which are defined in
 * {@link InputEvent_AxisEventType}.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param axisEventType Axis event type, which is defined in {@link InputEvent_AxisEventType}.
 * @param callback Callback for the specified type of axis events.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback);

/**
 * @brief Adds a key event interceptor. Only the first addition takes effect. Subsequent requests will return error
 * code {@link INPUT_REPEAT_INTERCEPTOR}. Key events are intercepted only when the application gains focus.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @param callback Callback used to receive key events.
 * @param option Options for event interception. If **null** is passed, the default value is used.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_REPEAT_INTERCEPTOR} if an interceptor is repeatedly added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddKeyEventInterceptor(Input_KeyEventCallback callback, Input_InterceptorOptions *option);

/**
 * @brief Adds an interceptor for input events, including mouse, touch, and axis events. Only the first addition takes
 * effect. Subsequent requests will return error code {@link INPUT_REPEAT_INTERCEPTOR}. Key events are intercepted only
 * when the application window is hit.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @param callback Pointer to the structure of the interceptor event callback. For details, see
 *     {@link Input_InterceptorEventCallback}.
 * @param option Options for event interception. If **null** is passed, the default value is used.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the callback is empty or no listener is added;
 *     <br>{@link INPUT_REPEAT_INTERCEPTOR} if an interceptor is repeatedly added;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddInputEventInterceptor(Input_InterceptorEventCallback *callback,
                                               Input_InterceptorOptions *option);

/**
 * @brief Removes the interceptor for key events.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveKeyEventInterceptor(void);

/**
 * @brief Removes the interceptor for input events, including mouse, touch, and axis events.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PERMISSION_DENIED} if permission verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveInputEventInterceptor(void);

/**
 * @brief Obtains the interval since the last system input event.
 *
 * @param timeInterval Time interval, in microseconds (μs).
 * @return Return value of the **OH_Input_GetIntervalSinceLastInput** function.
 *     <br>{@link INPUT_SUCCESS} if the interval is obtained successfully;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetIntervalSinceLastInput(int64_t *timeInterval);

/**
 * @brief Creates a hotkey object. You can call {@link OH_Input_DestroyHotkey()} to destroy a hotkey object.
 *
 * @return If the operation is successful, a pointer to an {@link Input_Hotkey} object is returned. Otherwise, a null
 *     pointer is returned, possibly due to memory allocation failure.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Hotkey *OH_Input_CreateHotkey(void);

/**
 * @brief Destroys a hotkey object.
 *
 * @param hotkey Hotkey object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_DestroyHotkey(Input_Hotkey **hotkey);

/**
 * @brief Sets the modifier keys.
 *
 * @param hotkey Hotkey object.
 * @param preKeys List of modifier keys.
 * @param size Number of modifier keys. One or two modifier keys are supported.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetPreKeys(Input_Hotkey *hotkey, int32_t *preKeys, int32_t size);

/**
 * @brief Obtains the modifier key.
 *
 * @param hotkey Hotkey object.
 * @param preKeys List of modifier keys.
 * @param preKeyCount Number of modifier keys.
 * @return Return value of the **OH_Input_GetPreKeys** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetPreKeys(const Input_Hotkey *hotkey, int32_t **preKeys, int32_t *preKeyCount);

/**
 * @brief Sets the modified key.
 *
 * @param hotkey Hotkey object.
 * @param finalKey Modifier key value. Only one modifier key value is allowed.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetFinalKey(Input_Hotkey *hotkey, int32_t finalKey);

/**
 * @brief Obtains the modified key.
 *
 * @param hotkey Hotkey object.
 * @param finalKeyCode Modified key.
 * @return Return value of the **OH_Input_GetFinalKey** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetFinalKey(const Input_Hotkey *hotkey, int32_t *finalKeyCode);

/**
 * @brief Creates an {@link Input_Hotkey} array. You can call {@link OH_Input_GetAllSystemHotkeys()} to obtain a valid *
 * *count** parameter. You can call {@link OH_Input_DestroyAllSystemHotkeys()} to destroy the array of the
 * {@link Input_Hotkey} instance and reclaim the memory.
 *
 * @param count Number of {@link Input_Hotkey} instances.
 * @return Return value of the **OH_Input_CreateAllSystemHotkeys** function.
 *     <br>which is {@link INPUT_SUCCESS} if the operation is successful.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Hotkey **OH_Input_CreateAllSystemHotkeys(int32_t count);

/**
 * @brief Destroys an {@link Input_Hotkey} array and reclaims the memory.
 *
 * @param hotkeys Double pointer to the {@link Input_Hotkey} array.
 * @param count Number of {@link Input_Hotkey} instances.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_DestroyAllSystemHotkeys(Input_Hotkey **hotkeys, int32_t count);

/**
 * @brief Obtains all configured hotkeys.
 *
 * @param hotkey {@link Input_Hotkey} array. When calling this API for the first time, you can pass **NULL** to obtain
 *     the array length.
 * @param count Number of supported hotkeys.
 * @return Return value of the **OH_Input_GetAllSystemHotkeys** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetAllSystemHotkeys(Input_Hotkey **hotkey, int32_t *count);

/**
 * @brief Specifies whether to report repeated key events.
 *
 * @param hotkey Hotkey object.
 * @param isRepeat Whether to report repeated key events. The value **true** means to report repeated key events, and
 *     the value **false** means the opposite.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetRepeat(Input_Hotkey* hotkey, bool isRepeat);

/**
 * @brief Checks whether to report repeated key events.
 *
 * @param hotkey Hotkey object.
 * @param isRepeat Whether the reported key event is repeated. The value **true** indicates that the key event is
 *     repeated, and the value **false** indicates that the key event is not repeated.
 * @return Return value of the **OH_Input_GetRepeat** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetRepeat(const Input_Hotkey* hotkey, bool *isRepeat);

/**
 * @brief Subscribes to hotkey events.
 *
 * @param hotkey Hotkey object.
 * @param callback Defines the callback used to return hotkey events.
 * @return Return value of the **OH_Input_AddHotkeyMonitor** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if parameter verification fails;
 *     <br>{@link INPUT_OCCUPIED_BY_SYSTEM} if the hotkey has been occupied by the system (you can use
 *     {@link OH_Input_GetAllSystemHotkeys()} to query allsystem hotkeys);
 *     <br>{@link INPUT_OCCUPIED_BY_OTHER} if the hotkey has been occupied by another application;
 *     <br>{@link INPUT_DEVICE_NOT_SUPPORTED} if the function is not supported.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_AddHotkeyMonitor(const Input_Hotkey* hotkey, Input_HotkeyCallback callback);

/**
 * @brief Unsubscribes from hotkey events.
 *
 * @param hotkey Hotkey object.
 * @param callback Defines the callback used to return hotkey events.
 * @return Return value of the **OH_Input_RemoveHotkeyMonitor** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if parameter verification fails.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_RemoveHotkeyMonitor(const Input_Hotkey* hotkey, Input_HotkeyCallback callback);

/**
 * @brief Obtains the IDs of all input devices.
 *
 * @param deviceIds List of input device IDs.
 * @param inSize Size of the input device ID list.
 * @param outSize Length of the output device ID list. The value must be less than or equal to the value of **inSize**.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceIds** or **outSize** is a null pointer or **inSize** is less than
 *     **0**.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceIds(int32_t *deviceIds, int32_t inSize, int32_t *outSize);

/**
 * @brief Obtains information about the input device.
 *
 * @param deviceId Unique ID of the input device. If a physical device is repeatedly reinstalled or restarted, its ID
 *     may change.
 * @param deviceInfo Pointer to the {@link Input_DeviceInfo} object.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** is a null pointer or **deviceId** is invalid;
 *     <br>You can use {@link OH_Input_GetDeviceIds()} to query the device IDs supported by the system.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDevice(int32_t deviceId, Input_DeviceInfo **deviceInfo);

/**
 * @brief Creates a **deviceInfo** object. You can call {@link OH_Input_DestroyDeviceInfo()} to destroy an input device
 * information object.
 *
 * @return Pointer to the {@link Input_DeviceInfo} object if the operation is successful; a null pointer otherwise (
 *     possibly because of a memory allocation failure).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_DeviceInfo* OH_Input_CreateDeviceInfo(void);

/**
 * @brief Destroys a **deviceInfo** object.
 *
 * @param deviceInfo **deviceInfo** object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
void OH_Input_DestroyDeviceInfo(Input_DeviceInfo **deviceInfo);

/**
 * @brief Obtains the keyboard type of the input device.
 *
 * @param deviceId Unique ID of the input device. If a physical device is repeatedly reinstalled or restarted, its ID
 *     may change.
 * @param keyboardType Pointer to the keyboard type of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the device ID is invalid or **keyboardType** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetKeyboardType(int32_t deviceId, int32_t *keyboardType);

/**
 * @brief Obtains the ID of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param id Pointer to the input device ID.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **ID** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceId(Input_DeviceInfo *deviceInfo, int32_t *id);

/**
 * @brief Obtains the name of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param name Pointer to the input device name.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **name** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceName(Input_DeviceInfo *deviceInfo, char **name);

/**
 * @brief Obtains the capabilities of an input device, for example, a touchscreen, touchpad, or keyboard.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param capabilities Pointer to the capability information of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **capabilities** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetCapabilities(Input_DeviceInfo *deviceInfo, int32_t *capabilities);

/**
 * @brief Obtains the version information of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param version Pointer to the version information of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **version** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceVersion(Input_DeviceInfo *deviceInfo, int32_t *version);

/**
 * @brief Obtains the product information of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param product Pointer to the product information of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **product** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceProduct(Input_DeviceInfo *deviceInfo, int32_t *product);

/**
 * @brief Obtains the vendor information of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param vendor Pointer to the vendor information of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **vendor** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceVendor(Input_DeviceInfo *deviceInfo, int32_t *vendor);

/**
 * @brief Obtains the physical address of an input device.
 *
 * @param deviceInfo Input device information. For details, see {@link Input_DeviceInfo}.
 * @param address Pointer to the physical address of the input device.
 * @return {@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **deviceInfo** or **address** is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceAddress(Input_DeviceInfo *deviceInfo, char **address);

/**
 * @brief Registers a listener for device hot swap events.
 *
 * @param listener Pointer to the {@link Input_DeviceListener} object.
 * @return Return value of the **OH_Input_RegisterDeviceListener** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the listener is null;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_RegisterDeviceListener(Input_DeviceListener* listener);

/**
 * @brief Unregisters the listener for device hot swap events.
 *
 * @param listener Pointer to the {@link Input_DeviceListener} object.
 * @return Return value of the **OH_Input_UnregisterDeviceListener** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if **listener** is null or the listener is not registered;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_UnregisterDeviceListener(Input_DeviceListener* listener);

/**
 * @brief Unregisters the listener for all device hot swap events.
 *
 * @return Return value of the **OH_Input_UnregisterDeviceListener** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_UnregisterDeviceListeners();

/**
 * @brief Obtains the function key status.
 *
 * @param keyCode Function key. Currently, only the **CapsLock** key is supported. The key value is **1**.
 * @param state Function key status. The value **0** indicates that the function key is disabled, and the value **1**
 *     indicates that the function key is enabled.
 * @return Return value of the **OH_Input_GetFunctionKeyState** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect;
 *     <br>{@link INPUT_KEYBOARD_DEVICE_NOT_EXIST} if the keyboard device does not exist.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 15
 */
Input_Result OH_Input_GetFunctionKeyState(int32_t keyCode, int32_t *state);

/**
 * @brief Queries the maximum number of touch points supported by the device.
 *
 * @param count Maximum number of touch points supported by the device. The value range is [0, 10]. The value **-1**
 *     indicates that the number of touch points is unknown.
 * @return Return value of the **OH_Input_QueryMaxTouchPoints** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 20
 */
Input_Result OH_Input_QueryMaxTouchPoints(int32_t *count);

/**
 * @brief Requests the permission for {@link OH_Input_InjectKeyEvent}, {@link OH_Input_InjectTouchEvent}, and
 * {@link OH_Input_InjectMouseEvent}.
 * <br>Since API version 26.0.0, if the ohos.permission.CONTROL_DEVICE permission has been granted, you do not need to
 * request the injection permission. The behavior of this API is independent of the ohos.permission.CONTROL_DEVICE
 * permission.
 *
 * @param callback Callback used to return the permission authorization status. For details, see
 *     {@link Input_InjectAuthorizeCallback}.
 * @return Return value. For details, see {@link Input_Result}.
 *     <br>INPUT_SUCCESS = 0: Operation success. The application waits for the user authorization result and returns
 *     the authorization status through a callback.
 *     <br>INPUT_PARAMETER_ERROR = 401: Parameter error. The callback parameter is empty.
 *     <br>INPUT_DEVICE_NOT_SUPPORTED = 801: Function not supported.
 *     <br>INPUT_SERVICE_EXCEPTION = 3800001: Service error.
 *     <br>INPUT_INJECTION_AUTHORIZING = 3900005: Permission being granted.
 *     <br>INPUT_INJECTION_OPERATION_FREQUENT = 3900006: Repeated request. The application continuously requests
 *     permission authorization at an interval of no more than 3 seconds.
 *     <br>INPUT_INJECTION_AUTHORIZED = 3900007: Permission granted.
 *     <br>INPUT_INJECTION_AUTHORIZED_OTHERS = 3900008: Permission granted to other applications.
 * @since 20
 */
Input_Result OH_Input_RequestInjection(Input_InjectAuthorizeCallback callback);

/**
 * @brief Queries the injection permission authorization status of the current application.
 * <br>Since API version 26.0.0, this API returns only the dialog authorization status. It does not indicate whether
 * the caller has injection capability due to holding the ohos.permission.CONTROL_DEVICE permission.
 *
 * @param status Injection permission authorization status of the current application. See
 *     {@link Input_InjectionStatus}.
 * @return Return value. For details, see {@link Input_Result}.
 *     <br>INPUT_SUCCESS = 0: Operation success.
 *     <br>INPUT_PARAMETER_ERROR = 401: Parameter error. The status parameter is empty.
 *     <br>INPUT_SERVICE_EXCEPTION = 3800001: Service error.
 * @since 20
 */
Input_Result OH_Input_QueryAuthorizedStatus(Input_InjectionStatus* status);

/**
 * @brief Obtains the coordinates of the mouse pointer on the current screen.
 * <br>Since API version 26.0.0, non-focused applications that have the ohos.permission.INPUT_DEVICE_CONFIGURATOR
 * permission can call this API.
 *
 * @param displayId Screen ID of the current screen.
 * @param displayX X coordinate of the mouse on the current screen, in pixels (px).
 * @param displayY Y coordinate of the mouse on the current screen, in pixels (px).
 * @return Return value of the **GetPointerLocation** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter is incorrect;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if a service exception occurs;
 *     <br>{@link INPUT_APP_NOT_FOCUSED} if the current application is not in focus;
 *     <br>{@link INPUT_DEVICE_NO_POINTER} if no mouse device is available.
 * @since 20
 */
Input_Result OH_Input_GetPointerLocation(int32_t *displayId, double *displayX, double *displayY);

/**
 * @brief Sets the visible status of the mouse pointer in the current window.
 *
 * @param visible Whether the mouse pointer is visible. The value **true** indicates that the mouse pointer is visible,
 *     and the value **false** indicates the opposite.
 * @return Return value of the **OH_Input_SetPointerVisible** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_DEVICE_NOT_SUPPORTED} if the device is not supported;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 22
 */
Input_Result OH_Input_SetPointerVisible(bool visible);

/**
 * @brief Gets the mouse cursor style of a specified window. This API only supports getting the mouse cursor style of
 * windows within the current application process.
 *
 * @param windowId Window ID. The value is an integer greater than or equal to **-1**. The value **-1** indicates the
 *     global window.
 *     <br>Only the ID of the current window or global window can be specified. If any other ID is specified, the
 *     default pointer style of the global window is returned. You can obtain the ID of the current window through
 *     {@link getWindowProperties}.
 * @param pointerStyle Mouse cursor style, which is an enum value of {@link Input_PointerStyle}.
 * @return Return value of the **OH_Input_GetPointerStyle** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 22
 */
Input_Result OH_Input_GetPointerStyle(int32_t windowId, int32_t *pointerStyle);

/**
 * @brief Sets the mouse cursor style for a specified window. This API only supports setting the mouse cursor style for
 * windows within the current application process.
 *
 * @param windowId Window ID. The value is an integer greater than or equal to 0.
 *     <br>Only the ID of the current window can be specified. If any other ID is specified, the API call is successful,
 *     but the setting does not take effect. You can obtain the ID of the current window through
 *     {@link getWindowProperties}.
 * @param pointerStyle Mouse pointer style. The value is an enumerated value of {@link Input_PointerStyle}.
 * @return Return value of the **OH_Input_SetPointerStyle** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 22
 */
Input_Result OH_Input_SetPointerStyle(int32_t windowId, int32_t pointerStyle);

/**
 * @brief Creates a custom mouse pointer object. You can call {@link OH_Input_CustomCursor_Destroy()} to destroy a
 * custom mouse pointer resource object.
 *
 * @param pixelMap Pixel map of the custom mouse pointer object. For details, see {@link OH_PixelmapNative}. The
 *     minimum value is the minimum size of the resource image. The maximum value is 256 x 256 px.
 * @param anchorX Horizontal coordinate of the custom mouse cursor focus. This coordinate is limited by the size of the
 *     custom mouse cursor. The minimum value is 0, and the maximum value is the maximum width of the resource image,
 *     in pixels (px).
 * @param anchorY Vertical coordinate of the custom mouse cursor focus. This coordinate is limited by the size of the
 *     custom mouse cursor. The minimum value is 0, and the maximum value is the maximum height of the resource image,
 *     in pixels (px).
 * @return {@link Input_CustomCursor} object. The pointer to the custom mouse pointer object is returned if the
 *     operation is successful, and a null pointer is returned if an exception occurs.
 * @since 22
 */
Input_CustomCursor* OH_Input_CustomCursor_Create(OH_PixelmapNative* pixelMap, int32_t anchorX, int32_t anchorY);

/**
 * @brief Destroys a custom mouse pointer object.
 *
 * @param customCursor Custom mouse pointer object. For details, see {@link Input_CustomCursor}.
 * @since 22
 */
void OH_Input_CustomCursor_Destroy(Input_CustomCursor** customCursor);

/**
 * @brief Obtains the pixel map of a custom mouse pointer object.
 *
 * @param customCursor Custom mouse pointer object. For details, see {@link Input_CustomCursor}.
 * @param pixelMap Pixel map of the custom mouse pointer object. For details, see {@link OH_PixelmapNative}.
 * @return Return value of the **OH_Input_CustomCursor_GetPixelMap** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 22
 */
Input_Result OH_Input_CustomCursor_GetPixelMap(Input_CustomCursor* customCursor, OH_PixelmapNative** pixelMap);

/**
 * @brief Obtains the focus coordinates of a custom mouse pointer object.
 *
 * @param customCursor Custom mouse pointer object. For details, see {@link Input_CustomCursor}.
 * @param anchorX Horizontal coordinate of the focus point of the custom mouse cursor resource, in pixels (px).
 * @param anchorY Vertical coordinate of the focus point of the custom mouse cursor resource, in pixels (px).
 * @return Return value of the **OH_Input_CustomCursor_GetAnchor** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 22
 */
Input_Result OH_Input_CustomCursor_GetAnchor(Input_CustomCursor* customCursor, int32_t* anchorX, int32_t* anchorY);

/**
 * @brief Creates a custom mouse pointer configuration object. You can call {@link OH_Input_CursorConfig_Destroy()} to
 * destroy a custom mouse pointer configuration object.
 *
 * @param followSystem Whether to adjust the mouse cursor size based on system settings. false means using the custom
 *     mouse cursor style size, true means adjusting the mouse cursor size based on system settings. The adjustable
 *     range is: [cursor resource image size, 256×256], in pixels (px).
 * @return Custom mouse pointer configuration object. For details, see {@link Input_CursorConfig}.
 * @since 22
 */
Input_CursorConfig* OH_Input_CursorConfig_Create(bool followSystem);

/**
 * @brief Destroys a custom mouse pointer configuration object.
 *
 * @param cursorConfig Custom mouse pointer configuration object. For details, see {@link Input_CursorConfig}.
 * @since 22
 */
void OH_Input_CursorConfig_Destroy(Input_CursorConfig** cursorConfig);

/**
 * @brief Queries whether the custom mouse pointer configuration follows the system setting to adjust the pointer size.
 *
 * @param cursorConfig Custom mouse pointer configuration object. For details, see {@link Input_CursorConfig}.
 * @param followSystem Whether to adjust the pointer size based on the system setting. The value **true** means to
 *     adjust the pointer size based on the system setting, and the value **false** means to use the size of custom
 *     mouse pointer.
 * @return Return value of the **OH_Input_CursorConfig_IsFollowSystem** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 22
 */
Input_Result OH_Input_CursorConfig_IsFollowSystem(Input_CursorConfig *cursorConfig, bool *followSystem);

/**
 * @brief Sets the custom mouse pointer style.
 * <br>The cursor may revert to the system style in the following scenarios: application window layout changes, hotspot
 * switching, page navigation, the cursor leaving and re-entering the window, or the cursor moving between different
 * areas of the window. In these cases, the developer needs to set the cursor style again. This API only supports
 * setting the custom mouse cursor style for windows within the current application process.
 *
 * @param windowId Window ID. The value must be an integer greater than or equal to **0**. Only the pointer style of
 *     the current window can be specified.
 * @param customCursor Custom mouse pointer object. For details, see {@link Input_CustomCursor}.
 * @param cursorConfig Custom mouse pointer configuration object. For details, see {@link Input_CursorConfig}.
 * @return Return value of the **OH_Input_SetCustomCursor** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_INVALID_WINDOWID} if the window ID is invalid;
 *     <br>{@link INPUT_DEVICE_NOT_SUPPORTED} if the device is not supported;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 22
 */
Input_Result OH_Input_SetCustomCursor(int32_t windowId, Input_CustomCursor* customCursor,
                                      Input_CursorConfig* cursorConfig);

/**
 * @brief Creates a mouse pointer information object. You can call {@link OH_Input_CursorInfo_Destroy()} to destroy a
 * mouse pointer information object.
 *
 * @return An {@link Input_CursorInfo} object if the operation is successful; a null pointer otherwise (possibly
 *     because of a memory allocation failure).
 * @since 22
 */
struct Input_CursorInfo* OH_Input_CursorInfo_Create();

/**
 * @brief Destroys the mouse pointer information object.
 *
 * @param cursorInfo Mouse pointer information object.
 * @since 22
 */
void OH_Input_CursorInfo_Destroy(Input_CursorInfo** cursorInfo);

/**
 * @brief Obtains the pointer visible status of the specified mouse pointer information object.
 *
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_GetMouseEventCursorInfo()} to query
 *     the mouse pointer information of a specified mouse event, or call {@link OH_Input_GetCursorInfo()} to query the
 *     current mouse pointer information.
 * @param visible Visible status of the mouse pointer. The value **true** indicates that the mouse pointer is visible,
 *     and the value **false** indicates the opposite.
 * @return Return value of the **OH_Input_CursorInfo_IsVisible** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 22
 */
Input_Result OH_Input_CursorInfo_IsVisible(Input_CursorInfo* cursorInfo, bool* visible);

/**
 * @brief Obtains the pointer style of the specified mouse pointer information object.
 *
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_GetMouseEventCursorInfo()} to query
 *     the mouse pointer information of a specified mouse event, or call {@link OH_Input_GetCursorInfo()} to query the
 *     current mouse pointer information.
 * @param style Cursor style of the cursorInfo.
 * @return Return value of the **OH_Input_CursorInfo_GetStyle** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails or the pointer is invisible.
 * @since 22
 */
Input_Result OH_Input_CursorInfo_GetStyle(Input_CursorInfo* cursorInfo, Input_PointerStyle* style);

/**
 * @brief Obtains the pointer size level of the specified mouse pointer information object.
 *
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_GetMouseEventCursorInfo()} to query
 *     the mouse pointer information of a specified mouse event, or call {@link OH_Input_GetCursorInfo()} to query the
 *     current mouse pointer information.
 * @param sizeLevel Pointer size level of the mouse pointer information object. The value is an integer ranging from 1
 *     to 7. A larger value indicates a higher pointer size level. The size of the custom pointer
 *     {@link DEVELOPER_DEFINED_ICON} is subject to the actual bitmap size.
 * @return Return value of the **OH_Input_CursorInfo_GetSizeLevel** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails or the pointer is invisible.
 * @since 22
 */
Input_Result OH_Input_CursorInfo_GetSizeLevel(Input_CursorInfo* cursorInfo, int32_t* sizeLevel);

/**
 * @brief Gets the cursor color corresponding to a specified mouse cursor info object, represented as a 32-bit ARGB
 * integer.
 *
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_GetMouseEventCursorInfo()} to query
 *     the mouse pointer information of a specified mouse event, or call {@link OH_Input_GetCursorInfo()} to query the
 *     current mouse pointer information.
 * @param color Cursor color of the mouse cursor info, represented by a 32-bit ARGB integer. For application-defined
 *     custom cursors {@link DEVELOPER_DEFINED_ICON}, the actual bitmap color shall prevail.
 * @return Return value of the **OH_Input_CursorInfo_GetColor** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails or the pointer is invisible.
 * @since 22
 */
Input_Result OH_Input_CursorInfo_GetColor(Input_CursorInfo* cursorInfo, uint32_t* color);

/**
 * @brief Obtains the mouse pointer information of the mouse event, including the pointer visible status, pointer style,
 * pointer size level, and pointer color.
 *
 * @param mouseEvent Mouse event object. You can obtain the mouse event object from the callback of
 *     {@link OH_Input_AddMouseEventMonitor()} or {@link OH_Input_AddInputEventInterceptor()}.
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_CursorInfo_Create()} to create a
 *     mouse pointer information object.
 * @return Return value of the **OH_Input_GetMouseEventCursorInfo** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails.
 * @since 22
 */
Input_Result OH_Input_GetMouseEventCursorInfo(const struct Input_MouseEvent* mouseEvent, Input_CursorInfo* cursorInfo);

/**
 * @brief Obtains the mouse pointer information, including the pointer visible status, pointer style, pointer size
 * level, and pointer color. If the **pixelmap** parameter is not empty and the pointer style is
 * {@link DEVELOPER_DEFINED_ICON}, the **PixelMap** object of the pointer is returned.
 *
 * @param cursorInfo Mouse pointer information object. You can call {@link OH_Input_CursorInfo_Create()} to create a
 *     mouse pointer information object.
 * @param pixelmap **PixelMap** object. If this parameter is not empty and the pointer is a custom one, the **PixelMap**
 *     object of the pointer is returned. Otherwise, the **PixelMap** object is not returned. Firstly, create an **
 *     OH_PixelmapInitializationOptions** object through {@link OH_PixelmapInitializationOptions_Create}. Then, set the
 *     width to a value greater than **0** through {@link OH_PixelmapInitializationOptions_SetWidth}, set the height to
 *     a value greater than **0** through {@link OH_PixelmapInitializationOptions_SetHeight}. Finally, create a **
 *     PixelMap** object by calling {@link OH_PixelmapNative_CreateEmptyPixelmap} with the **
 *     OH_PixelmapInitializationOptions** object passed in.
 *     <br>When the **PixelMap** object is no longer needed, you need to call {@link OH_PixelmapNative_Release} to
 *     release the object and then call {@link OH_PixelmapNative_Destroy} to destroy it.
 * @return Return value of the **OH_Input_GetCursorInfo** function.
 *     <br>{@link INPUT_SUCCESS} if the operation is successful;
 *     <br>{@link INPUT_PARAMETER_ERROR} if the parameter verification fails;
 *     <br>{@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @since 22
 */
Input_Result OH_Input_GetCursorInfo(Input_CursorInfo* cursorInfo, OH_PixelmapNative** pixelmap);

/**
 * @brief Binds a specified input device to a specified screen.
 *
 * @permission ohos.permission.INPUT_DEVICE_CONFIGURATOR
 * @param inputDeviceId ID of the input device.
 * @param displayId ID of the screen.
 * @return Return values of the OH_Input_BindInputDeviceToDisplay function:
 *     <br>{@link INPUT_SUCCESS} indicates that the operation is successful.
 *     <br>{@link INPUT_PERMISSION_DENIED} indicates that the permission verification fails.
 *     <br>{@link INPUT_PARAMETER_ERROR} indicates that the parameter check fails (the input device does not exist, the
 *     display device does not exist, or the input device is not a stylus device).
 *     <br>{@link INPUT_SERVICE_EXCEPTION} indicates that the service is abnormal. Try again.
 * @since 26.0.0
 */
Input_Result OH_Input_BindInputDeviceToDisplay(int32_t inputDeviceId, int32_t displayId);
#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OH_INPUT_MANAGER_H */
