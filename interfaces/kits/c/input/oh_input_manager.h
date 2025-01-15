/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_INPUT_MANAGER_H
#define OH_INPUT_MANAGER_H

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
 * @brief Provides capabilities such as event injection and key status query.
 *
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @library liboh_input.so
 * @since 12
 */

#include <stdint.h>

#include "oh_axis_type.h"
#include "oh_key_code.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerated values of key event action.
 *
 * @since 12
 */
typedef enum Input_KeyStateAction {
    /** Default */
    KEY_DEFAULT = -1,
    /** Pressing of a key */
    KEY_PRESSED = 0,
    /** Release of a key */
    KEY_RELEASED = 1,
    /** Key switch enabled */
    KEY_SWITCH_ON = 2,
    /** Key switch disabled */
    KEY_SWITCH_OFF = 3
} Input_KeyStateAction;

/**
 * @brief Enumerates key event types.
 *
 * @since 12
 */
typedef enum Input_KeyEventAction {
    /** Cancellation of a key action. */
    KEY_ACTION_CANCEL = 0,
    /** Pressing of a key. */
    KEY_ACTION_DOWN = 1,
    /** Release of a key. */
    KEY_ACTION_UP = 2,
} Input_KeyEventAction;

/**
 * @brief Enumerated values of mouse event action.
 *
 * @since 12
 */
typedef enum Input_MouseEventAction {
    /** Cancel. */
    MOUSE_ACTION_CANCEL = 0,
    /** Moving of the mouse pointer. */
    MOUSE_ACTION_MOVE = 1,
    /** Pressing down of the mouse. */
    MOUSE_ACTION_BUTTON_DOWN = 2,
    /** Lifting of the mouse button. */
    MOUSE_ACTION_BUTTON_UP = 3,
    /** Beginning of the mouse axis event */
    MOUSE_ACTION_AXIS_BEGIN = 4,
    /** Updating of the mouse axis event */
    MOUSE_ACTION_AXIS_UPDATE = 5,
    /** End of the mouse axis event */
    MOUSE_ACTION_AXIS_END = 6,
} Input_MouseEventAction;

/**
 * @brief Mouse axis types.
 *
 * @since 12
 */
typedef enum InputEvent_MouseAxis {
    /** Vertical scroll axis */
    MOUSE_AXIS_SCROLL_VERTICAL = 0,
    /** Horizontal scroll axis */
    MOUSE_AXIS_SCROLL_HORIZONTAL = 1,
} InputEvent_MouseAxis;

/**
 * @brief Enumerated values of mouse event button.
 *
 * @since 12
 */
typedef enum Input_MouseEventButton {
    /** Invalid button */
    MOUSE_BUTTON_NONE = -1,
    /** Left button on the mouse. */
    MOUSE_BUTTON_LEFT = 0,
    /** Middle button on the mouse. */
    MOUSE_BUTTON_MIDDLE = 1,
    /** Right button on the mouse. */
    MOUSE_BUTTON_RIGHT = 2,
    /** Forward button on the mouse. */
    MOUSE_BUTTON_FORWARD = 3,
    /** Back button on the mouse. */
    MOUSE_BUTTON_BACK = 4,
} Input_MouseEventButton;

/**
 * @brief Enumerated values of touch event action.
 *
 * @since 12
 */
typedef enum Input_TouchEventAction {
    /** Touch cancelled. */
    TOUCH_ACTION_CANCEL = 0,
    /** Touch pressed. */
    TOUCH_ACTION_DOWN = 1,
    /** Touch moved. */
    TOUCH_ACTION_MOVE = 2,
    /** Touch lifted. */
    TOUCH_ACTION_UP = 3,
} Input_TouchEventAction;

/**
 * @brief Enumerates event source types.
 *
 * @since 12
 */
typedef enum InputEvent_SourceType {
    /**
     * Indicates that the input source generates events similar to mouse cursor movement,
     * button press and release, and wheel scrolling.
     *
     * @since 12
     */
    SOURCE_TYPE_MOUSE = 1,
    /**
     * Indicates that the input source generates a touchscreen multi-touch event.
     *
     * @since 12
     */
    SOURCE_TYPE_TOUCHSCREEN = 2,
    /**
     * Indicates that the input source generates a touchpad multi-touch event.
     *
     * @since 12
     */
    SOURCE_TYPE_TOUCHPAD = 3
} InputEvent_SourceType;

/**
 * @brief Enumerates keyboard types.
 *
 * @since 13
 */
typedef enum Input_KeyboardType {
    /** Keyboard without keys */
    KEYBOARD_TYPE_NONE = 0,
    /** Keyboard with unknown keys */
    KEYBOARD_TYPE_UNKNOWN = 1,
    /** Full keyboard */
    KEYBOARD_TYPE_ALPHABETIC = 2,
    /** Digital keyboard */
    KEYBOARD_TYPE_DIGITAL = 3,
    /** Stylus */
    KEYBOARD_TYPE_STYLUS = 4,
    /** Remote control */
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
 * @brief The mouse event to be injected.
 *
 * @since 12
 */
typedef struct Input_MouseEvent Input_MouseEvent;

/**
 * @brief The touch event to be injected.
 *
 * @since 12
 */
typedef struct Input_TouchEvent Input_TouchEvent;

/**
 * @brief Enumerates axis events.
 *
 * @since 12
 */
typedef struct Input_AxisEvent Input_AxisEvent;

/**
 * @brief Enumerates error codes.
 *
 * @since 12
 */
typedef enum Input_Result {
    /** Success */
    INPUT_SUCCESS = 0,
    /** Permission verification failed */
    INPUT_PERMISSION_DENIED = 201,
    /** Non-system application */
    INPUT_NOT_SYSTEM_APPLICATION = 202,
    /** Parameter check failed */
    INPUT_PARAMETER_ERROR = 401,
    /**
     * @error Device not support
     * @since 14
     */
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    /** Service error */
    INPUT_SERVICE_EXCEPTION = 3800001,
    /** Interceptor repeatedly created for an application */
    INPUT_REPEAT_INTERCEPTOR = 4200001,
    /**
	 * @error Already occupied by the other
	 * @since 13
	 */
    INPUT_OCCUPIED_BY_OTHER = 4200003
} Input_Result;

/**
 * @brief Defines the hot key structure.
 *
 * @since 14
 */
typedef struct Input_Hotkey Input_Hotkey;

/**
 * @brief Defines a lifecycle callback for **keyEvent**.
 * If the callback is triggered, **keyEvent** will be destroyed.
 * @since 12
 */
typedef void (*Input_KeyEventCallback)(const Input_KeyEvent* keyEvent);

/**
 * @brief Defines a lifecycle callback for **mouseEvent**.
 * If the callback is triggered, **mouseEvent** will be destroyed.
 * @since 12
 */
typedef void (*Input_MouseEventCallback)(const Input_MouseEvent* mouseEvent);

/**
 * @brief Defines a lifecycle callback for **touchEvent**.
 * If the callback is triggered, **touchEvent** will be destroyed.
 * @since 12
 */
typedef void (*Input_TouchEventCallback)(const Input_TouchEvent* touchEvent);

/**
 * @brief Defines a lifecycle callback for **axisEvent**.
 * If the callback is triggered, **axisEvent** will be destroyed.
 * @since 12
 */
typedef void (*Input_AxisEventCallback)(const Input_AxisEvent* axisEvent);

typedef void (*Input_HotkeyCallback)(Input_Hotkey* hotkey);

/**
 * @brief Defines the callback for device addition events.
 * @param deviceId Device ID.
 * @since 13
 */
typedef void (*Input_DeviceAddedCallback)(int32_t deviceId);

/**
 * @brief Defines the callback for device removal events.
 * @param deviceId Device ID.
 * @since 13
 */
typedef void (*Input_DeviceRemovedCallback)(int32_t deviceId);

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
 * @brief Defines a listener for device insertion and removal events.
 * @since 13
 */
typedef struct Input_DeviceListener {
    /** Callback for device addition events */
    Input_DeviceAddedCallback deviceAddedCallback;
    /** Callback for device removal events */
    Input_DeviceRemovedCallback deviceRemovedCallback;
} Input_DeviceListener;

/**
 * @brief Defines event interceptor options.
 * @since 12
 */
typedef struct Input_InterceptorOptions Input_InterceptorOptions;

/**
 * @brief Represents information about the input device.
 *
 * @since 13
 */
typedef struct Input_DeviceInfo Input_DeviceInfo;

/**
 * @brief Queries the key state.
 *
 * @param keyState Key state.
 * @HTTP4O4 Returns {@Link Input_Result#INPUT_SUCCESS} if the operation is successful;
 * returns an error code defined in {@Link Input_Result} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState);

/**
 * @brief Creates a key status enumeration object.
 *
 * @return Returns an {@link Input_KeyState} pointer object if the operation is successful.
 * returns a null pointer otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_KeyState* OH_Input_CreateKeyState();

/**
 * @brief Destroys a key status enumeration object.
 *
 * @param keyState Key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyKeyState(struct Input_KeyState** keyState);

/**
 * @brief Sets the key value of a key status enumeration object.
 *
 * @param keyState Key status enumeration object.
 * @param keyCode Key value of the key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyCode(struct Input_KeyState* keyState, int32_t keyCode);

/**
 * @brief Obtains the key value of a key status enumeration object.
 *
 * @param keyState Key status enumeration object.
 * @return Key value of the key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyCode(const struct Input_KeyState* keyState);

/**
 * @brief Sets whether the key specific to a key status enumeration object is pressed.
 *
 * @param keyState Key status enumeration object.
 * @param keyAction Whether the key is pressed.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyPressed(struct Input_KeyState* keyState, int32_t keyAction);

/**
 * @brief Checks whether the key specific to a key status enumeration object is pressed.
 *
 * @param keyState Key status enumeration object.
 * @return Key pressing status of the key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyPressed(const struct Input_KeyState* keyState);

/**
 * @brief Sets the key switch of the key status enumeration object.
 *
 * @param keyState Key status enumeration object.
 * @param keySwitch Key switch of the key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeySwitch(struct Input_KeyState* keyState, int32_t keySwitch);

/**
 * @brief Obtains the key switch of the key status enumeration object.
 *
 * @param keyState Key status enumeration object.
 * @return Key switch of the key status enumeration object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeySwitch(const struct Input_KeyState* keyState);

/**
 * @brief Inject system keys.
 *
 * @param keyEvent - the key event to be injected.
 * @return 0 - Success.
 *         201 - Missing permissions.
 *         401 - Parameter error.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_InjectKeyEvent(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Creates a key event object.
 *
 * @return Returns an {@link Input_KeyEvent} pointer object if the operation is successful.
 * returns a null pointer otherwise.
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
 * @param keyEvent Key event object.
 * @param action Key event type.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventAction(struct Input_KeyEvent* keyEvent, int32_t action);

/**
 * @brief Obtains the key event type.
 *
 * @param keyEvent Key event object.
 * @return Key event type.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyEventAction(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the key value for a key event.
 *
 * @param keyEvent Key event object.
 * @param keyCode keyCode Key code.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventKeyCode(struct Input_KeyEvent* keyEvent, int32_t keyCode);

/**
 * @brief Obtains the key value of a key event.
 *
 * @param keyEvent Key event object.
 * @return Key code.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetKeyEventKeyCode(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Sets the time when a key event occurs.
 *
 * @param keyEvent Key event object.
 * @param actionTime Time when the key event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetKeyEventActionTime(struct Input_KeyEvent* keyEvent, int64_t actionTime);

/**
 * @brief Obtains the time when a key event occurs.
 *
 * @param keyEvent Key event object.
 * @return Returns the time when the key event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetKeyEventActionTime(const struct Input_KeyEvent* keyEvent);

/**
 * @brief Inject mouse event.
 *
 * @param mouseEvent - the mouse event to be injected.
 * @return 0 - Success.
 *         201 - Missing permissions.
 *         401 - Parameter error.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_InjectMouseEvent(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Creates a mouse event object.
 *
 * @return Returns an {@link Input_MouseEvent} pointer object if the operation is successful.
 * returns a null pointer otherwise.
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
 * @param mouseEvent Mouse event object.
 * @param action Mouse action.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAction(struct Input_MouseEvent* mouseEvent, int32_t action);

/**
 * @brief Obtains the action of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return Mouse action.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventAction(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the X coordinate for a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @param displayX X coordinate on the display.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventDisplayX(struct Input_MouseEvent* mouseEvent, int32_t displayX);

/**
 * @brief Obtains the X coordinate of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return X coordinate on the display.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventDisplayX(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the Y coordinate for a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @param displayY Y coordinate on the display.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventDisplayY(struct Input_MouseEvent* mouseEvent, int32_t displayY);

/**
 * @brief Obtains the Y coordinate of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return Y coordinate on the display.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventDisplayY(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the button for a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @param button Mouse button.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventButton(struct Input_MouseEvent* mouseEvent, int32_t button);

/**
 * @brief Obtains the button of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return Mouse button.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventButton(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the axis type for mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @param axisType Axis type, for example, X axis or Y axis.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAxisType(struct Input_MouseEvent* mouseEvent, int32_t axisType);

/**
 * @brief Obtains the axis type of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return Axis type.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetMouseEventAxisType(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the axis value for a mouse axis event.
 *
 * @param mouseEvent Mouse event object.
 * @param axisType Axis value. A positive value means scrolling forward, and a negative number means scrolling backward.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventAxisValue(struct Input_MouseEvent* mouseEvent, float axisValue);

/**
 * @brief Obtains the axis value of a mouse event.
 *
 * @param mouseEvent Mouse event object.
 * @return Axis value.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
float OH_Input_GetMouseEventAxisValue(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Sets the time when a mouse event occurs.
 *
 * @param mouseEvent Mouse event object.
 * @param actionTime Time when the mouse event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetMouseEventActionTime(struct Input_MouseEvent* mouseEvent, int64_t actionTime);

/**
 * @brief Obtains the time when a mouse event occurs.
 *
 * @param keyEvent Mouse event object.
 * @return Returns the time when the mouse event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetMouseEventActionTime(const struct Input_MouseEvent* mouseEvent);

/**
 * @brief Inject touch event.
 *
 * @param touchEvent - the touch event to be injected.
 * @return 0 - Success.
 *         201 - Missing permissions.
 *         401 - Parameter error.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_InjectTouchEvent(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Creates a touch event object.
 *
 * @return Returns an {@link Input_TouchEvent} pointer object if the operation is successful.
 * returns a null pointer otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
struct Input_TouchEvent* OH_Input_CreateTouchEvent();

/**
 * @brief Destroys a touch event object.
 *
 * @param touchEvent Touch event object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_DestroyTouchEvent(struct Input_TouchEvent** touchEvent);

/**
 * @brief Sets the action for a touch event.
 *
 * @param touchEvent Touch event object.
 * @param action Touch action.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventAction(struct Input_TouchEvent* touchEvent, int32_t action);

/**
 * @brief Obtains the action of a touch event.
 *
 * @param touchEvent Touch event object.
 * @return Touch action.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventAction(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the finger ID for the touch event.
 *
 * @param touchEvent Touch event object.
 * @param id Finger ID.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventFingerId(struct Input_TouchEvent* touchEvent, int32_t id);

/**
 * @brief Obtains the finger ID of a touch event.
 *
 * @param touchEvent Touch event object.
 * @return Finger ID.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventFingerId(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the X coordinate for a touch event.
 *
 * @param touchEvent Touch event object.
 * @param displayX X coordinate.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventDisplayX(struct Input_TouchEvent* touchEvent, int32_t displayX);

/**
 * @brief Obtains the X coordinate of a touch event.
 *
 * @param touchEvent Touch event object.
 * @return X coordinate.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventDisplayX(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the Y coordinate for a touch event.
 *
 * @param touchEvent Touch event object.
 * @param displayY Y coordinate.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventDisplayY(struct Input_TouchEvent* touchEvent, int32_t displayY);

/**
 * @brief Obtains the Y coordinate of a touch event.
 *
 * @param touchEvent Touch event object.
 * @return Y coordinate.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int32_t OH_Input_GetTouchEventDisplayY(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Sets the time when a touch event occurs.
 *
 * @param keyEvent Touch event object.
 * @param actionTime Time when the touch event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_SetTouchEventActionTime(struct Input_TouchEvent* touchEvent, int64_t actionTime);

/**
 * @brief Obtains the time when a touch event occurs.
 *
 * @param keyEvent touch event object.
 * @return Returns the time when the touch event occurs.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
int64_t OH_Input_GetTouchEventActionTime(const struct Input_TouchEvent* touchEvent);

/**
 * @brief Cancels event injection and revokes authorization.
 *
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
void OH_Input_CancelInjection();

/**
 * @brief Creates an axis event object.
 *
 * @return If the operation is successful, a {@Link Input_AxisEvent} object is returned.
 * If the operation fails, null is returned.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_AxisEvent* OH_Input_CreateAxisEvent(void);

/**
 * @brief Destroys an axis event object.
 * 
 * @param axisEvent Pointer to the axis event object.
 * @return OH_Input_DestroyAxisEvent function result code.
 *         {@link INPUT_SUCCESS} Destroys axisEvent success.\n
 *         {@link INPUT_PARAMETER_ERROR}The axisEvent is NULL or the *axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_DestroyAxisEvent(Input_AxisEvent** axisEvent);

/**
 * @brief Sets the axis event action.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param action Axis event action. The values are defined in {@link InputEvent_AxisAction}.
 * @return OH_Input_SetAxisEventAction function result code.
 *         {@link INPUT_SUCCESS} Sets the axis event action success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventAction(Input_AxisEvent* axisEvent, InputEvent_AxisAction action);

/**
 * @brief Obtains the axis event action.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param action Axis event action. The values are defined in {@link InputEvent_AxisAction}.
 * @return OH_Input_GetAxisEventAction function result code.
 *         {@link INPUT_SUCCESS} Obtains the axis event action success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the action is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventAction(const Input_AxisEvent* axisEvent, InputEvent_AxisAction *action);

/**
 * @brief Sets the X coordinate of an axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param displayX X coordinate of the axis event.
 * @return OH_Input_SetAxisEventDisplayX function result code.
 *         {@link INPUT_SUCCESS} Sets the X coordinate of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventDisplayX(Input_AxisEvent* axisEvent, float displayX);

/**
 * @brief Obtains the X coordinate of an axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param displayX X coordinate of the axis event.
 * @return OH_Input_GetAxisEventDisplayX function result code.
 *         {@link INPUT_SUCCESS} Obtains the X coordinate of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the displayX is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventDisplayX(const Input_AxisEvent* axisEvent, float* displayX);

/**
 * @brief Sets the Y coordinate of an axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param displayY Y coordinate of the axis event.
 * @return OH_Input_SetAxisEventDisplayY function result code.
 *         {@link INPUT_SUCCESS} Sets the Y coordinate of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventDisplayY(Input_AxisEvent* axisEvent, float displayY);

/**
 * @brief Obtains the Y coordinate of an axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param displayY Y coordinate of the axis event.
 * @return OH_Input_GetAxisEventDisplayY function result code.
 *         {@link INPUT_SUCCESS} Obtains the Y coordinate of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the displayY is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventDisplayY(const Input_AxisEvent* axisEvent, float* displayY);

/**
 * @brief Sets the axis value of the axis type specified by the axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param axisType Axis type. The values are defined in {@link InputEvent_AxisType}.
 * @param axisValue Axis value.
 * @return OH_Input_SetAxisEventAxisValue function result code.
 *         {@link INPUT_SUCCESS} Sets the axis value of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventAxisValue(Input_AxisEvent* axisEvent,
                                            InputEvent_AxisType axisType, double axisValue);

/**
 * @brief Obtains the axis value for the specified axis type of the axis event.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param axisType Axis type. The values are defined in {@link InputEvent_AxisType}.
 * @param axisValue Axis value.
 * @return OH_Input_GetAxisEventAxisValue function result code.
 *         {@link INPUT_SUCCESS} Obtains the axis value of the axis event success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the axisValue is NULL,
 *         or the axisType not found in the axisEvent.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventAxisValue(const Input_AxisEvent* axisEvent,
                                            InputEvent_AxisType axisType, double* axisValue);

/**
 * @brief Sets the time when an axis event occurs.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param actionTime Time when an axis event occurs.
 * @return OH_Input_SetAxisEventActionTime function result code.
 *         {@link INPUT_SUCCESS} Sets the time when an axis event occurs success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventActionTime(Input_AxisEvent* axisEvent, int64_t actionTime);

/**
 * @brief Obtains the time when an axis event occurs.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param actionTime Time when an axis event occurs.
 * @return OH_Input_GetAxisEventActionTime function result code.
 *         {@link INPUT_SUCCESS} Obtains the time when an axis event occurs success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the actionTime is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventActionTime(const Input_AxisEvent* axisEvent, int64_t* actionTime);

/**
 * @brief Sets the axis event type.
 *
 * @param axisEvent Axis event object. For details, see {@Link Input_AxisEvent}.
 * @param axisEventType Axis event type. The values are defined in {@link InputEvent_AxisEventType}.
 * @return OH_Input_SetAxisEventType function result code.
 *         {@link INPUT_SUCCESS} Sets the axis event type success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventType(Input_AxisEvent* axisEvent, InputEvent_AxisEventType axisEventType);

/**
 * @brief Obtains the axis event type.
 *
 * @param axisEvent Axis event object.
 * @param axisEventType Axis event type. The values are defined in {@link InputEvent_AxisEventType}.
 * @return OH_Input_GetAxisEventType function result code.
 *         {@link INPUT_SUCCESS} Obtains the axis event type success.\n
 *         {@Link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the axisEventType is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventType(const Input_AxisEvent* axisEvent, InputEvent_AxisEventType* axisEventType);

/**
 * @brief Sets the axis event source type.
 *
 * @param axisEvent Axis event object.
 * @param sourceType Axis event source type. The values are defined in {@link InputEvent_SourceType}.
 * @return OH_Input_SetAxisEventSourceType function result code.
 *         {@link INPUT_SUCCESS} Sets the axis event source type success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_SetAxisEventSourceType(Input_AxisEvent* axisEvent, InputEvent_SourceType sourceType);

/**
 * @brief Obtains the axis event source type.
 *
 * @param axisEvent Axis event object.
 * @param axisEventType Axis event source type. The values are defined in {@link InputEvent_SourceType}.
 * @return OH_Input_GetAxisEventSourceType function result code.
 *         {@link INPUT_SUCCESS} Obtains the axis event source type success.\n
 *         {@link INPUT_PARAMETER_ERROR} The axisEvent is NULL or the sourceType is NULL.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_GetAxisEventSourceType(const Input_AxisEvent* axisEvent, InputEvent_SourceType* sourceType);

/**
 * @brief Adds a listener of key events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback used to receive key events.
 * @return OH_Input_AddKeyEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Adds a listener of key events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddKeyEventMonitor(Input_KeyEventCallback callback);

/**
 * @brief Adds a listener for mouse events, including mouse click and movement events,
 * but not scroll wheel events. Scroll wheel events are axis events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback used to receive mouse events.
 * @return OH_Input_AddMouseEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Adds a listener of mouse events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddMouseEventMonitor(Input_MouseEventCallback callback);

/**
 * @brief Add a listener for touch events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback used to receive touch events.
 * @return OH_Input_AddTouchEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Adds a listener of touch events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddTouchEventMonitor(Input_TouchEventCallback callback);

/**
 * @brief Adds a listener for all types of axis events.
 * The axis event types are defined in {@Link InputEvent_AxisEventType}.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback used to receive axis events.
 * @return OH_Input_AddAxisEventMonitorForAll function result code.
 *         {@link INPUT_SUCCESS} Adds a listener for all types of axis events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddAxisEventMonitorForAll(Input_AxisEventCallback callback);

/**
 * @brief Adds a listener for the specified type of axis events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param axisEventType - Axis event type. The values are defined in {@Link InputEvent_AxisEventType}.
 * @param callback - Callback used to receive the specified type of axis events.
 * @return OH_Input_AddAxisEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Adds a listener for the specified types of axis events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback);

/**
 * @brief Removes a key event listener.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback for the key event listener.
 * @return OH_Input_RemoveKeyEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Removes a key event listener success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL or has not been added.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Fail to remove the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveKeyEventMonitor(Input_KeyEventCallback callback);

/**
 * @brief Removes a mouse event listener.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback for the mouse event listener.
 * @return OH_Input_RemoveMouseEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Removes a mouse event listener success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL or has not been added.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Fail to remove the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveMouseEventMonitor(Input_MouseEventCallback callback);

/**
 * @brief Removes a touch event listener.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback for the touch event listener.
 * @return OH_Input_RemoveTouchEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Removes a touch event listener success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL or has not been added.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Fail to remove the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveTouchEventMonitor(Input_TouchEventCallback callback);

/**
 * @brief Removes the listener for all types of axis events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param callback - Callback for the listener used to listen for all types of axis events.
 * @return OH_Input_RemoveAxisEventMonitorForAll function result code.
 *         {@link INPUT_SUCCESS} Removes the listener for all types of axis events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL or has not been added.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Fail to remove the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveAxisEventMonitorForAll(Input_AxisEventCallback callback);

/**
 * @brief Removes the listener for the specified type of axis events.
 *
 * @permission ohos.permission.INPUT_MONITORING
 * @param axisEventType - Axis event type. The axis event type is defined in {@Link InputEvent_AxisEventType}.
 * @param callback - Callback for the listener used to listen for the specified type of axis events.
 * @return OH_Input_RemoveAxisEventMonitor function result code.
 *         {@link INPUT_SUCCESS} Removes the listener for the specified type of axis events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL or has not been added.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Fail to remove the monitor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback);

/**
 * @brief Adds a key event interceptor. If multiple interceptors are added, only the first one takes effect.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @param callback - Callback used to receive key events.
 * @param option - Options for event interception. If **null** is passed, the default value is used.
 * @return OH_Input_AddKeyEventInterceptor function result code.
 *         {@link INPUT_SUCCESS} Adds a key event interceptor success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_REPEAT_INTERCEPTOR} Interceptor repeatedly created for an application.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the interceptor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddKeyEventInterceptor(Input_KeyEventCallback callback, Input_InterceptorOptions *option);

/**
 * @brief Adds an interceptor for input events, including mouse, touch, and axis events.
 * If multiple interceptors are added, only the first one takes effect.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @param callback - Pointer to the structure of the callback for the input event interceptor.
 * For details, see {@Link Input_InterceptorEventCallback}.
 * @param option - Options for event interception. If **null** is passed, the default value is used.
 * @return OH_Input_AddInputEventInterceptor function result code.
 *         {@link INPUT_SUCCESS} Adds an interceptor for input events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_PARAMETER_ERROR} The callback is NULL.\n
 *         {@link INPUT_REPEAT_INTERCEPTOR} Interceptor repeatedly created for an application.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to add the interceptor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_AddInputEventInterceptor(Input_InterceptorEventCallback *callback,
                                               Input_InterceptorOptions *option);

/**
 * @brief Removes a key event interceptor.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @return OH_Input_RemoveKeyEventInterceptor function result code.
 *         {@link INPUT_SUCCESS}Removes a key event interceptor success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to remove the interceptor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveKeyEventInterceptor(void);

/**
 * @brief Removes an interceptor for input events, including mouse, touch, and axis events.
 *
 * @permission ohos.permission.INTERCEPT_INPUT_EVENT
 * @return OH_Input_RemoveInputEventInterceptor function result code.
 *         {@link INPUT_SUCCESS} Removes an interceptor for input events success.\n
 *         {@link INPUT_PERMISSION_DENIED} Permission verification failed.\n
 *         {@link INPUT_SERVICE_EXCEPTION} Failed to remove the interceptor because the service is exception.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 12
 */
Input_Result OH_Input_RemoveInputEventInterceptor(void);

/**
 * @brief Creates a hot key object.
 *
 * @return Returns an {@Link Input_Hotkey} pointer object if the operation is successful. Otherwise, a null pointer is
 * returned. The possible cause is memory allocation failure.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Hotkey *OH_Input_CreateHotkey(void);

/**
 * @brief Destroys a hot key object.
 *
 * @param hotkey Hot key object.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_DestroyHotkey(Input_Hotkey **hotkey);

/**
 * @brief Sets a modifier key.
 *
 * @param hotkey Hotkey key object.
 * @param preKeys List of modifier keys.
 * @param size Number of modifier keys. One or two modifier keys are supported.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetPreKeys(Input_Hotkey *hotkey, int32_t *preKeys, int32_t size);

/**
 * @brief Obtains a modifier key.
 *
 * @param hotkey Hotkey key object.
 * @param preKeys List of modifier keys.
 * @param preKeyCount Number of modifier keys.
 * @return OH_Input_GetPreKeys status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} The hotkey is NULL or the pressedKeys is NULL or the pressedKeyCount
 *         is NULL;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetPreKeys(const Input_Hotkey *hotkey, int32_t **preKeys, int32_t *preKeyCount);

/**
 * @brief Sets a modified key.
 *
 * @param hotkey Hotkey key object.
 * @param finalKey Modified key. Only one modified key is supported.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetFinalKey(Input_Hotkey *hotkey, int32_t finalKey);

/**
 * @brief Obtains a modified key.
 *
 * @param hotkey Hotkey key object.
 * @param finalKeyCode Returns the key value of the decorated key.
 * @return OH_Input_GetfinalKey status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} The hotkey is NULL or the finalKeyCode is NULL;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetFinalKey(const Input_Hotkey *hotkey, int32_t *finalKeyCode);

/**
 * @brief Creates an array of {@Link Input_Hotkey} instances.
 *
 * @param count Number of {@Link Input_Hotkey} instances to be created. The count must be the same as the number of
 * system shortcut keys.
 * @return If the operation is successful, the pointer to an array of {@Link Input_Hotkey} instances is returned.
 * If the operation fails, a null pointer is returned. The possible cause is memory allocation failure or count is
 * not equal to the number of system hotkeys.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Hotkey **OH_Input_CreateAllSystemHotkeys(int32_t count);

/**
 * @brief Destroys an array of {@link Input_Hotkey} instances and reclaims memory.
 *
 * @param hotkeys Pointer to an array of {@Link Input_Hotkey } instances created by the
 * {@Link OH_Input_CreateAllSystemHotkeys} method.
 * @param count Count of the array to be destroyed, which must be the same as the number of system shortcut keys.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_DestroyAllSystemHotkeys(Input_Hotkey **hotkeys, int32_t count);

/**
 * @brief Obtains all hot keys supported by the system.
 *
 * @param hotkey Array of {@Link Input_Hotkey} instances.
 * When calling this API for the first time, you can pass NULL to obtain the array length.
 * @param count Number of hot keys supported by the system.
 * @return OH_Input_GetAllSystemHotkeys status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} The hotkey or count is NULL, or the value of count does not match the number
 *         of system shortcut keys supported by the system;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetAllSystemHotkeys(Input_Hotkey **hotkey, int32_t *count);

/**
 * @brief Specifies whether to report repeated key events.
 *
 * @param hotkey Shortcut key object.
 * @param isRepeat Whether to report repeated key events.
 * The value <b>true</b> means to report repeated key events, and the value <b>false</b> means the opposite.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
void OH_Input_SetRepeat(Input_Hotkey* hotkey, bool isRepeat);

/**
 * @brief Checks whether to report repeated key events.
 *
 * @param hotkey Shortcut key object.
 * @param isRepeat Whether a key event is repeated.
 * @return OH_Input_GetRepeat status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} otherwise;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_GetRepeat(const Input_Hotkey* hotkey, bool *isRepeat);

/**
 * @brief Subscribes to shortcut key events.
 *
 * @param hotkey Shortcut key object.
 * @param callback Callback used to return shortcut key events.
 * @return OH_Input_AddHotkeyMonitor status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} if hotkey or callback is NULL;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported;\n
 *         {@link INPUT_HOTKEY_ALREADY_REGISTER} Subscription has been enabled;\n
 *         {@link INPUT_REPEAT_INTERCEPTOR} The shortcut key has been occupied.
 *         You can use {@link getAllSystemHotkeys} to query all system shortcut keys.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_AddHotkeyMonitor(const Input_Hotkey* hotkey, Input_HotkeyCallback callback);

/**
 * @brief Unsubscribes from shortcut key events.
 *
 * @param hotkey Shortcut key object.
 * @param callback Callback used to return shortcut key events.
 * @return OH_Input_RemoveHotkeyMonitor status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} if hotkey or callback is NULL;\n
 *         {@Link INPUT_DEVICE_NOT_SUPPORTED} Capability not supported.\n
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 14
 */
Input_Result OH_Input_RemoveHotkeyMonitor(const Input_Hotkey* hotkey, Input_HotkeyCallback callback);

/**
 * @brief Obtains the IDs of all input devices.
 *
 * @param deviceIds Array of input device IDs.
 * @param inSize Size of the array of input device IDs.
 * @param outSize Length of the list of input device IDs. The value cannot be greater than the value of inSize.
 * @return OH_Input_GetDeviceIds result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceIds or outSize is a null pointer or inSize is less than 0.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceIds(int32_t *deviceIds, int32_t inSize, int32_t *outSize);

/**
 * @brief Obtains the information about an input device.
 *
 * @param deviceId Device ID.
 * @param deviceInfo Pointer to an {@Link Input_DeviceInfo} object.
 * @return OH_Input_GetDevice result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if the deviceInfo is a null pointer or the deviceId is invalid.
 * You can use the {@Link OH_Input_GetDeviceIds} interface to query the device IDs supported by the system.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDevice(int32_t deviceId, Input_DeviceInfo **deviceInfo);

/**
 * @brief Creates a deviceInfo object.
 *
 * @return Pointer to an {@Link Input_DeviceInfo} object if the operation is successful;
 * a null pointer otherwise (possibly because of a memory allocation failure).
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_DeviceInfo* OH_Input_CreateDeviceInfo(void);

/**
 * @brief Destroys a deviceInfo object.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
void OH_Input_DestroyDeviceInfo(Input_DeviceInfo **deviceInfo);

/**
 * @brief Obtains the keyboard type of an input device.
 *
 * @param deviceId Device ID.
 * @param keyboardType Pointer to the keyboard type of the input device.
 * @return OH_Input_GetKeyboardType result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if the device ID is invalid or keyboardType is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetKeyboardType(int32_t deviceId, int32_t *keyboardType);

/**
 * @brief Obtains the ID of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param id Pointer to the ID of the input device.
 * @return OH_Input_GetDeviceId result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or id is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceId(Input_DeviceInfo *deviceInfo, int32_t *id);

/**
 * @brief Obtains the name of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param name Pointer to the name of the input device.
 * @return OH_Input_GetDeviceName result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or name is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceName(Input_DeviceInfo *deviceInfo, char **name);

/**
 * @brief Obtains the capabilities of an input device, for example, a touchscreen, touchpad, or keyboard.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param capabilities Pointer to the capabilities of the input device.
 * @return OH_Input_GetCapabilities result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or capabilities is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetCapabilities(Input_DeviceInfo *deviceInfo, int32_t *capabilities);

/**
 * @brief Obtains the version information of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param version Pointer to the version information of the input device.
 * @return OH_Input_GetDeviceVersion result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or version is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceVersion(Input_DeviceInfo *deviceInfo, int32_t *version);

/**
 * @brief Obtains the product information of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param product Pointer to the product information of the input device.
 * @return OH_Input_GetDeviceProduct result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or product is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceProduct(Input_DeviceInfo *deviceInfo, int32_t *product);

/**
 * @brief Obtains the vendor information of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param vendor Pointer to the vendor information of the input device.
 * @return OH_Input_GetDeviceVendor result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or vendor is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceVendor(Input_DeviceInfo *deviceInfo, int32_t *vendor);

/**
 * @brief Obtains the physical address of an input device.
 *
 * @param deviceInfo information object. For details, see {@Link Input_DeviceInfo}.
 * @param address Pointer to the physical address of the input device.
 * @return OH_Input_GetDeviceAddress result code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;
 *         {@link INPUT_PARAMETER_ERROR} if deviceInfo or address is a null pointer.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_GetDeviceAddress(Input_DeviceInfo *deviceInfo, char **address);

/**
 * @brief Registers a listener for device hot swap events.
 *
 * @param listener Pointer to an {@Link Input_DeviceListener} object.
 *
 * @return OH_Input_RegisterDeviceListener status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} if listener is NULL;
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_RegisterDeviceListener(Input_DeviceListener* listener);

/**
 * @brief Unregisters the listener for device hot swap events.
 *
 * @param listener Pointer to the listener for device hot swap events. For details, see {@Link Input_DeviceListener}.
 *
 * @return OH_Input_UnregisterDeviceListener status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_PARAMETER_ERROR} if listener is NULL or no listener is registered;
 *         {@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_UnregisterDeviceListener(Input_DeviceListener* listener);

/**
 * @brief Unregisters the listener for all device hot swap events.
 *
 * @return OH_Input_UnregisterDeviceListener status code, specifically,
 *         {@link INPUT_SUCCESS} if the operation is successful;\n
 *         {@link INPUT_SERVICE_EXCEPTION} if the service is abnormal.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
Input_Result OH_Input_UnregisterDeviceListeners(void);

/**
 * @brief Obtains the interval since the last system input event.
 *
 * @param timeInterval Interval, in microseconds.
 * @return OH_Input_GetIntervalSinceLastInput status code, specifically,
 *         {@Link INPUT_SUCCESS} if the Operation is successful;
 *         {@Link INPUT_SERVICE_EXCEPTION} otherwise.
 * @syscap SystemCapability.MultimodalInput.Input.Core
 * @since 13
 */
int32_t OH_Input_GetIntervalSinceLastInput(int64_t *timeInterval);
#ifdef __cplusplus
}
#endif
/** @} */

#endif /* OH_INPUT_MANAGER_H */
