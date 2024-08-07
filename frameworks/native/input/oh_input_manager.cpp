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

#include "oh_input_manager.h"

#include "error_multimodal.h"
#include "input_manager.h"
#include "input_manager_impl.h"
#include "key_event.h"
#include "mmi_log.h"
#include "oh_axis_type.h"
#include "oh_input_interceptor.h"
#include "oh_key_code.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManager"

struct Input_KeyState {
    int32_t keyCode;
    int32_t keyState;
    int32_t keySwitch;
};

struct Input_KeyEvent {
    int32_t action;
    int32_t keyCode;
    int64_t actionTime { -1 };
};

struct Input_MouseEvent {
    int32_t action;
    int32_t displayX;
    int32_t displayY;
    int32_t button { -1 };
    int32_t axisType { -1 };
    float axisValue { 0.0f };
    int64_t actionTime { -1 };
};

struct Input_TouchEvent {
    int32_t action;
    int32_t id;
    int32_t displayX;
    int32_t displayY;
    int64_t actionTime { -1 };
};

struct Input_AxisEvent {
    int32_t axisAction;
    float displayX;
    float displayY;
    std::map<int32_t, double> axisValues;
    int64_t actionTime { -1 };
    int32_t sourceType;
    int32_t axisEventType { -1 };
};

static constexpr int32_t INVALID_MONITOR_ID = -1;
static constexpr int32_t INVALID_INTERCEPTOR_ID = -1;
static std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_mouseEvent = OHOS::MMI::PointerEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_touchEvent = OHOS::MMI::PointerEvent::Create();
static std::set<Input_KeyEventCallback> g_keyMonitorCallbacks;
static std::set<Input_MouseEventCallback> g_mouseMonitorCallbacks;
static std::set<Input_TouchEventCallback> g_touchMonitorCallbacks;
static std::set<Input_AxisEventCallback> g_axisMonitorAllCallbacks;
static std::map<InputEvent_AxisEventType, std::set<Input_AxisEventCallback>> g_axisMonitorCallbacks;
static Input_KeyEventCallback g_keyInterceptorCallback = nullptr;
static struct Input_InterceptorEventCallback *g_pointerInterceptorCallback = nullptr;
static std::shared_ptr<OHOS::MMI::OHInputInterceptor> g_pointerInterceptor =
    std::make_shared<OHOS::MMI::OHInputInterceptor>();
static std::shared_ptr<OHOS::MMI::OHInputInterceptor> g_keyInterceptor =
    std::make_shared<OHOS::MMI::OHInputInterceptor>();
static std::mutex g_mutex;
static int32_t g_keyMonitorId = INVALID_MONITOR_ID;
static int32_t g_pointerMonitorId = INVALID_MONITOR_ID;
static int32_t g_keyInterceptorId = INVALID_INTERCEPTOR_ID;
static int32_t g_pointerInterceptorId = INVALID_INTERCEPTOR_ID;
static const std::set<int32_t> g_keyCodeValueSet = {
    KEYCODE_DPAD_UP, KEYCODE_DPAD_DOWN, KEYCODE_DPAD_LEFT, KEYCODE_DPAD_RIGHT, KEYCODE_ALT_LEFT, KEYCODE_ALT_RIGHT,
    KEYCODE_SHIFT_LEFT, KEYCODE_SHIFT_RIGHT, KEYCODE_TAB, KEYCODE_CTRL_LEFT, KEYCODE_CTRL_RIGHT, KEYCODE_CAPS_LOCK,
    KEYCODE_SCROLL_LOCK, KEYCODE_F1, KEYCODE_F2, KEYCODE_F3, KEYCODE_F4, KEYCODE_F5, KEYCODE_F6, KEYCODE_F7,
    KEYCODE_F8, KEYCODE_F9, KEYCODE_F10, KEYCODE_F11, KEYCODE_F12, KEYCODE_NUM_LOCK
};

Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyState, INPUT_PARAMETER_ERROR);
    if (keyState->keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        MMI_HILOGE("keyCode is invalid, keyCode:%{public}d", keyState->keyCode);
        return INPUT_PARAMETER_ERROR;
    }
    if (g_keyCodeValueSet.find(keyState->keyCode) == g_keyCodeValueSet.end()) {
        MMI_HILOGE("keyCode is not within the query range, keyCode:%{public}d", keyState->keyCode);
        return INPUT_PARAMETER_ERROR;
    }
    std::vector<int32_t> pressedKeys;
    std::map<int32_t, int32_t> specialKeysState;
    OHOS::MMI::InputManager::GetInstance()->GetKeyState(pressedKeys, specialKeysState);
    auto iter = std::find(pressedKeys.begin(), pressedKeys.end(), keyState->keyCode);
    if (iter != pressedKeys.end()) {
        keyState->keyState = KEY_PRESSED;
    } else {
        keyState->keyState = KEY_RELEASED;
    }
    auto itr = specialKeysState.find(keyState->keyCode);
    if (itr != specialKeysState.end()) {
        if (itr->second == 0) {
            keyState->keySwitch = KEY_SWITCH_OFF;
        } else {
            keyState->keySwitch = KEY_SWITCH_ON;
        }
    } else {
        keyState->keySwitch = KEY_DEFAULT;
    }
    return INPUT_SUCCESS;
}

struct Input_KeyState* OH_Input_CreateKeyState()
{
    Input_KeyState* keyState = new (std::nothrow) Input_KeyState();
    CHKPL(keyState);
    return keyState;
}

void OH_Input_DestroyKeyState(struct Input_KeyState** keyState)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyState);
    CHKPV(*keyState);
    delete *keyState;
    *keyState = nullptr;
}

void OH_Input_SetKeyCode(struct Input_KeyState* keyState, int32_t keyCode)
{
    CHKPV(keyState);
    if (keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        MMI_HILOGE("keyCode is invalid, keyCode:%{public}d", keyCode);
        return;
    }
    keyState->keyCode = keyCode;
}

int32_t OH_Input_GetKeyCode(const struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEYCODE_UNKNOWN);
    return keyState->keyCode;
}

void OH_Input_SetKeyPressed(struct Input_KeyState* keyState, int32_t keyAction)
{
    CHKPV(keyState);
    keyState->keyState = keyAction;
}

int32_t OH_Input_GetKeyPressed(const struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEY_DEFAULT);
    return keyState->keyState;
}

void OH_Input_SetKeySwitch(struct Input_KeyState* keyState, int32_t keySwitch)
{
    CHKPV(keyState);
    keyState->keySwitch = keySwitch;
}

int32_t OH_Input_GetKeySwitch(const struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEY_DEFAULT);
    return keyState->keySwitch;
}

static void HandleKeyAction(const struct Input_KeyEvent* keyEvent, OHOS::MMI::KeyEvent::KeyItem &item)
{
    if (keyEvent->action == KEY_ACTION_DOWN) {
        g_keyEvent->AddPressedKeyItems(item);
    }
    if (keyEvent->action == KEY_ACTION_UP) {
        std::optional<OHOS::MMI::KeyEvent::KeyItem> pressedKeyItem = g_keyEvent->GetKeyItem(keyEvent->keyCode);
        if (pressedKeyItem) {
            item.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_HILOGW("Find pressed key failed, keyCode:%{public}d", keyEvent->keyCode);
        }
        g_keyEvent->RemoveReleasedKeyItems(item);
        g_keyEvent->AddPressedKeyItems(item);
    }
}

int32_t OH_Input_InjectKeyEvent(const struct Input_KeyEvent* keyEvent)
{
    MMI_HILOGI("Input_KeyEvent injectEvent");
    CHKPR(keyEvent, INPUT_PARAMETER_ERROR);
    if (keyEvent->keyCode < 0) {
        MMI_HILOGE("keyCode:%{public}d is less 0, can not process", keyEvent->keyCode);
        return INPUT_PARAMETER_ERROR;
    }
    CHKPR(g_keyEvent, INPUT_PARAMETER_ERROR);
    g_keyEvent->ClearFlag();
    if (g_keyEvent->GetAction() == OHOS::MMI::KeyEvent::KEY_ACTION_UP) {
        std::optional<OHOS::MMI::KeyEvent::KeyItem> preUpKeyItem = g_keyEvent->GetKeyItem();
        if (preUpKeyItem) {
            g_keyEvent->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_HILOGE("The preUpKeyItem is nullopt");
        }
    }
    int64_t time = keyEvent->actionTime;
    if (time < 0) {
        time = OHOS::MMI::GetSysClockTime();
    }
    g_keyEvent->SetActionTime(time);
    g_keyEvent->SetRepeat(true);
    g_keyEvent->SetKeyCode(keyEvent->keyCode);
    bool isKeyPressed = false;
    if (keyEvent->action == KEY_ACTION_DOWN) {
        g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
        g_keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
        isKeyPressed = true;
    } else if (keyEvent->action == KEY_ACTION_UP) {
        g_keyEvent->SetAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
        g_keyEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
        isKeyPressed = false;
    }
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetDownTime(time);
    item.SetKeyCode(keyEvent->keyCode);
    item.SetPressed(isKeyPressed);
    HandleKeyAction(keyEvent, item);
    g_keyEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_keyEvent, true);
    return INPUT_SUCCESS;
}

struct Input_KeyEvent* OH_Input_CreateKeyEvent()
{
    Input_KeyEvent* keyEvent = new (std::nothrow) Input_KeyEvent();
    CHKPL(keyEvent);
    return keyEvent;
}

void OH_Input_DestroyKeyEvent(struct Input_KeyEvent** keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(*keyEvent);
    delete *keyEvent;
    *keyEvent = nullptr;
}

void OH_Input_SetKeyEventAction(struct Input_KeyEvent* keyEvent, int32_t action)
{
    CHKPV(keyEvent);
    keyEvent->action = action;
}

int32_t OH_Input_GetKeyEventAction(const struct Input_KeyEvent* keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    return keyEvent->action;
}

void OH_Input_SetKeyEventKeyCode(struct Input_KeyEvent* keyEvent, int32_t keyCode)
{
    CHKPV(keyEvent);
    keyEvent->keyCode = keyCode;
}

int32_t OH_Input_GetKeyEventKeyCode(const struct Input_KeyEvent* keyEvent)
{
    CHKPR(keyEvent, KEYCODE_UNKNOWN);
    return keyEvent->keyCode;
}

void OH_Input_SetKeyEventActionTime(struct Input_KeyEvent* keyEvent, int64_t actionTime)
{
    CHKPV(keyEvent);
    keyEvent->actionTime = actionTime;
}

int64_t OH_Input_GetKeyEventActionTime(const struct Input_KeyEvent* keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    return keyEvent->actionTime;
}

static int32_t HandleMouseButton(const struct Input_MouseEvent* mouseEvent)
{
    int32_t button = mouseEvent->button;
    switch (button) {
        case MOUSE_BUTTON_NONE: {
            button = OHOS::MMI::PointerEvent::BUTTON_NONE;
            break;
        }
        case MOUSE_BUTTON_LEFT: {
            button = OHOS::MMI::PointerEvent::MOUSE_BUTTON_LEFT;
            break;
        }
        case MOUSE_BUTTON_MIDDLE: {
            button = OHOS::MMI::PointerEvent::MOUSE_BUTTON_MIDDLE;
            break;
        }
        case MOUSE_BUTTON_RIGHT: {
            button = OHOS::MMI::PointerEvent::MOUSE_BUTTON_RIGHT;
            break;
        }
        case MOUSE_BUTTON_FORWARD: {
            button = OHOS::MMI::PointerEvent::MOUSE_BUTTON_FORWARD;
            break;
        }
        case MOUSE_BUTTON_BACK: {
            button = OHOS::MMI::PointerEvent::MOUSE_BUTTON_BACK;
            break;
        }
        default: {
            MMI_HILOGE("button:%{public}d is invalid", button);
            return INPUT_PARAMETER_ERROR;
        }
    }
    if (mouseEvent->action == MOUSE_ACTION_BUTTON_DOWN) {
        g_mouseEvent->SetButtonPressed(button);
    } else if (mouseEvent->action == MOUSE_ACTION_BUTTON_UP) {
        g_mouseEvent->DeleteReleaseButton(button);
    }
    g_mouseEvent->SetButtonId(button);
    return INPUT_SUCCESS;
}

static int32_t HandleMouseAction(const struct Input_MouseEvent* mouseEvent, OHOS::MMI::PointerEvent::PointerItem &item)
{
    switch (mouseEvent->action) {
        case MOUSE_ACTION_CANCEL:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_CANCEL);
            break;
        case MOUSE_ACTION_MOVE:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
            break;
        case MOUSE_ACTION_BUTTON_DOWN:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN);
            item.SetPressed(true);
            break;
        case MOUSE_ACTION_BUTTON_UP:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_UP);
            item.SetPressed(false);
            break;
        case MOUSE_ACTION_AXIS_BEGIN:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN);
            break;
        case MOUSE_ACTION_AXIS_UPDATE:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE);
            break;
        case MOUSE_ACTION_AXIS_END:
            g_mouseEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END);
            break;
        default:
            MMI_HILOGE("action:%{public}d is invalid", mouseEvent->action);
            return INPUT_PARAMETER_ERROR;
    }
    if (mouseEvent->axisType == MOUSE_AXIS_SCROLL_VERTICAL) {
        g_mouseEvent->SetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, mouseEvent->axisValue);
    }
    if (mouseEvent->axisType == MOUSE_AXIS_SCROLL_HORIZONTAL) {
        g_mouseEvent->SetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, mouseEvent->axisValue);
    }
    return HandleMouseButton(mouseEvent);
}

static int32_t HandleMouseProperty(const struct Input_MouseEvent* mouseEvent,
    OHOS::MMI::PointerEvent::PointerItem &item)
{
    int32_t screenX = mouseEvent->displayX;
    int32_t screenY = mouseEvent->displayY;
    g_mouseEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    item.SetPointerId(0);
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    g_mouseEvent->SetPointerId(0);
    g_mouseEvent->UpdatePointerItem(g_mouseEvent->GetPointerId(), item);
    return INPUT_SUCCESS;
}

int32_t OH_Input_InjectMouseEvent(const struct Input_MouseEvent* mouseEvent)
{
    MMI_HILOGI("Input_MouseEvent injectEvent");
    CHKPR(mouseEvent, INPUT_PARAMETER_ERROR);
    CHKPR(g_mouseEvent, INPUT_PARAMETER_ERROR);
    g_mouseEvent->ClearFlag();
    g_mouseEvent->ClearAxisValue();
    g_mouseEvent->SetTargetDisplayId(0);
    int64_t time = mouseEvent->actionTime;
    if (time < 0) {
        time = OHOS::MMI::GetSysClockTime();
    }
    g_mouseEvent->SetActionTime(time);
    OHOS::MMI::PointerEvent::PointerItem item;
    item.SetDownTime(time);
    int32_t result = HandleMouseAction(mouseEvent, item);
    if (result != 0) {
        return result;
    }
    result = HandleMouseProperty(mouseEvent, item);
    if (result != 0) {
        return result;
    }
    g_mouseEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_mouseEvent, true);
    return INPUT_SUCCESS;
}

struct Input_MouseEvent* OH_Input_CreateMouseEvent()
{
    CALL_DEBUG_ENTER;
    Input_MouseEvent* mouseEvent = new (std::nothrow) Input_MouseEvent();
    CHKPL(mouseEvent);
    return mouseEvent;
}

void OH_Input_DestroyMouseEvent(struct Input_MouseEvent** mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    CHKPV(*mouseEvent);
    delete *mouseEvent;
    *mouseEvent = nullptr;
}

void OH_Input_SetMouseEventAction(struct Input_MouseEvent* mouseEvent, int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->action = action;
}

int32_t OH_Input_GetMouseEventAction(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->action;
}

void OH_Input_SetMouseEventDisplayX(struct Input_MouseEvent* mouseEvent, int32_t displayX)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->displayX = displayX;
}

int32_t OH_Input_GetMouseEventDisplayX(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->displayX;
}

void OH_Input_SetMouseEventDisplayY(struct Input_MouseEvent* mouseEvent, int32_t displayY)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->displayY = displayY;
}

int32_t OH_Input_GetMouseEventDisplayY(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->displayY;
}

void OH_Input_SetMouseEventButton(struct Input_MouseEvent* mouseEvent, int32_t button)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->button = button;
}

int32_t OH_Input_GetMouseEventButton(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->button;
}

void OH_Input_SetMouseEventAxisType(struct Input_MouseEvent* mouseEvent, int32_t axisType)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->axisType = axisType;
}

int32_t OH_Input_GetMouseEventAxisType(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->axisType;
}

void OH_Input_SetMouseEventAxisValue(struct Input_MouseEvent* mouseEvent, float axisValue)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->axisValue = axisValue;
}

float OH_Input_GetMouseEventAxisValue(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->axisValue;
}

void OH_Input_SetMouseEventActionTime(struct Input_MouseEvent* mouseEvent, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->actionTime = actionTime;
}

int64_t OH_Input_GetMouseEventActionTime(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->actionTime;
}

static void HandleTouchActionDown(OHOS::MMI::PointerEvent::PointerItem &item, int64_t time)
{
    auto pointIds = g_touchEvent->GetPointerIds();
    if (pointIds.empty()) {
        g_touchEvent->SetActionStartTime(time);
        g_touchEvent->SetTargetDisplayId(0);
    }
    g_touchEvent->SetActionTime(time);
    g_touchEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_DOWN);
    item.SetDownTime(time);
    item.SetPressed(true);
}

static int32_t HandleTouchAction(const struct Input_TouchEvent* touchEvent, OHOS::MMI::PointerEvent::PointerItem &item)
{
    CALL_DEBUG_ENTER;
    int64_t time = touchEvent->actionTime;
    if (time < 0) {
        time = OHOS::MMI::GetSysClockTime();
    }
    switch (touchEvent->action) {
        case TOUCH_ACTION_CANCEL:{
            g_touchEvent->SetActionTime(time);
            g_touchEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_CANCEL);
            if (!(g_touchEvent->GetPointerItem(touchEvent->id, item))) {
                MMI_HILOGE("Get pointer parameter failed");
                return INPUT_PARAMETER_ERROR;
            }
            item.SetPressed(false);
            break;
        }
        case TOUCH_ACTION_DOWN: {
            HandleTouchActionDown(item, time);
            break;
        }
        case TOUCH_ACTION_MOVE: {
            g_touchEvent->SetActionTime(time);
            g_touchEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
            if (!(g_touchEvent->GetPointerItem(touchEvent->id, item))) {
                MMI_HILOGE("Get pointer parameter failed");
                return INPUT_PARAMETER_ERROR;
            }
            break;
        }
        case TOUCH_ACTION_UP: {
            g_touchEvent->SetActionTime(time);
            g_touchEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_UP);
            if (!(g_touchEvent->GetPointerItem(touchEvent->id, item))) {
                MMI_HILOGE("Get pointer parameter failed");
                return INPUT_PARAMETER_ERROR;
            }
            item.SetPressed(false);
            break;
        }
        default: {
            MMI_HILOGE("action:%{public}d is invalid", touchEvent->action);
            return INPUT_PARAMETER_ERROR;
        }
    }
    return INPUT_SUCCESS;
}

static int32_t HandleTouchProperty(const struct Input_TouchEvent* touchEvent,
    OHOS::MMI::PointerEvent::PointerItem &item)
{
    CALL_DEBUG_ENTER;
    int32_t id = touchEvent->id;
    int32_t screenX = touchEvent->displayX;
    int32_t screenY = touchEvent->displayY;
    if (screenX < 0 || screenY < 0) {
        MMI_HILOGE("touch parameter is less 0, can not process");
        return INPUT_PARAMETER_ERROR;
    }
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetPointerId(id);
    g_touchEvent->SetPointerId(id);
    g_touchEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    if (touchEvent->action == TOUCH_ACTION_DOWN) {
        g_touchEvent->AddPointerItem(item);
    } else if ((touchEvent->action == TOUCH_ACTION_MOVE) || (touchEvent->action == TOUCH_ACTION_UP)) {
        g_touchEvent->UpdatePointerItem(id, item);
    }
    return INPUT_SUCCESS;
}

int32_t OH_Input_InjectTouchEvent(const struct Input_TouchEvent* touchEvent)
{
    MMI_HILOGI("Input_TouchEvent injectTouchEvent");
    CHKPR(touchEvent, INPUT_PARAMETER_ERROR);
    CHKPR(g_touchEvent, INPUT_PARAMETER_ERROR);
    g_touchEvent->ClearFlag();
    OHOS::MMI::PointerEvent::PointerItem item;
    int32_t result = HandleTouchAction(touchEvent, item);
    if (result != 0) {
        return INPUT_PARAMETER_ERROR;
    }
    result = HandleTouchProperty(touchEvent, item);
    if (result != 0) {
        return INPUT_PARAMETER_ERROR;
    }
    g_touchEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_touchEvent, true);
    if (touchEvent->action == TOUCH_ACTION_UP) {
        g_touchEvent->RemovePointerItem(g_touchEvent->GetPointerId());
        MMI_HILOGD("This touch event is up remove this finger");
        if (g_touchEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch event is final finger up remove this finger");
            g_touchEvent->Reset();
        }
    }
    return INPUT_SUCCESS;
}

struct Input_TouchEvent* OH_Input_CreateTouchEvent()
{
    CALL_DEBUG_ENTER;
    Input_TouchEvent* touchEvent = new (std::nothrow) Input_TouchEvent();
    CHKPL(touchEvent);
    return touchEvent;
}

void OH_Input_DestroyTouchEvent(struct Input_TouchEvent** touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    CHKPV(*touchEvent);
    delete *touchEvent;
    *touchEvent = nullptr;
}

void OH_Input_SetTouchEventAction(struct Input_TouchEvent* touchEvent, int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->action = action;
}

int32_t OH_Input_GetTouchEventAction(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->action;
}

void OH_Input_SetTouchEventFingerId(struct Input_TouchEvent* touchEvent, int32_t id)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->id = id;
}

int32_t OH_Input_GetTouchEventFingerId(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->id;
}

void OH_Input_SetTouchEventDisplayX(struct Input_TouchEvent* touchEvent, int32_t displayX)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->displayX = displayX;
}

int32_t OH_Input_GetTouchEventDisplayX(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->displayX;
}

void OH_Input_SetTouchEventDisplayY(struct Input_TouchEvent* touchEvent, int32_t displayY)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->displayY = displayY;
}

int32_t OH_Input_GetTouchEventDisplayY(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->displayY;
}

void OH_Input_SetTouchEventActionTime(struct Input_TouchEvent* touchEvent, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->actionTime = actionTime;
}

int64_t OH_Input_GetTouchEventActionTime(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->actionTime;
}

void OH_Input_CancelInjection()
{
    CALL_DEBUG_ENTER;
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().CancelInjection();
}

static bool SetAxisValueByAxisEventType(std::shared_ptr<OHOS::MMI::PointerEvent> event,
    struct Input_AxisEvent *axisEvent, int32_t axisEventType)
{
    CHKPR(event, false);
    CHKPR(axisEvent, false);
    if (axisEventType == OHOS::MMI::PointerEvent::AXIS_EVENT_TYPE_PINCH) {
        double value = event->GetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_PINCH);
        axisEvent->axisValues.insert(std::make_pair(AXIS_TYPE_PINCH, value));
        value = event->GetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_ROTATE);
        axisEvent->axisValues.insert(std::make_pair(AXIS_TYPE_ROTATE, value));
    } else if (axisEventType == OHOS::MMI::PointerEvent::AXIS_EVENT_TYPE_SCROLL) {
        double value = event->GetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
        axisEvent->axisValues.insert(std::make_pair(AXIS_TYPE_SCROLL_VERTICAL, value));
        value = event->GetAxisValue(OHOS::MMI::PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
        axisEvent->axisValues.insert(std::make_pair(AXIS_TYPE_SCROLL_HORIZONTAL, value));
    } else {
        MMI_HILOGE("Undefined axisEventType: %{public}d", axisEventType);
        return false;
    }
    axisEvent->axisEventType = axisEventType;
    return true;
}

static bool IsAxisEvent(int32_t action)
{
    if (action != AXIS_ACTION_BEGIN && action != AXIS_ACTION_UPDATE && action != AXIS_ACTION_END) {
        return false;
    }
    return true;
}

Input_AxisEvent* OH_Input_CreateAxisEvent(void)
{
    Input_AxisEvent* axisEvent = new (std::nothrow) Input_AxisEvent();
    CHKPP(axisEvent);
    return axisEvent;
}

Input_Result OH_Input_DestroyAxisEvent(Input_AxisEvent** axisEvent)
{
    CALL_DEBUG_ENTER;
    if (axisEvent == nullptr || *axisEvent == nullptr) {
        return INPUT_PARAMETER_ERROR;
    }
    delete *axisEvent;
    *axisEvent = nullptr;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventAction(Input_AxisEvent* axisEvent, InputEvent_AxisAction action)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->axisAction = action;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventAction(const Input_AxisEvent* axisEvent, InputEvent_AxisAction *action)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(action, INPUT_PARAMETER_ERROR);
    *action = InputEvent_AxisAction(axisEvent->axisAction);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventDisplayX(Input_AxisEvent* axisEvent, float displayX)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->displayX = displayX;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventDisplayX(const Input_AxisEvent* axisEvent, float* displayX)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(displayX, INPUT_PARAMETER_ERROR);
    *displayX = axisEvent->displayX;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventDisplayY(Input_AxisEvent* axisEvent, float displayY)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->displayY = displayY;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventDisplayY(const Input_AxisEvent* axisEvent, float* displayY)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(displayY, INPUT_PARAMETER_ERROR);
    *displayY = axisEvent->displayY;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventAxisValue(Input_AxisEvent* axisEvent,
    InputEvent_AxisType axisType, double axisValue)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->axisValues.emplace(axisType, axisValue);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventAxisValue(const Input_AxisEvent* axisEvent,
    InputEvent_AxisType axisType, double* axisValue)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(axisValue, INPUT_PARAMETER_ERROR);
    auto it = axisEvent->axisValues.find(axisType);
    if (it == axisEvent->axisValues.end()) {
        MMI_HILOGE("There is no axis value of axisType: %{public}d in the axisEvent", axisType);
        return INPUT_PARAMETER_ERROR;
    }
    *axisValue = it->second;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventActionTime(Input_AxisEvent* axisEvent, int64_t actionTime)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->actionTime = actionTime;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventActionTime(const Input_AxisEvent* axisEvent, int64_t* actionTime)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(actionTime, INPUT_PARAMETER_ERROR);
    *actionTime = axisEvent->actionTime;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventType(Input_AxisEvent* axisEvent, InputEvent_AxisEventType axisEventType)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->axisEventType = axisEventType;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventType(const Input_AxisEvent* axisEvent, InputEvent_AxisEventType* axisEventType)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(axisEventType, INPUT_PARAMETER_ERROR);
    *axisEventType = InputEvent_AxisEventType(axisEvent->axisEventType);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventSourceType(Input_AxisEvent* axisEvent, InputEvent_SourceType sourceType)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->sourceType = sourceType;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventSourceType(const Input_AxisEvent* axisEvent, InputEvent_SourceType* sourceType)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(sourceType, INPUT_PARAMETER_ERROR);
    *sourceType = InputEvent_SourceType(axisEvent->sourceType);
    return INPUT_SUCCESS;
}

static Input_Result NormalizeResult(int32_t result)
{
    if (result < RET_OK) {
        if (result == OHOS::MMI::ERROR_NO_PERMISSION) {
            MMI_HILOGE("Permisson denied");
            return INPUT_PERMISSION_DENIED;
        }
        return INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}

static void KeyEventMonitorCallback(std::shared_ptr<OHOS::MMI::KeyEvent> event)
{
    CHKPV(event);
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    CHKPV(keyEvent);
    keyEvent->action = event->GetKeyAction();
    keyEvent->keyCode = event->GetKeyCode();
    keyEvent->actionTime = event->GetActionTime();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_keyMonitorCallbacks) {
        callback(keyEvent);
    }
    OH_Input_DestroyKeyEvent(&keyEvent);
}

Input_Result OH_Input_AddKeyEventMonitor(Input_KeyEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    if (g_keyMonitorId == INVALID_MONITOR_ID) {
        int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().AddMonitor(KeyEventMonitorCallback);
        retCode = NormalizeResult(ret);
        if (retCode != INPUT_SUCCESS) {
            return retCode;
        }
        g_keyMonitorId = ret;
    }
    g_keyMonitorCallbacks.insert(callback);
    return retCode;
}

static void TouchEventMonitorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    CHKPV(touchEvent);
    touchEvent->action = event->GetPointerAction();
    touchEvent->id = event->GetPointerId();
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    touchEvent->displayX = item.GetDisplayX();
    touchEvent->displayY = item.GetDisplayY();
    touchEvent->actionTime = event->GetActionTime();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_touchMonitorCallbacks) {
        callback(touchEvent);
    }
    OH_Input_DestroyTouchEvent(&touchEvent);
}

static void MouseEventMonitorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    CHKPV(mouseEvent);
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    mouseEvent->displayX = item.GetDisplayX();
    mouseEvent->displayY = item.GetDisplayY();
    mouseEvent->action = event->GetPointerAction();
    mouseEvent->button = event->GetButtonId();
    mouseEvent->actionTime = event->GetActionTime();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_mouseMonitorCallbacks) {
        callback(mouseEvent);
    }
    OH_Input_DestroyMouseEvent(&mouseEvent);
}

static void AxisEventMonitorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    CHKPV(axisEvent);
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyAxisEvent(&axisEvent);
        return;
    }
    if (!SetAxisValueByAxisEventType(event, axisEvent, event->GetAxisEventType())) {
        OH_Input_DestroyAxisEvent(&axisEvent);
        return;
    }
    axisEvent->axisAction = event->GetPointerAction();
    axisEvent->displayX = item.GetDisplayX();
    axisEvent->displayY = item.GetDisplayY();
    axisEvent->actionTime = event->GetActionTime();
    axisEvent->sourceType = event->GetSourceType();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_axisMonitorAllCallbacks) {
        callback(axisEvent);
    }
    auto it = g_axisMonitorCallbacks.find(InputEvent_AxisEventType(event->GetAxisEventType()));
    if (it != g_axisMonitorCallbacks.end()) {
        for (auto &callback : it->second) {
            callback(axisEvent);
        }
    }
    OH_Input_DestroyAxisEvent(&axisEvent);
}

static void PointerEventMonitorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    if (event->GetSourceType() == SOURCE_TYPE_TOUCHSCREEN) {
        TouchEventMonitorCallback(event);
    } else if (event->GetSourceType() == SOURCE_TYPE_MOUSE && !IsAxisEvent(event->GetPointerAction())) {
        MouseEventMonitorCallback(event);
    } else if (IsAxisEvent(event->GetPointerAction()) && event->GetSourceType() != SOURCE_TYPE_TOUCHSCREEN) {
        AxisEventMonitorCallback(event);
    } else {
        MMI_HILOGE("Undefined event type");
    }
}

static Input_Result AddPointerEventMonitor()
{
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    if (g_pointerMonitorId == INVALID_MONITOR_ID) {
        int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().AddMonitor(
            PointerEventMonitorCallback);
        retCode = NormalizeResult(ret);
        if (retCode != INPUT_SUCCESS) {
            MMI_HILOGE("Add pointer event monitor failed.");
            return retCode;
        }
        g_pointerMonitorId = ret;
    }
    return retCode;
}

Input_Result OH_Input_AddMouseEventMonitor(Input_MouseEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result ret = AddPointerEventMonitor();
    if (ret != INPUT_SUCCESS) {
        return ret;
    }
    std::lock_guard guard(g_mutex);
    g_mouseMonitorCallbacks.insert(callback);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_AddTouchEventMonitor(Input_TouchEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result ret = AddPointerEventMonitor();
    if (ret != INPUT_SUCCESS) {
        return ret;
    }
    std::lock_guard guard(g_mutex);
    g_touchMonitorCallbacks.insert(callback);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_AddAxisEventMonitorForAll(Input_AxisEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result ret = AddPointerEventMonitor();
    if (ret != INPUT_SUCCESS) {
        return ret;
    }
    std::lock_guard guard(g_mutex);
    g_axisMonitorAllCallbacks.insert(callback);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_AddAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result ret = AddPointerEventMonitor();
    if (ret != INPUT_SUCCESS) {
        return ret;
    }
    std::lock_guard guard(g_mutex);
    auto it = g_axisMonitorCallbacks.find(axisEventType);
    if (it == g_axisMonitorCallbacks.end()) {
        std::set<Input_AxisEventCallback> callbacks;
        callbacks.insert(callback);
        g_axisMonitorCallbacks.insert(std::make_pair(axisEventType, callbacks));
    } else {
        it->second.insert(callback);
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_RemoveKeyEventMonitor(Input_KeyEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    auto it = g_keyMonitorCallbacks.find(callback);
    if (it == g_keyMonitorCallbacks.end()) {
        return INPUT_PARAMETER_ERROR;
    }
    g_keyMonitorCallbacks.erase(it);
    if (g_keyMonitorCallbacks.empty()) {
        int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().RemoveMonitor(g_keyMonitorId);
        retCode = NormalizeResult(ret);
        if (retCode != INPUT_SUCCESS) {
            return retCode;
        }
        g_keyMonitorId = INVALID_MONITOR_ID;
    }
    return retCode;
}

static bool IsNeedRemoveMonitor()
{
    if (g_mouseMonitorCallbacks.empty() && g_touchMonitorCallbacks.empty() &&
        g_axisMonitorCallbacks.empty() && g_axisMonitorAllCallbacks.empty()) {
        return true;
    }
    return false;
}

static Input_Result RemovePointerEventMonitor()
{
    Input_Result retCode = INPUT_SUCCESS;
    if (IsNeedRemoveMonitor()) {
        int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().RemoveMonitor(g_pointerMonitorId);
        retCode = NormalizeResult(ret);
        if (retCode != INPUT_SUCCESS) {
            return retCode;
        }
        g_pointerMonitorId = INVALID_MONITOR_ID;
    }
    return retCode;
}

Input_Result OH_Input_RemoveMouseEventMonitor(Input_MouseEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_mutex);
    auto it = g_mouseMonitorCallbacks.find(callback);
    if (it == g_mouseMonitorCallbacks.end()) {
        MMI_HILOGE("The callback has not been added.");
        return INPUT_PARAMETER_ERROR;
    }
    g_mouseMonitorCallbacks.erase(it);
    return RemovePointerEventMonitor();
}

Input_Result OH_Input_RemoveTouchEventMonitor(Input_TouchEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_mutex);
    auto it = g_touchMonitorCallbacks.find(callback);
    if (it == g_touchMonitorCallbacks.end()) {
        MMI_HILOGE("The callback has not been added.");
        return INPUT_PARAMETER_ERROR;
    }
    g_touchMonitorCallbacks.erase(it);
    return RemovePointerEventMonitor();
}

Input_Result OH_Input_RemoveAxisEventMonitorForAll(Input_AxisEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_mutex);
    auto it = g_axisMonitorAllCallbacks.find(callback);
    if (it == g_axisMonitorAllCallbacks.end()) {
        MMI_HILOGE("The callback has not been added.");
        return INPUT_PARAMETER_ERROR;
    }
    g_axisMonitorAllCallbacks.erase(it);
    return RemovePointerEventMonitor();
}

Input_Result OH_Input_RemoveAxisEventMonitor(InputEvent_AxisEventType axisEventType, Input_AxisEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_mutex);
    if (g_axisMonitorCallbacks.find(axisEventType) == g_axisMonitorCallbacks.end()) {
        MMI_HILOGE("The axis event type has not been added.");
        return INPUT_PARAMETER_ERROR;
    }
    auto it = g_axisMonitorCallbacks[axisEventType].find(callback);
    if (it == g_axisMonitorCallbacks[axisEventType].end()) {
        MMI_HILOGE("The callback has not been added.");
        return INPUT_PARAMETER_ERROR;
    }
    g_axisMonitorCallbacks[axisEventType].erase(it);
    if (g_axisMonitorCallbacks[axisEventType].empty()) {
        g_axisMonitorCallbacks.erase(axisEventType);
    }
    return RemovePointerEventMonitor();
}

static void KeyEventInterceptorCallback(std::shared_ptr<OHOS::MMI::KeyEvent> event)
{
    CHKPV(event);
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    CHKPV(keyEvent);
    keyEvent->action = event->GetKeyAction();
    keyEvent->keyCode = event->GetKeyCode();
    keyEvent->actionTime = event->GetActionTime();
    std::lock_guard guard(g_mutex);
    if (g_keyInterceptorCallback != nullptr) {
        g_keyInterceptorCallback(keyEvent);
    }
    OH_Input_DestroyKeyEvent(&keyEvent);
}

Input_Result OH_Input_AddKeyEventInterceptor(Input_KeyEventCallback callback, Input_InterceptorOptions *option)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    if (g_keyInterceptorId != INVALID_INTERCEPTOR_ID) {
        MMI_HILOGE("Another key event interceptor has been added");
        return INPUT_REPEAT_INTERCEPTOR;
    }
    g_keyInterceptor->SetCallback(KeyEventInterceptorCallback);
    int32_t ret = g_keyInterceptor->Start(OHOS::MMI::INTERCEPTOR_TYPE_KEY);
    retCode = NormalizeResult(ret);
    if (retCode != INPUT_SUCCESS) {
        MMI_HILOGE("Add key event interceptor failed.");
        return retCode;
    }
    g_keyInterceptorId = ret;
    g_keyInterceptorCallback = callback;
    return retCode;
}

static void TouchEventInterceptorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    std::lock_guard guard(g_mutex);
    CHKPV(g_pointerInterceptorCallback);
    if (g_pointerInterceptorCallback->touchCallback == nullptr) {
        MMI_HILOGE("There is no callback for mouse event interceptor");
        return;
    }
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    CHKPV(touchEvent);
    touchEvent->action = event->GetPointerAction();
    touchEvent->id = event->GetPointerId();
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    touchEvent->displayX = item.GetDisplayX();
    touchEvent->displayY = item.GetDisplayY();
    touchEvent->actionTime = event->GetActionTime();
    g_pointerInterceptorCallback->touchCallback(touchEvent);
    OH_Input_DestroyTouchEvent(&touchEvent);
}

static void MouseEventInterceptorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    std::lock_guard guard(g_mutex);
    CHKPV(g_pointerInterceptorCallback);
    if (g_pointerInterceptorCallback->mouseCallback == nullptr) {
        MMI_HILOGE("There is no callback for mouse event interceptor");
        return;
    }
    Input_MouseEvent* mouseEvent = OH_Input_CreateMouseEvent();
    CHKPV(mouseEvent);
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    mouseEvent->displayX = item.GetDisplayX();
    mouseEvent->displayY = item.GetDisplayY();
    mouseEvent->action = event->GetPointerAction();
    mouseEvent->button = event->GetButtonId();
    mouseEvent->actionTime = event->GetActionTime();
    g_pointerInterceptorCallback->mouseCallback(mouseEvent);
    OH_Input_DestroyMouseEvent(&mouseEvent);
}

static void AxisEventInterceptorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    std::lock_guard guard(g_mutex);
    CHKPV(g_pointerInterceptorCallback);
    if (g_pointerInterceptorCallback->axisCallback == nullptr) {
        MMI_HILOGE("There is no callback for axis event interceptor");
        return;
    }
    Input_AxisEvent* axisEvent = OH_Input_CreateAxisEvent();
    CHKPV(axisEvent);
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyAxisEvent(&axisEvent);
        return;
    }
    if (!SetAxisValueByAxisEventType(event, axisEvent, event->GetAxisEventType())) {
        MMI_HILOGE("Fail to set axis value");
        OH_Input_DestroyAxisEvent(&axisEvent);
        return;
    }
    axisEvent->axisAction = event->GetPointerAction();
    axisEvent->displayX = item.GetDisplayX();
    axisEvent->displayY = item.GetDisplayY();
    axisEvent->actionTime = event->GetActionTime();
    axisEvent->sourceType = event->GetSourceType();
    g_pointerInterceptorCallback->axisCallback(axisEvent);
    OH_Input_DestroyAxisEvent(&axisEvent);
}

static void PointerEventInterceptorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    if (event->GetSourceType() == SOURCE_TYPE_TOUCHSCREEN) {
        TouchEventInterceptorCallback(event);
    } else if (event->GetSourceType() == SOURCE_TYPE_MOUSE && !IsAxisEvent(event->GetPointerAction())) {
        MouseEventInterceptorCallback(event);
    } else if (IsAxisEvent(event->GetPointerAction()) && event->GetSourceType() != SOURCE_TYPE_TOUCHSCREEN) {
        AxisEventInterceptorCallback(event);
    } else {
        MMI_HILOGE("Undefined event type");
    }
}

Input_Result OH_Input_AddInputEventInterceptor(Input_InterceptorEventCallback *callback,
                                               Input_InterceptorOptions *option)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    if (g_pointerInterceptorId != INVALID_INTERCEPTOR_ID) {
        MMI_HILOGE("Another interceptor for input event has been added");
        return INPUT_REPEAT_INTERCEPTOR;
    }
    g_pointerInterceptor->SetCallback(PointerEventInterceptorCallback);
    int32_t ret = g_pointerInterceptor->Start(OHOS::MMI::INTERCEPTOR_TYPE_POINTER);
    retCode = NormalizeResult(ret);
    if (retCode != INPUT_SUCCESS) {
        MMI_HILOGE("Add pointer event interceptor failed.");
        return retCode;
    }
    g_pointerInterceptorId = ret;
    g_pointerInterceptorCallback = callback;
    return retCode;
}

Input_Result OH_Input_RemoveKeyEventInterceptor(void)
{
    CALL_DEBUG_ENTER;
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    int32_t ret = g_keyInterceptor->Stop(OHOS::MMI::INTERCEPTOR_TYPE_KEY);
    retCode = NormalizeResult(ret);
    if (retCode != INPUT_SUCCESS) {
        MMI_HILOGE("Remove key event interceptor failed.");
        return retCode;
    }
    g_keyInterceptorCallback = nullptr;
    g_keyInterceptorId = INVALID_INTERCEPTOR_ID;
    return retCode;
}

Input_Result OH_Input_RemoveInputEventInterceptor(void)
{
    CALL_DEBUG_ENTER;
    Input_Result retCode = INPUT_SUCCESS;
    std::lock_guard guard(g_mutex);
    int32_t ret = g_pointerInterceptor->Stop(OHOS::MMI::INTERCEPTOR_TYPE_POINTER);
    retCode = NormalizeResult(ret);
    if (retCode != INPUT_SUCCESS) {
        MMI_HILOGE("Remove pointer event interceptor failed.");
        return retCode;
    }
    g_pointerInterceptorId = INVALID_INTERCEPTOR_ID;
    g_pointerInterceptorCallback = nullptr;
    return retCode;
}
