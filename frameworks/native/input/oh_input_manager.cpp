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

#include "input_manager.h"
#include "input_manager_impl.h"
#include "key_event.h"
#include "mmi_log.h"
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

static std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_mouseEvent = OHOS::MMI::PointerEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_touchEvent = OHOS::MMI::PointerEvent::Create();

Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyState, INPUT_PARAMETER_ERROR);
    if (keyState->keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        MMI_HILOGE("keyCode is invalid, keyCode:%{public}d", keyState->keyCode);
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
