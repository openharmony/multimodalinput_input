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

#include "oh_input_manager.h"

#include <atomic>
#include <vector>

#include "securec.h"

#include "event_log_helper.h"
#include "input_manager.h"
#include "input_manager_impl.h"
#include "key_event_hook_handler.h"
#include "oh_input_device_listener.h"
#include "oh_input_interceptor.h"
#include "oh_key_code.h"
#include "permission_helper.h"
#include "pointer_event_ndk.h"
#ifdef PLAYER_FRAMEWORK_EXISTS
#include "screen_capture_monitor.h"
#include "ipc_skeleton.h"
#include "pixel_map.h"
#include "image/pixelmap_native.h"
#endif // PLAYER_FRAMEWORK_EXISTS

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManager"

struct Input_KeyState {
    int32_t keyCode;
    int32_t keyState;
    int32_t keySwitch;
};

struct Input_KeyEvent {
    int32_t id { -1 };
    int32_t action { -1 };
    int32_t keyCode { -1 };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_MouseEvent {
    int32_t action;
    int32_t displayX;
    int32_t displayY;
    int32_t globalX { INT32_MAX  };
    int32_t globalY { INT32_MAX  };
    int32_t button { -1 };
    int32_t axisType { -1 };
    float axisValue { 0.0f };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_TouchEvent {
    int32_t action;
    int32_t id;
    int32_t displayX;
    int32_t displayY;
    int32_t globalX { INT32_MAX  };
    int32_t globalY { INT32_MAX  };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_AxisEvent {
    int32_t axisAction;
    float displayX;
    float displayY;
    int32_t globalX { INT32_MAX  };
    int32_t globalY { INT32_MAX  };
    std::map<int32_t, double> axisValues;
    int64_t actionTime { -1 };
    int32_t sourceType;
    int32_t axisEventType { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
};

struct Input_HotkeyInfo {
    int32_t subscribeId;
    std::string hotkeyId;
    Input_HotkeyCallback callback { nullptr };
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption { nullptr };
};

struct Input_Hotkey {
    std::set<int32_t> preKeys {};
    int32_t finalKey { -1 };
    bool isRepeat { true };
};

constexpr int32_t SIZE_ARRAY = 64;
struct Input_DeviceInfo {
    int32_t id { -1 };
    char name[SIZE_ARRAY] {};
    int32_t ability { -1 };
    int32_t product { -1 };
    int32_t vendor { -1 };
    int32_t version { -1 };
    char phys[SIZE_ARRAY] {};
};

struct Input_CustomCursor {
    OH_PixelmapNative* pixelMap { nullptr };
    int32_t anchorX { 0 };
    int32_t anchorY { 0 };
};

struct Input_CursorConfig {
    bool followSystem { false };
};

typedef std::map<std::string, std::list<Input_HotkeyInfo *>> Callbacks;
static Callbacks g_callbacks = {};
static std::mutex g_CallBacksMutex;
static constexpr size_t PRE_KEYS_SIZE { 4 };
static constexpr size_t KEYS_SIZE { 3 };
static std::mutex g_hotkeyCountsMutex;
static std::unordered_map<Input_Hotkey**, int32_t> g_hotkeyCounts;
static constexpr int32_t INVALID_MONITOR_ID = -1;
static constexpr int32_t INVALID_INTERCEPTOR_ID = -1;
static constexpr int32_t OCCUPIED_BY_SYSTEM = -3;
static constexpr int32_t OCCUPIED_BY_OTHER = -4;
static constexpr int32_t SIMULATE_POINTER_EVENT_START_ID { 30000 };
static std::shared_ptr<OHOS::MMI::KeyEvent> g_keyEvent = OHOS::MMI::KeyEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_mouseEvent = OHOS::MMI::PointerEvent::Create();
static std::shared_ptr<OHOS::MMI::PointerEvent> g_touchEvent = OHOS::MMI::PointerEvent::Create();
static const std::set<int32_t> g_keyCodeValueSet = {
    KEYCODE_FN, KEYCODE_DPAD_UP, KEYCODE_DPAD_DOWN, KEYCODE_DPAD_LEFT, KEYCODE_DPAD_RIGHT, KEYCODE_ALT_LEFT,
    KEYCODE_ALT_RIGHT, KEYCODE_SHIFT_LEFT, KEYCODE_SHIFT_RIGHT, KEYCODE_TAB, KEYCODE_ENTER, KEYCODE_DEL, KEYCODE_MENU,
    KEYCODE_PAGE_UP, KEYCODE_PAGE_DOWN, KEYCODE_ESCAPE, KEYCODE_FORWARD_DEL, KEYCODE_CTRL_LEFT, KEYCODE_CTRL_RIGHT,
    KEYCODE_CAPS_LOCK, KEYCODE_SCROLL_LOCK, KEYCODE_META_LEFT, KEYCODE_META_RIGHT, KEYCODE_SYSRQ, KEYCODE_BREAK,
    KEYCODE_MOVE_HOME, KEYCODE_MOVE_END, KEYCODE_INSERT, KEYCODE_F1, KEYCODE_F2, KEYCODE_F3, KEYCODE_F4, KEYCODE_F5,
    KEYCODE_F6, KEYCODE_F7, KEYCODE_F8, KEYCODE_F9, KEYCODE_F10, KEYCODE_F11, KEYCODE_F12, KEYCODE_NUM_LOCK
};
static std::set<Input_KeyEventCallback> g_keyMonitorCallbacks;
static std::set<Input_MouseEventCallback> g_mouseMonitorCallbacks;
static std::set<Input_TouchEventCallback> g_touchMonitorCallbacks;
static std::set<Input_AxisEventCallback> g_axisMonitorAllCallbacks;
static std::set<Input_DeviceListener*> g_ohDeviceListenerList;
static std::map<InputEvent_AxisEventType, std::set<Input_AxisEventCallback>> g_axisMonitorCallbacks;
static Input_KeyEventCallback g_keyInterceptorCallback = nullptr;
static Input_KeyEventCallback g_keyEventHookCallback = nullptr;
static struct Input_InterceptorEventCallback *g_pointerInterceptorCallback = nullptr;
static std::shared_ptr<OHOS::MMI::OHInputInterceptor> g_pointerInterceptor =
    std::make_shared<OHOS::MMI::OHInputInterceptor>();
static std::shared_ptr<OHOS::MMI::OHInputInterceptor> g_keyInterceptor =
    std::make_shared<OHOS::MMI::OHInputInterceptor>();
static std::shared_ptr<OHOS::MMI::OHInputDeviceListener> g_deviceListener =
    std::make_shared<OHOS::MMI::OHInputDeviceListener>();
static std::mutex g_DeviceListerCallbackMutex;
static std::mutex g_mutex;
static int32_t g_keyMonitorId = INVALID_MONITOR_ID;
static int32_t g_pointerMonitorId = INVALID_MONITOR_ID;
static int32_t g_keyInterceptorId = INVALID_INTERCEPTOR_ID;
static int32_t g_pointerInterceptorId = INVALID_INTERCEPTOR_ID;
static std::atomic_int32_t g_keyEventHookId = INVALID_INTERCEPTOR_ID;
static int32_t UNKNOWN_MAX_TOUCH_POINTS { -1 };

static const std::vector<int32_t> g_pressKeyCodes = {
    OHOS::MMI::KeyEvent::KEYCODE_ALT_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_ALT_RIGHT,
    OHOS::MMI::KeyEvent::KEYCODE_SHIFT_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_SHIFT_RIGHT,
    OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_CTRL_RIGHT
};
static const std::vector<int32_t> g_finalKeyCodes = {
    OHOS::MMI::KeyEvent::KEYCODE_ALT_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_ALT_RIGHT,
    OHOS::MMI::KeyEvent::KEYCODE_SHIFT_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_SHIFT_RIGHT,
    OHOS::MMI::KeyEvent::KEYCODE_CTRL_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_CTRL_RIGHT,
    OHOS::MMI::KeyEvent::KEYCODE_META_LEFT,
    OHOS::MMI::KeyEvent::KEYCODE_META_RIGHT
};
using OHOS::MMI::AUTHORIZE_QUERY_STATE;

Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyState, INPUT_PARAMETER_ERROR);
    if (keyState->keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        if (!OHOS::MMI::EventLogHelper::IsBetaVersion()) {
            MMI_HILOGE("Invaild");
        } else {
            MMI_HILOGE("Invaild");
        }
        return INPUT_PARAMETER_ERROR;
    }
    if (g_keyCodeValueSet.find(keyState->keyCode) == g_keyCodeValueSet.end()) {
        MMI_HILOGE("code is not within the query range:%{private}d", keyState->keyCode);
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
        if (!OHOS::MMI::EventLogHelper::IsBetaVersion()) {
            MMI_HILOGE("Invaild");
        } else {
            MMI_HILOGE("Invaild");
        }
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
        } else if (!OHOS::MMI::EventLogHelper::IsBetaVersion()) {
            MMI_HILOGW("Find pressed key failed");
        } else {
            MMI_HILOGW("Find pressed key failed");
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
        if (!OHOS::MMI::EventLogHelper::IsBetaVersion()) {
            MMI_HILOGE("code is less 0, can not process");
        } else {
            MMI_HILOGE("code is less 0, can not process");
        }
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

void OH_Input_SetKeyEventWindowId(struct Input_KeyEvent* keyEvent, int32_t windowId)
{
    CHKPV(keyEvent);
    keyEvent->windowId = windowId;
}

int32_t OH_Input_GetKeyEventWindowId(const struct Input_KeyEvent* keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    return keyEvent->windowId;
}

void OH_Input_SetKeyEventDisplayId(struct Input_KeyEvent* keyEvent, int32_t displayId)
{
    CHKPV(keyEvent);
    keyEvent->displayId = displayId;
}

int32_t OH_Input_GetKeyEventDisplayId(const struct Input_KeyEvent* keyEvent)
{
    CHKPR(keyEvent, RET_ERR);
    return keyEvent->displayId;
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
            MMI_HILOGE("The action:%{public}d is invalid", mouseEvent->action);
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
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
    int32_t globalX = mouseEvent->globalX;
    int32_t globalY = mouseEvent->globalY;
    if (globalX != INT32_MAX && globalY != INT32_MAX) {
        item.SetGlobalX(globalX);
        item.SetGlobalY(globalY);
    } else {
        item.SetGlobalX(DBL_MAX);
        item.SetGlobalY(DBL_MAX);
    }
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
    if (mouseEvent->displayId <= 0) {
        g_mouseEvent->SetTargetDisplayId(0);
    } else {
        MMI_HILOGI("{%{public}d}", mouseEvent->displayId);
        g_mouseEvent->SetTargetDisplayId(mouseEvent->displayId);
    }
    int64_t time = mouseEvent->actionTime;
    if (time < 0) {
        time = OHOS::MMI::GetSysClockTime();
    }
    g_mouseEvent->SetActionTime(time);
    OHOS::MMI::PointerEvent::PointerItem item;
    int32_t pointerId = 10000;
    g_mouseEvent->GetPointerItem(pointerId, item);
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
    result = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_mouseEvent,
        true, PointerEvent::DISPLAY_COORDINATE);
    if ((result == INPUT_PERMISSION_DENIED) || (result == INPUT_OCCUPIED_BY_OTHER)) {
        MMI_HILOGE("Permission denied or occupied by other");
        return result;
    }
    return INPUT_SUCCESS;
}

int32_t OH_Input_InjectMouseEventGlobal(const struct Input_MouseEvent* mouseEvent)
{
    MMI_HILOGD("Input_MouseEvent global");
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
    int32_t pointerId = 10000;
    g_mouseEvent->GetPointerItem(pointerId, item);
    item.SetDownTime(time);
    int32_t result = HandleMouseAction(mouseEvent, item);
    if (result != 0) {
        return result;
    }
    result = HandleMouseProperty(mouseEvent, item);
    if (result != 0) {
        return result;
    }
    if (!item.IsValidGlobalXY()) {
        return INPUT_PARAMETER_ERROR;
    }
    g_mouseEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    result = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_mouseEvent,
        true, PointerEvent::GLOBAL_COORDINATE);
    if ((result == INPUT_PERMISSION_DENIED) || (result == INPUT_OCCUPIED_BY_OTHER)) {
        MMI_HILOGE("Permission denied or occupied by other");
        return INPUT_PERMISSION_DENIED;
    }
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

void OH_Input_SetMouseEventWindowId(struct Input_MouseEvent* mouseEvent, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->windowId = windowId;
}

int32_t OH_Input_GetMouseEventWindowId(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->windowId;
}

void OH_Input_SetMouseEventDisplayId(struct Input_MouseEvent* mouseEvent, int32_t displayId)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->displayId = displayId;
}

int32_t OH_Input_GetMouseEventDisplayId(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, RET_ERR);
    return mouseEvent->displayId;
}

void OH_Input_SetMouseEventGlobalX(struct Input_MouseEvent* mouseEvent, int32_t globalX)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->globalX = globalX;
}

int32_t OH_Input_GetMouseEventGlobalX(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, INT32_MAX);
    return mouseEvent->globalX;
}

void OH_Input_SetMouseEventGlobalY(struct Input_MouseEvent* mouseEvent, int32_t globalY)
{
    CALL_DEBUG_ENTER;
    CHKPV(mouseEvent);
    mouseEvent->globalY = globalY;
}

int32_t OH_Input_GetMouseEventGlobalY(const struct Input_MouseEvent* mouseEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(mouseEvent, INT32_MAX);
    return mouseEvent->globalY;
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
    OHOS::MMI::PointerEvent::PointerItem &item, int32_t useCoordinate)
{
    CALL_DEBUG_ENTER;
    int32_t id = touchEvent->id;
    int32_t screenX = touchEvent->displayX;
    int32_t screenY = touchEvent->displayY;
    if (useCoordinate == PointerEvent::DISPLAY_COORDINATE && (screenX < 0 || screenY < 0)) {
        MMI_HILOGE("touch parameter is less 0, can not process");
        return INPUT_PARAMETER_ERROR;
    }
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
    int32_t globalX = touchEvent->globalX;
    int32_t globalY = touchEvent->globalY;
    if (globalX != INT32_MAX && globalY != INT32_MAX) {
        item.SetGlobalX(globalX);
        item.SetGlobalY(globalY);
    } else {
        item.SetGlobalX(DBL_MAX);
        item.SetGlobalY(DBL_MAX);
    }
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
    result = HandleTouchProperty(touchEvent, item, PointerEvent::DISPLAY_COORDINATE);
    if (result != 0) {
        return INPUT_PARAMETER_ERROR;
    }
    g_touchEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_touchEvent, true,
        PointerEvent::DISPLAY_COORDINATE);
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

int32_t OH_Input_InjectTouchEventGlobal(const struct Input_TouchEvent* touchEvent)
{
    MMI_HILOGD("injectTouchEvent global");
    CHKPR(touchEvent, INPUT_PARAMETER_ERROR);
    CHKPR(g_touchEvent, INPUT_PARAMETER_ERROR);
    g_touchEvent->ClearFlag();
    OHOS::MMI::PointerEvent::PointerItem item;
    int32_t result = HandleTouchAction(touchEvent, item);
    if (result != 0) {
        return INPUT_PARAMETER_ERROR;
    }
    result = HandleTouchProperty(touchEvent, item, PointerEvent::GLOBAL_COORDINATE);
    if (result != 0) {
        return INPUT_PARAMETER_ERROR;
    }
    if (!item.IsValidGlobalXY()) {
        return INPUT_PARAMETER_ERROR;
    }
    g_touchEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    result = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SimulateInputEvent(g_touchEvent, true,
        PointerEvent::GLOBAL_COORDINATE);
    if (touchEvent->action == TOUCH_ACTION_UP) {
        g_touchEvent->RemovePointerItem(g_touchEvent->GetPointerId());
        MMI_HILOGD("This touch event is up remove this finger");
        if (g_touchEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch event is final finger up remove this finger");
            g_touchEvent->Reset();
        }
    }
    if ((result == INPUT_PERMISSION_DENIED) || (result == INPUT_OCCUPIED_BY_OTHER)) {
        MMI_HILOGE("Permission denied or occupied by other");
        return INPUT_PERMISSION_DENIED;
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

void OH_Input_SetTouchEventWindowId(struct Input_TouchEvent* touchEvent, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->windowId = windowId;
}

int32_t OH_Input_GetTouchEventWindowId(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->windowId;
}

void OH_Input_SetTouchEventDisplayId(struct Input_TouchEvent* touchEvent, int32_t displayId)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->displayId = displayId;
}

int32_t OH_Input_GetTouchEventDisplayId(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    return touchEvent->displayId;
}

void OH_Input_SetTouchEventGlobalX(struct Input_TouchEvent* touchEvent, int32_t globalX)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->globalX = globalX;
}

int32_t OH_Input_GetTouchEventGlobalX(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, INT32_MAX);
    return touchEvent->globalX;
}

void OH_Input_SetTouchEventGlobalY(struct Input_TouchEvent* touchEvent, int32_t globalY)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    touchEvent->globalY = globalY;
}

int32_t OH_Input_GetTouchEventGlobalY(const struct Input_TouchEvent* touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, INT32_MAX);
    return touchEvent->globalY;
}

void OH_Input_CancelInjection()
{
    CALL_DEBUG_ENTER;
    OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().CancelInjection();
}

static bool SetAxisValueByAxisEventType(std::shared_ptr<OHOS::MMI::PointerEvent> event,
    struct Input_AxisEvent *axisEvent, int32_t axisEventType)
{
    CHKPF(event);
    CHKPF(axisEvent);
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
        MMI_HILOGE("Undefined axisEventType:%{public}d", axisEventType);
        return false;
    }
    axisEvent->axisEventType = axisEventType;
    return true;
}

static bool IsAxisEvent(int32_t action)
{
    if (action != OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
        action != OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        action != OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END) {
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
        MMI_HILOGE("There is no axis value of axisType:%{public}d in the axisEvent", axisType);
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

Input_Result OH_Input_SetAxisEventWindowId(Input_AxisEvent* axisEvent, int32_t windowId)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->windowId = windowId;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventWindowId(const Input_AxisEvent* axisEvent, int32_t* windowId)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(windowId, INPUT_PARAMETER_ERROR);
    *windowId = axisEvent->windowId;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventDisplayId(Input_AxisEvent* axisEvent, int32_t displayId)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->displayId = displayId;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventDisplayId(const Input_AxisEvent* axisEvent, int32_t* displayId)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(displayId, INPUT_PARAMETER_ERROR);
    *displayId = axisEvent->displayId;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventGlobalX(struct Input_AxisEvent* axisEvent, int32_t globalX)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->globalX = globalX;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventGlobalX(const Input_AxisEvent* axisEvent, int32_t* globalX)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(globalX, INPUT_PARAMETER_ERROR);
    *globalX = axisEvent->globalX;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetAxisEventGlobalY(struct Input_AxisEvent* axisEvent, int32_t globalY)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    axisEvent->globalY = globalY;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetAxisEventGlobalY(const Input_AxisEvent* axisEvent, int32_t* globalY)
{
    CHKPR(axisEvent, INPUT_PARAMETER_ERROR);
    CHKPR(globalY, INPUT_PARAMETER_ERROR);
    *globalY = axisEvent->globalY;
    return INPUT_SUCCESS;
}

static Input_Result NormalizeResult(int32_t result)
{
    if (result < RET_OK) {
        if (result == OHOS::MMI::ERROR_NO_PERMISSION) {
            MMI_HILOGE("permission denied");
            return INPUT_PERMISSION_DENIED;
        }
        return INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}

static Input_Result NormalizeHookResult(int32_t result)
{
    if (result == RET_OK) {
        return INPUT_SUCCESS;
    }
    switch (result) {
        case OHOS::MMI::ERROR_NO_PERMISSION: {
            MMI_HILOGE("permission denied");
            return INPUT_PERMISSION_DENIED;
        }
        case OHOS::MMI::ERROR_UNSUPPORT: {
            MMI_HILOGE("Not supported");
            return INPUT_DEVICE_NOT_SUPPORTED;
        }
        case OHOS::MMI::ERROR_REPEAT_INTERCEPTOR: {
            MMI_HILOGE("Interceptor repeat");
            return INPUT_REPEAT_INTERCEPTOR;
        }
        case OHOS::MMI::ERROR_INVALID_PARAMETER: {
            MMI_HILOGE("Invalid parameter");
            return INPUT_PARAMETER_ERROR;
        }
        default: {
            break;
        }
    }
    MMI_HILOGW("Unclear exception, treat as INPUT_SERVICE_EXCEPTION");
    return INPUT_SERVICE_EXCEPTION;
}

static bool SetKeyEventAction(Input_KeyEvent* keyEvent, int32_t action)
{
    CHKPF(keyEvent);
    if (action == OHOS::MMI::KeyEvent::KEY_ACTION_CANCEL) {
        keyEvent->action = KEY_ACTION_CANCEL;
    } else if (action == OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) {
        keyEvent->action = KEY_ACTION_DOWN;
    } else if (action == OHOS::MMI::KeyEvent::KEY_ACTION_UP) {
        keyEvent->action = KEY_ACTION_UP;
    } else {
        MMI_HILOGE("Invalid key event action");
        return false;
    }
    return true;
}

static void KeyEventMonitorCallback(std::shared_ptr<OHOS::MMI::KeyEvent> event)
{
    CHKPV(event);
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    CHKPV(keyEvent);
    if (!SetKeyEventAction(keyEvent, event->GetKeyAction())) {
        OH_Input_DestroyKeyEvent(&keyEvent);
        return;
    }
    keyEvent->keyCode = event->GetKeyCode();
    keyEvent->actionTime = event->GetActionTime();
    keyEvent->windowId = event->GetTargetWindowId();
    keyEvent->displayId = event->GetTargetDisplayId();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_keyMonitorCallbacks) {
        callback(keyEvent);
    }
    OH_Input_DestroyKeyEvent(&keyEvent);
}

static Input_KeyEventCallback GetHookCallback()
{
    std::lock_guard guard(g_mutex);
    return g_keyEventHookCallback;
}

static void SetHookCallback(Input_KeyEventCallback hookCallback)
{
    std::lock_guard guard(g_mutex);
    g_keyEventHookCallback = hookCallback;
}

static void KeyEventHookCallback(std::shared_ptr<OHOS::MMI::KeyEvent> event)
{
    CHKPV(event);
    Input_KeyEvent* keyEvent = OH_Input_CreateKeyEvent();
    CHKPV(keyEvent);
    if (!SetKeyEventAction(keyEvent, event->GetKeyAction())) {
        OH_Input_DestroyKeyEvent(&keyEvent);
        return;
    }
    keyEvent->id = event->GetId();
    keyEvent->keyCode = event->GetKeyCode();
    keyEvent->actionTime = event->GetActionTime();
    keyEvent->windowId = event->GetTargetWindowId();
    keyEvent->displayId = event->GetTargetDisplayId();
    auto hookCallback = GetHookCallback();
    if (hookCallback != nullptr) {
        hookCallback(keyEvent);
    }
    OH_Input_DestroyKeyEvent(&keyEvent);
}

static bool IsScreenCaptureWorking()
{
    CALL_DEBUG_ENTER;
#ifdef PLAYER_FRAMEWORK_EXISTS
    int32_t pid = OHOS::IPCSkeleton::GetCallingPid();
    std::list<int32_t> pidList = OHOS::Media::ScreenCaptureMonitor::GetInstance()->IsScreenCaptureWorking();
    for (const auto &capturePid : pidList) {
        MMI_HILOGI("Current screen capture work pid %{public}d ", capturePid);
        if (capturePid == pid) {
            return true;
        } else {
            MMI_HILOGE("Calling pid is:%{public}d, but screen capture pid is:%{public}d", pid, capturePid);
        }
    }
    return false;
#else
    return false;
#endif // PLAYER_FRAMEWORK_EXISTS
}

Input_Result OH_Input_AddKeyEventMonitor(Input_KeyEventCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    if (!OHOS::MMI::PermissionHelper::GetInstance()->VerifySystemApp()) {
        if (!IsScreenCaptureWorking()) {
            MMI_HILOGE("The screen capture is not working");
            return INPUT_PERMISSION_DENIED;
        }
    }
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

static bool SetTouchEventAction(Input_TouchEvent* touchEvent, int32_t action)
{
    CHKPF(touchEvent);
    switch (action) {
        case OHOS::MMI::PointerEvent::POINTER_ACTION_CANCEL:
            touchEvent->action = TOUCH_ACTION_CANCEL;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_DOWN:
            touchEvent->action = TOUCH_ACTION_DOWN;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE:
            touchEvent->action = TOUCH_ACTION_MOVE;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_UP:
            touchEvent->action = TOUCH_ACTION_UP;
            break;
        default:
            MMI_HILOGE("Invalid touch event action");
            return false;
    }
    return true;
}

static void TouchEventMonitorCallback(std::shared_ptr<OHOS::MMI::PointerEvent> event)
{
    CHKPV(event);
    Input_TouchEvent* touchEvent = OH_Input_CreateTouchEvent();
    CHKPV(touchEvent);
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    if (!SetTouchEventAction(touchEvent, event->GetPointerAction())) {
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    touchEvent->id = event->GetPointerId();
    touchEvent->displayX = item.GetDisplayX();
    touchEvent->displayY = item.GetDisplayY();
    touchEvent->globalX = item.GetGlobalX();
    touchEvent->globalY = item.GetGlobalY();
    touchEvent->actionTime = event->GetActionTime();
    touchEvent->windowId = event->GetTargetWindowId();
    touchEvent->displayId = event->GetTargetDisplayId();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_touchMonitorCallbacks) {
        callback(touchEvent);
    }
    OH_Input_DestroyTouchEvent(&touchEvent);
}

static bool SetMouseEventAction(Input_MouseEvent* mouseEvent, int32_t action)
{
    CHKPF(mouseEvent);
    switch (action) {
        case OHOS::MMI::PointerEvent::POINTER_ACTION_CANCEL:
            mouseEvent->action = MOUSE_ACTION_CANCEL;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE:
            mouseEvent->action = MOUSE_ACTION_MOVE;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_DOWN:
            mouseEvent->action = MOUSE_ACTION_BUTTON_DOWN;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_BUTTON_UP:
            mouseEvent->action = MOUSE_ACTION_BUTTON_UP;
            break;
        default:
            MMI_HILOGE("Invalid mouse event action");
            return false;
    }
    return true;
}

static bool SetMouseEventButton(Input_MouseEvent* mouseEvent, int32_t button)
{
    CHKPF(mouseEvent);
    switch (button) {
        case OHOS::MMI::PointerEvent::BUTTON_NONE:
            mouseEvent->button = MOUSE_BUTTON_NONE;
            break;
        case OHOS::MMI::PointerEvent::MOUSE_BUTTON_LEFT:
            mouseEvent->button = MOUSE_BUTTON_LEFT;
            break;
        case OHOS::MMI::PointerEvent::MOUSE_BUTTON_MIDDLE:
            mouseEvent->button = MOUSE_BUTTON_MIDDLE;
            break;
        case OHOS::MMI::PointerEvent::MOUSE_BUTTON_RIGHT:
            mouseEvent->button = MOUSE_BUTTON_RIGHT;
            break;
        case OHOS::MMI::PointerEvent::MOUSE_BUTTON_FORWARD:
            mouseEvent->button = MOUSE_BUTTON_FORWARD;
            break;
        case OHOS::MMI::PointerEvent::MOUSE_BUTTON_BACK:
            mouseEvent->button = MOUSE_BUTTON_BACK;
            break;
        default:
            MMI_HILOGE("Invalid mouse event button");
            return false;
    }
    return true;
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
    if (!SetMouseEventAction(mouseEvent, event->GetPointerAction())) {
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    if (!SetMouseEventButton(mouseEvent, event->GetButtonId())) {
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    mouseEvent->displayX = item.GetDisplayX();
    mouseEvent->displayY = item.GetDisplayY();
    mouseEvent->globalX = item.GetGlobalX();
    mouseEvent->globalY = item.GetGlobalY();
    mouseEvent->actionTime = event->GetActionTime();
    mouseEvent->windowId = event->GetTargetWindowId();
    mouseEvent->displayId = event->GetTargetDisplayId();
    std::lock_guard guard(g_mutex);
    for (auto &callback : g_mouseMonitorCallbacks) {
        callback(mouseEvent);
    }
    OH_Input_DestroyMouseEvent(&mouseEvent);
}

static void SetAxisEventAction(Input_AxisEvent* axisEvent, int32_t action)
{
    CHKPV(axisEvent);
    switch (action) {
        case OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_BEGIN:
            axisEvent->axisAction = AXIS_ACTION_BEGIN;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_UPDATE:
            axisEvent->axisAction = AXIS_ACTION_UPDATE;
            break;
        case OHOS::MMI::PointerEvent::POINTER_ACTION_AXIS_END:
            axisEvent->axisAction = AXIS_ACTION_END;
            break;
        default:
            break;
    }
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
    SetAxisEventAction(axisEvent, event->GetPointerAction());
    axisEvent->displayX = item.GetDisplayX();
    axisEvent->displayY = item.GetDisplayY();
    axisEvent->globalX = item.GetGlobalX();
    axisEvent->globalY = item.GetGlobalY();
    axisEvent->actionTime = event->GetActionTime();
    axisEvent->sourceType = event->GetSourceType();
    axisEvent->windowId = event->GetTargetWindowId();
    axisEvent->displayId = event->GetTargetDisplayId();
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
            MMI_HILOGE("Add pointer event monitor failed");
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
    if (!OHOS::MMI::PermissionHelper::GetInstance()->VerifySystemApp()) {
        if (!IsScreenCaptureWorking()) {
            MMI_HILOGE("The screen capture is not working");
            return INPUT_PERMISSION_DENIED;
        }
    }
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
    if (!OHOS::MMI::PermissionHelper::GetInstance()->VerifySystemApp()) {
        if (!IsScreenCaptureWorking()) {
            MMI_HILOGE("The screen capture is not working");
            return INPUT_PERMISSION_DENIED;
        }
    }
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
    if (!OHOS::MMI::PermissionHelper::GetInstance()->VerifySystemApp()) {
        if (!IsScreenCaptureWorking()) {
            MMI_HILOGE("The screen capture is not working");
            return INPUT_PERMISSION_DENIED;
        }
    }
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
    if (!OHOS::MMI::PermissionHelper::GetInstance()->VerifySystemApp()) {
        if (!IsScreenCaptureWorking()) {
            MMI_HILOGE("The screen capture is not working");
            return INPUT_PERMISSION_DENIED;
        }
    }
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
        MMI_HILOGE("The callback has not been added");
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
        MMI_HILOGE("The axis event type has not been added");
        return INPUT_PARAMETER_ERROR;
    }
    auto it = g_axisMonitorCallbacks[axisEventType].find(callback);
    if (it == g_axisMonitorCallbacks[axisEventType].end()) {
        MMI_HILOGE("The callback has not been added");
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
    if (!SetKeyEventAction(keyEvent, event->GetKeyAction())) {
        OH_Input_DestroyKeyEvent(&keyEvent);
        return;
    }
    keyEvent->keyCode = event->GetKeyCode();
    keyEvent->actionTime = event->GetActionTime();
    keyEvent->windowId = event->GetTargetWindowId();
    keyEvent->displayId = event->GetTargetDisplayId();
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
    CHKPR(g_keyInterceptor, INPUT_PARAMETER_ERROR);
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
    OHOS::MMI::PointerEvent::PointerItem item;
    if (!(event->GetPointerItem(event->GetPointerId(), item))) {
        MMI_HILOGE("Can not get pointerItem for the pointer event");
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    if (!SetTouchEventAction(touchEvent, event->GetPointerAction())) {
        OH_Input_DestroyTouchEvent(&touchEvent);
        return;
    }
    touchEvent->id = event->GetPointerId();
    touchEvent->displayX = item.GetDisplayX();
    touchEvent->displayY = item.GetDisplayY();
    touchEvent->globalX = item.GetGlobalX();
    touchEvent->globalY = item.GetGlobalY();
    touchEvent->actionTime = event->GetActionTime();
    touchEvent->windowId = event->GetTargetWindowId();
    touchEvent->displayId = event->GetTargetDisplayId();
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
    if (!SetMouseEventAction(mouseEvent, event->GetPointerAction())) {
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    if (!SetMouseEventButton(mouseEvent, event->GetButtonId())) {
        OH_Input_DestroyMouseEvent(&mouseEvent);
        return;
    }
    mouseEvent->displayX = item.GetDisplayX();
    mouseEvent->displayY = item.GetDisplayY();
    mouseEvent->globalX = item.GetGlobalX();
    mouseEvent->globalY = item.GetGlobalY();
    mouseEvent->actionTime = event->GetActionTime();
    mouseEvent->windowId = event->GetTargetWindowId();
    mouseEvent->displayId = event->GetTargetDisplayId();
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
    SetAxisEventAction(axisEvent, event->GetPointerAction());
    axisEvent->displayX = item.GetDisplayX();
    axisEvent->displayY = item.GetDisplayY();
    axisEvent->globalX = item.GetGlobalX();
    axisEvent->globalY = item.GetGlobalY();
    axisEvent->actionTime = event->GetActionTime();
    axisEvent->sourceType = event->GetSourceType();
    axisEvent->windowId = event->GetTargetWindowId();
    axisEvent->displayId = event->GetTargetDisplayId();
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
    CHKPR(g_keyInterceptor, INPUT_PARAMETER_ERROR);
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

int32_t OH_Input_GetIntervalSinceLastInput(int64_t *intervalSinceLastInput)
{
    CALL_DEBUG_ENTER;
    CHKPR(intervalSinceLastInput, INPUT_PARAMETER_ERROR);
    int64_t interval = -1;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetIntervalSinceLastInput(interval);
    *intervalSinceLastInput = interval;
    Input_Result retCode = INPUT_SUCCESS;
    retCode = NormalizeResult(ret);
    if (retCode != INPUT_SUCCESS) {
        MMI_HILOGE("Get Interval Since Last Input failed");
        return retCode;
    }
    return INPUT_SUCCESS;
}

Input_Hotkey **OH_Input_CreateAllSystemHotkeys(int32_t count)
{
    if (count <= 0) {
        MMI_HILOGE("Invalid count:%{public}d", count);
        return nullptr;
    }
    std::vector<std::unique_ptr<OHOS::MMI::KeyOption>> keyOptions;
    int32_t hotkeyCount = -1;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetAllSystemHotkeys(keyOptions, hotkeyCount);
    if (ret != RET_OK || hotkeyCount < 0) {
        MMI_HILOGE("GetAllSystemHotkeys fail");
        return nullptr;
    }
    if (count != hotkeyCount) {
        MMI_HILOGE("Parameter error");
        return nullptr;
    }
    auto hotkeys = new (std::nothrow)Input_Hotkey *[count];
    if (hotkeys == nullptr) {
        MMI_HILOGE("Memory allocation failed");
        return nullptr;
    }
    for (int32_t i = 0; i < count; ++i) {
        hotkeys[i] = new (std::nothrow)Input_Hotkey();
        if (hotkeys[i] == nullptr) {
            MMI_HILOGE("Memory allocation failed");
            for (int32_t j = 0; j < i; ++j) {
                delete hotkeys[j];
                hotkeys[j] = nullptr;
            }
            delete[] hotkeys;
            hotkeys = nullptr;
            return nullptr;
        }
    }
    std::lock_guard<std::mutex> lock(g_hotkeyCountsMutex);
    g_hotkeyCounts.insert(std::make_pair(hotkeys, count));
    return hotkeys;
}

void OH_Input_DestroyAllSystemHotkeys(Input_Hotkey **hotkeys, int32_t count)
{
    std::lock_guard<std::mutex> lock(g_hotkeyCountsMutex);
    if (g_hotkeyCounts.find(hotkeys) != g_hotkeyCounts.end()) {
        if (count != g_hotkeyCounts[hotkeys]) {
                MMI_HILOGW("Parameter inconsistency");
            }
        for (int32_t i = 0; i < g_hotkeyCounts[hotkeys]; ++i) {
            if (hotkeys[i] != nullptr) {
                delete hotkeys[i];
                hotkeys[i] = nullptr;
            }
        }
        if (hotkeys != nullptr) {
            delete[] hotkeys;
            hotkeys = nullptr;
        }
        g_hotkeyCounts.erase(hotkeys);
    }
}

Input_Result OH_Input_GetAllSystemHotkeys(Input_Hotkey **hotkey, int32_t *count)
{
    CALL_DEBUG_ENTER;
    CHKPR(count, INPUT_PARAMETER_ERROR);
    std::vector<std::unique_ptr<OHOS::MMI::KeyOption>> keyOptions;
    int32_t hotkeyCount = -1;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetAllSystemHotkeys(keyOptions, hotkeyCount);
    if (ret != RET_OK || hotkeyCount < 0) {
        MMI_HILOGE("GetAllSystemHotkeys fail");
        return INPUT_SERVICE_EXCEPTION;
    }
    if (hotkey == nullptr) {
        *count = static_cast<int32_t>(hotkeyCount);
        MMI_HILOGD("Hot key count:%{public}d", *count);
        return INPUT_SUCCESS;
    }
    if ((static_cast<int32_t>(hotkeyCount) != *count) && (*count <= 0)) {
        MMI_HILOGE("Count:%{public}d is invalid, should be:%{public}d", *count, hotkeyCount);
        return INPUT_PARAMETER_ERROR;
    }
    for (int32_t i = 0; i < hotkeyCount; ++i) {
        if (hotkey[i] == nullptr) {
            MMI_HILOGE("Hotkey is null, i:%{public}d", i);
            return INPUT_PARAMETER_ERROR;
        }
        hotkey[i]->preKeys = keyOptions[i]->GetPreKeys();
        hotkey[i]->finalKey = keyOptions[i]->GetFinalKey();
    }
    return INPUT_SUCCESS;
}

Input_Hotkey* OH_Input_CreateHotkey(void)
{
    CALL_DEBUG_ENTER;
    Input_Hotkey* hotkey = new (std::nothrow) Input_Hotkey();
    CHKPP(hotkey);
    return hotkey;
}

void OH_Input_DestroyHotkey(Input_Hotkey **hotkey)
{
    CALL_DEBUG_ENTER;
    CHKPV(hotkey);
    CHKPV(*hotkey);
    delete *hotkey;
    *hotkey = nullptr;
}

void OH_Input_SetPreKeys(Input_Hotkey *hotkey, int32_t *preKeys, int32_t size)
{
    CALL_DEBUG_ENTER;
    CHKPV(hotkey);
    CHKPV(preKeys);
    if (size <= 0) {
        MMI_HILOGE("PreKeys does not exist");
        return;
    }

    for (int32_t i = 0; i < size; ++i) {
        hotkey->preKeys.insert(preKeys[i]);
    }
    return;
}

Input_Result OH_Input_GetPreKeys(const Input_Hotkey *hotkey, int32_t **preKeys, int32_t *preKeyCount)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(preKeys, INPUT_PARAMETER_ERROR);
    CHKPR(*preKeys, INPUT_PARAMETER_ERROR);
    CHKPR(preKeyCount, INPUT_PARAMETER_ERROR);
    std::set<int32_t> preKey = hotkey->preKeys;
    if (preKey.empty()) {
        MMI_HILOGE("The pressKeys not exit");
        return INPUT_SERVICE_EXCEPTION;
    }
    int32_t index = 0;
    for (auto it = preKey.begin(); it != preKey.end(); ++it) {
        *preKeys[index++] = *it;
    }
    *preKeyCount = index;
    return INPUT_SUCCESS;
}

void OH_Input_SetFinalKey(Input_Hotkey *hotkey, int32_t finalKey)
{
    CALL_DEBUG_ENTER;
    CHKPV(hotkey);
    hotkey->finalKey = finalKey;
    return;
}

Input_Result OH_Input_GetFinalKey(const Input_Hotkey *hotkey, int32_t *finalKeyCode)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(finalKeyCode, INPUT_PARAMETER_ERROR);
    *finalKeyCode = hotkey->finalKey;
    return INPUT_SUCCESS;
}

void OH_Input_SetRepeat(Input_Hotkey* hotkey, bool isRepeat)
{
    CALL_DEBUG_ENTER;
    CHKPV(hotkey);
    hotkey->isRepeat = isRepeat;
}

Input_Result OH_Input_GetRepeat(const Input_Hotkey* hotkey, bool *isRepeat)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(isRepeat, INPUT_PARAMETER_ERROR);
    *isRepeat = hotkey->isRepeat;
    return INPUT_SUCCESS;
}

std::string GetHotkeyName(std::set<int32_t> preKeys, int32_t finalKey, bool isRepeat,
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    bool isFinalKeyDown = true;
    int32_t keyDownDuration = 0;
    keyOption->SetPreKeys(preKeys);
    keyOption->SetFinalKey(finalKey);
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    keyOption->SetFinalKeyDownDuration(keyDownDuration);
    keyOption->SetRepeat(isRepeat);
    std::string hotkeyName;
    for (const auto &item : preKeys) {
        hotkeyName += std::to_string(item);
        hotkeyName += ",";
    }
    hotkeyName += std::to_string(finalKey);
    hotkeyName += ",";
    hotkeyName += std::to_string(isFinalKeyDown);
    hotkeyName += ",";
    hotkeyName += std::to_string(keyDownDuration);
    hotkeyName += ",";
    hotkeyName += std::to_string(isRepeat);
    return hotkeyName;
}

static int32_t MakeHotkeyInfo(const Input_Hotkey* hotkey, Input_HotkeyInfo* hotkeyInfo,
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);
    CHKPR(keyOption, INPUT_PARAMETER_ERROR);

    if (hotkey->preKeys.empty()) {
        MMI_HILOGE("PressedKeys not found");
        return INPUT_PARAMETER_ERROR;
    }
    std::set<int32_t> preKeys = hotkey->preKeys;
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("PreKeys size invalid");
        return INPUT_PARAMETER_ERROR;
    }
    for (const auto &item : preKeys) {
        auto it = std::find(g_pressKeyCodes.begin(), g_pressKeyCodes.end(), item);
        if (it == g_pressKeyCodes.end()) {
            MMI_HILOGE("PreKeys is not expect");
            return INPUT_PARAMETER_ERROR;
        }
    }

    int32_t finalKey = hotkey->finalKey;
    if (finalKey < 0) {
        MMI_HILOGE("FinalKey:%{private}d is less 0, can not process", finalKey);
        return INPUT_PARAMETER_ERROR;
    }
    auto it = std::find(g_finalKeyCodes.begin(), g_finalKeyCodes.end(), finalKey);
    if (it != g_finalKeyCodes.end()) {
        MMI_HILOGE("FinalKey is not expect");
        return INPUT_PARAMETER_ERROR;
    }

    bool isRepeat = hotkey->isRepeat;
    std::string hotkeyName = GetHotkeyName(preKeys, finalKey, isRepeat, keyOption);
    hotkeyInfo->hotkeyId = hotkeyName;
    MMI_HILOGI("HotkeyId is :%{private}s", hotkeyInfo->hotkeyId.c_str());
    return INPUT_SUCCESS;
}

static int32_t GetSubscribeId(Input_HotkeyInfo* hotkeyInfo)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);

    auto it = g_callbacks.find(hotkeyInfo->hotkeyId);
    if (it == g_callbacks.end() || it->second.empty()) {
        MMI_HILOGD("The callbacks is empty");
        return INPUT_PARAMETER_ERROR;
    }

    CHKPR(it->second.front(), INPUT_PARAMETER_ERROR);
    return it->second.front()->subscribeId;
}

static int32_t AddHotkeySubscribe(Input_HotkeyInfo* hotkeyInfo)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);
    if (g_callbacks.find(hotkeyInfo->hotkeyId) == g_callbacks.end()) {
        MMI_HILOGD("No callback in %{private}s", hotkeyInfo->hotkeyId.c_str());
        g_callbacks[hotkeyInfo->hotkeyId] = {};
    }
    auto it = g_callbacks.find(hotkeyInfo->hotkeyId);
    if (it != g_callbacks.end()) {
        for (const auto &iter: it->second) {
            if (iter->callback == hotkeyInfo->callback) {
                MMI_HILOGI("Callback already exist");
                return INPUT_PARAMETER_ERROR;
            }
        }
    }
    it->second.push_back(hotkeyInfo);
    return INPUT_SUCCESS;
}

static bool CheckHotkey(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent, std::string &hotkeyEventName)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);

    int32_t keyEventFinalKey = keyEvent->GetKeyCode();
    std::vector<OHOS::MMI::KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    if (items.size() > KEYS_SIZE || keyEvent->GetKeyAction() != OHOS::MMI::KeyEvent::KEY_ACTION_DOWN) {
        MMI_HILOGE("Prekeys num more than three or finalkey is not down");
        return false;
    }

    bool isFinalKeyDown = true;
    int32_t keyDownDuration = 0;
    std::string hotkeyName;
    bool isRepeat = keyEvent->IsRepeat();
    std::set<int32_t> presskeys;
    for (const auto &item : items) {
        presskeys.insert(item.GetKeyCode());
    }
    for (const auto &item : presskeys) {
        if (item == keyEventFinalKey) {
            continue;
        }
        hotkeyName += std::to_string(item);
        hotkeyName += ",";
    }
    hotkeyName += std::to_string(keyEventFinalKey);
    hotkeyName += ",";
    hotkeyName += std::to_string(isFinalKeyDown);
    hotkeyName += ",";
    hotkeyName += std::to_string(keyDownDuration);
    hotkeyName += ",";
    hotkeyName += std::to_string(isRepeat);
    hotkeyEventName = hotkeyName;
    MMI_HILOGD("HotkeyEventName:%{private}s", hotkeyEventName.c_str());
    return true;
}

static void OnNotifyCallbackWorkResult(Input_HotkeyInfo* reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);

    Input_HotkeyInfo *info = new(std::nothrow) Input_HotkeyInfo();
    CHKPV(info);
    info->keyOption = reportEvent->keyOption;
    if (info->keyOption == nullptr) {
        delete info;
        info = nullptr;
        MMI_HILOGE("KeyOption is null");
        return;
    }
    info->callback = reportEvent->callback;
    if (info->callback == nullptr) {
        delete info;
        info = nullptr;
        MMI_HILOGE("Callback is null");
        return;
    }

    Input_Hotkey hotkey;
    hotkey.preKeys = info->keyOption->GetPreKeys();
    hotkey.finalKey = info->keyOption->GetFinalKey();
    hotkey.isRepeat = info->keyOption->IsRepeat();
    info->callback(&hotkey);
    delete info;
    info = nullptr;
}

static void HandleKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(g_CallBacksMutex);
    std::string hotkeyEventName;
    if (CheckHotkey(keyEvent, hotkeyEventName)) {
        auto list = g_callbacks[hotkeyEventName];
        MMI_HILOGD("Callback list size:%{public}zu", list.size());
        for (const auto &info : list) {
            if (info->hotkeyId == hotkeyEventName) {
                OnNotifyCallbackWorkResult(info);
            }
        }
    }
}

Input_Result OH_Input_AddHotkeyMonitor(const Input_Hotkey* hotkey, Input_HotkeyCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_CallBacksMutex);

    Input_HotkeyInfo *hotkeyInfo = new (std::nothrow) Input_HotkeyInfo();
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);
    auto keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    if (MakeHotkeyInfo(hotkey, hotkeyInfo, keyOption) != INPUT_SUCCESS) {
        delete hotkeyInfo;
        hotkeyInfo = nullptr;
        MMI_HILOGE("MakeHotkeyInfo failed");
        return INPUT_PARAMETER_ERROR;
    }
    hotkeyInfo->keyOption = keyOption;
    hotkeyInfo->callback = callback;
    int32_t preSubscribeId = GetSubscribeId(hotkeyInfo);
    if (preSubscribeId == INPUT_PARAMETER_ERROR) {
        MMI_HILOGD("HotkeyId:%{private}s", hotkeyInfo->hotkeyId.c_str());
        int32_t subscribeId = -1;
        subscribeId = OHOS::MMI::InputManager::GetInstance()->SubscribeHotkey(keyOption, HandleKeyEvent);
        if (subscribeId == OHOS::MMI::ERROR_UNSUPPORT) {
            delete hotkeyInfo;
            hotkeyInfo = nullptr;
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            return INPUT_DEVICE_NOT_SUPPORTED;
        }
        if (subscribeId == OCCUPIED_BY_SYSTEM) {
            delete hotkeyInfo;
            hotkeyInfo = nullptr;
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            return INPUT_OCCUPIED_BY_SYSTEM;
        }
        if (subscribeId == OCCUPIED_BY_OTHER) {
            delete hotkeyInfo;
            hotkeyInfo = nullptr;
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            return INPUT_OCCUPIED_BY_OTHER;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        hotkeyInfo->subscribeId = subscribeId;
    } else {
        hotkeyInfo->subscribeId = preSubscribeId;
    }
    if (AddHotkeySubscribe(hotkeyInfo) != INPUT_SUCCESS) {
        delete hotkeyInfo;
        hotkeyInfo = nullptr;
        MMI_HILOGE("AddHotkeySubscribe fail");
        return INPUT_PARAMETER_ERROR;
    }
    return INPUT_SUCCESS;
}

int32_t DelHotkeyMonitor(std::list<Input_HotkeyInfo *> &infos,
    Input_HotkeyCallback callback, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(&infos, INPUT_PARAMETER_ERROR);
    CHKPR(callback, INPUT_PARAMETER_ERROR);

    auto iter = infos.begin();
    while (iter != infos.end()) {
        if (*iter == nullptr) {
            iter = infos.erase(iter);
            continue;
        }
        if (callback == nullptr) {
            Input_HotkeyInfo *monitorInfo = *iter;
            infos.erase(iter++);
            if (infos.empty()) {
                subscribeId = monitorInfo->subscribeId;
            }
            delete monitorInfo;
            monitorInfo = nullptr;
            MMI_HILOGD("Callback has been deleted, size:%{public}zu", infos.size());
            continue;
        }
        if ((*iter)->callback == callback) {
            Input_HotkeyInfo *monitorInfo = *iter;
            iter = infos.erase(iter);
            if (infos.empty()) {
                subscribeId = monitorInfo->subscribeId;
            }
            delete monitorInfo;
            monitorInfo = nullptr;
            MMI_HILOGD("Callback has been deleted, size:%{public}zu", infos.size());
            return INPUT_SUCCESS;
        }
        ++iter;
    }
    return INPUT_SUCCESS;
}

int32_t DelEventCallback(Input_HotkeyInfo* hotkeyInfo, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);
    if (g_callbacks.count(hotkeyInfo->hotkeyId) <= 0) {
        MMI_HILOGE("Callback doesn't exists");
        return INPUT_PARAMETER_ERROR;
    }
    auto &info = g_callbacks[hotkeyInfo->hotkeyId];
    MMI_HILOGD("HotkeyId is :%{private}s, Input_HotkeyInfo:%{public}zu", hotkeyInfo->hotkeyId.c_str(), info.size());
    return DelHotkeyMonitor(info, hotkeyInfo->callback, subscribeId);
}

Input_Result OH_Input_RemoveHotkeyMonitor(const Input_Hotkey *hotkey, Input_HotkeyCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(hotkey, INPUT_PARAMETER_ERROR);
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_CallBacksMutex);

    Input_HotkeyInfo *hotkeyInfo = new (std::nothrow) Input_HotkeyInfo();
    CHKPR(hotkeyInfo, INPUT_PARAMETER_ERROR);
    auto keyOption = std::make_shared<OHOS::MMI::KeyOption>();
    if (MakeHotkeyInfo(hotkey, hotkeyInfo, keyOption) != INPUT_SUCCESS) {
        delete hotkeyInfo;
        hotkeyInfo = nullptr;
        MMI_HILOGE("MakeHotkeyInfo failed");
        return INPUT_PARAMETER_ERROR;
    }
    hotkeyInfo->callback = callback;
    int32_t subscribeId = -1;
    if (DelEventCallback(hotkeyInfo, subscribeId) != INPUT_SUCCESS) {
        delete hotkeyInfo;
        hotkeyInfo = nullptr;
        MMI_HILOGE("DelEventCallback failed");
        return INPUT_SERVICE_EXCEPTION;
    }
    MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
    if (subscribeId >= 0) {
        OHOS::MMI::InputManager::GetInstance()->UnsubscribeHotkey(subscribeId);
    }
    delete hotkeyInfo;
    hotkeyInfo = nullptr;
    return INPUT_SUCCESS;
}

static void DeviceAddedCallback(int32_t deviceId, const std::string& Type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(g_DeviceListerCallbackMutex);
    for (auto listener : g_ohDeviceListenerList) {
        if (listener == nullptr) {
            MMI_HILOGE("listener is nullptr");
            continue;
        }
        if (listener->deviceAddedCallback == nullptr) {
            MMI_HILOGE("OnDeviceAdded is nullptr");
            continue;
        }
        listener->deviceAddedCallback(deviceId);
    }
}

static void DeviceRemovedCallback(int32_t deviceId, const std::string& Type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(g_DeviceListerCallbackMutex);
    for (auto listener : g_ohDeviceListenerList) {
        if (listener == nullptr) {
            MMI_HILOGE("listener is nullptr");
            continue;
        }
        if (listener->deviceRemovedCallback == nullptr) {
            MMI_HILOGE("OnDeviceRemoved is nullptr");
            continue;
        }
        listener->deviceRemovedCallback(deviceId);
    }
}

Input_Result OH_Input_RegisterDeviceListener(Input_DeviceListener* listener)
{
    CALL_DEBUG_ENTER;
    if (listener == nullptr || listener->deviceAddedCallback == nullptr ||
        listener->deviceRemovedCallback == nullptr) {
        MMI_HILOGE("listener or callback is nullptr");
        return INPUT_PARAMETER_ERROR;
    }
    std::lock_guard guard(g_DeviceListerCallbackMutex);
    if (g_ohDeviceListenerList.empty()) {
        int32_t ret = OHOS::MMI::InputManager::GetInstance()->RegisterDevListener("change", g_deviceListener);
        g_deviceListener->SetDeviceAddedCallback(DeviceAddedCallback);
        g_deviceListener->SetDeviceRemovedCallback(DeviceRemovedCallback);
        if (ret != RET_OK) {
            MMI_HILOGE("RegisterDevListener fail");
            return INPUT_SERVICE_EXCEPTION;
        }
    }
    g_ohDeviceListenerList.insert(listener);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_UnregisterDeviceListener(Input_DeviceListener* listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, INPUT_PARAMETER_ERROR);
    std::lock_guard guard(g_DeviceListerCallbackMutex);
    auto it = g_ohDeviceListenerList.find(listener);
    if (it == g_ohDeviceListenerList.end()) {
        MMI_HILOGE("listener not found");
        return INPUT_PARAMETER_ERROR;
    }
    g_ohDeviceListenerList.erase(it);
    if (g_ohDeviceListenerList.empty()) {
        int32_t ret = OHOS::MMI::InputManager::GetInstance()->UnregisterDevListener("change", g_deviceListener);
        if (ret != RET_OK) {
            MMI_HILOGE("UnregisterDevListener fail");
            return INPUT_SERVICE_EXCEPTION;
        }
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_UnregisterDeviceListeners()
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(g_DeviceListerCallbackMutex);
    if (g_ohDeviceListenerList.empty()) {
        return INPUT_SUCCESS;
    }
    auto ret = OHOS::MMI::InputManager::GetInstance()->UnregisterDevListener("change", g_deviceListener);
    g_ohDeviceListenerList.clear();
    if (ret != RET_OK) {
        MMI_HILOGE("UnregisterDevListener fail");
        return INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceIds(int32_t *deviceIds, int32_t inSize, int32_t *outSize)
{
    CALL_DEBUG_ENTER;
    if (inSize < 0) {
        MMI_HILOGE("Invalid inSize:%{public}d", inSize);
        return INPUT_PARAMETER_ERROR;
    }
    CHKPR(deviceIds, INPUT_PARAMETER_ERROR);
    CHKPR(outSize, INPUT_PARAMETER_ERROR);
    auto nativeCallback = [&](std::vector<int32_t> &ids) {
        auto deviceIdslength = static_cast<int32_t>(ids.size());
        if (inSize > deviceIdslength) {
            *outSize = deviceIdslength;
        }
        if (inSize < deviceIdslength) {
            *outSize = inSize;
        }
        for (int32_t i = 0; i < *outSize; ++i) {
            *(deviceIds + i) = ids[i];
        }
    };
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetDeviceIds(nativeCallback);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDeviceIds fail");
        return INPUT_PARAMETER_ERROR;
    }
    return INPUT_SUCCESS;
}

Input_DeviceInfo* OH_Input_CreateDeviceInfo(void)
{
    CALL_DEBUG_ENTER;
    Input_DeviceInfo* deviceInfo = new (std::nothrow) Input_DeviceInfo();
    CHKPP(deviceInfo);
    return deviceInfo;
}

void OH_Input_DestroyDeviceInfo(Input_DeviceInfo **deviceInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(deviceInfo);
    CHKPV(*deviceInfo);
    delete *deviceInfo;
    *deviceInfo = nullptr;
}

Input_Result OH_Input_GetDevice(int32_t deviceId, Input_DeviceInfo **deviceInfo)
{
    CALL_DEBUG_ENTER;
    if (deviceId < 0) {
        MMI_HILOGE("Invalid deviceId:%{public}d", deviceId);
        return INPUT_PARAMETER_ERROR;
    }
    CHKPR(*deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    auto nativeCallback = [deviceInfo](std::shared_ptr<OHOS::MMI::InputDevice> device) {
        CHKPV(*deviceInfo);
        (*deviceInfo)->id = device->GetId();
        if (strcpy_s((*deviceInfo)->name, device->GetName().size() + 1, device->GetName().c_str()) != EOK) {
            MMI_HILOGE("strcpy_s error");
            return;
        }
        (*deviceInfo)->product = device->GetProduct();
        (*deviceInfo)->vendor = device->GetVendor();
        (*deviceInfo)->version = device->GetVersion();
        if (strcpy_s((*deviceInfo)->phys, device->GetPhys().size() + 1, device->GetPhys().c_str()) != EOK) {
            MMI_HILOGE("strcpy_s error");
            return;
        }
        (*deviceInfo)->ability = device->GetType();
    };
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetDevice(deviceId, nativeCallback);
    if (ret != RET_OK) {
        MMI_HILOGE("GetDevice fail");
        return INPUT_PARAMETER_ERROR;
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetKeyboardType(int32_t deviceId, int32_t *KeyboardType)
{
    CALL_DEBUG_ENTER;
    if (deviceId < 0) {
        MMI_HILOGE("Invalid deviceId:%{public}d", deviceId);
        return INPUT_PARAMETER_ERROR;
    }
    CHKPR(KeyboardType, INPUT_PARAMETER_ERROR);
    auto nativeCallback = [KeyboardType](int32_t keyboardTypes) {
        *KeyboardType = keyboardTypes;
    };
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetKeyboardType(deviceId, nativeCallback);
    if (ret != RET_OK) {
        MMI_HILOGE("GetKeyboardType fail");
        return INPUT_PARAMETER_ERROR;
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceName(Input_DeviceInfo *deviceInfo, char **name)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(name, INPUT_PARAMETER_ERROR);
    *name = deviceInfo->name;
    return INPUT_SUCCESS;
}


Input_Result OH_Input_GetDeviceAddress(Input_DeviceInfo *deviceInfo, char **address)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(address, INPUT_PARAMETER_ERROR);
    *address = deviceInfo->phys;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceId(Input_DeviceInfo *deviceInfo, int32_t *id)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(id, INPUT_PARAMETER_ERROR);
    *id = deviceInfo->id;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetCapabilities(Input_DeviceInfo *deviceInfo, int32_t *capabilities)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(capabilities, INPUT_PARAMETER_ERROR);
    *capabilities = deviceInfo->ability;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceVersion(Input_DeviceInfo *deviceInfo, int32_t *version)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(version, INPUT_PARAMETER_ERROR);
    *version = deviceInfo->version;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceProduct(Input_DeviceInfo *deviceInfo, int32_t *product)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(product, INPUT_PARAMETER_ERROR);
    *product = deviceInfo->product;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetDeviceVendor(Input_DeviceInfo *deviceInfo, int32_t *vendor)
{
    CALL_DEBUG_ENTER;
    CHKPR(deviceInfo, INPUT_PARAMETER_ERROR);
    CHKPR(vendor, INPUT_PARAMETER_ERROR);
    *vendor = deviceInfo->vendor;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetFunctionKeyState(int32_t keyCode, int32_t *state)
{
    CALL_DEBUG_ENTER;
    if (keyCode < 0 || keyCode != OHOS::MMI::FunctionKey::FUNCTION_KEY_CAPSLOCK) {
        MMI_HILOGE("Invalid code:%{private}d", keyCode);
        return INPUT_PARAMETER_ERROR;
    }
    CHKPR(state, INPUT_PARAMETER_ERROR);
    bool resultState = false;
    int32_t napiCode = OHOS::MMI::InputManager::GetInstance()->GetFunctionKeyState(keyCode, resultState);
    *state = resultState ? 1 : 0;
    if (napiCode == INPUT_KEYBOARD_DEVICE_NOT_EXIST) {
        MMI_HILOGE("GetFunctionKeyState fail, no keyboard device connected");
        return INPUT_KEYBOARD_DEVICE_NOT_EXIST;
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_QueryMaxTouchPoints(int32_t *count)
{
    CHKPR(count, INPUT_PARAMETER_ERROR);
    auto ret = OHOS::MMI::InputManager::GetInstance()->GetMaxMultiTouchPointNum(*count);
    if (ret != RET_OK) {
        *count = UNKNOWN_MAX_TOUCH_POINTS;
        MMI_HILOGE("GetMaxMultiTouchPointNum fail, error:%{public}d", ret);
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_RequestInjection(Input_InjectAuthorizeCallback callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    int32_t reqId = 0;
    int32_t status = 0;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->RequestInjection(status, reqId);
    MMI_HILOGD("RequestInjection %{public}d,%{public}d,%{public}d", ret, status, reqId);
    if (ret != RET_OK) {
        MMI_HILOGE("RequestInjection fail, error:%{public}d", ret);
        if (ret ==  OHOS::MMI::ERROR_DEVICE_NOT_SUPPORTED) {
            return INPUT_DEVICE_NOT_SUPPORTED;
        }
        if (ret ==  OHOS::MMI::ERROR_OPERATION_FREQUENT) {
            return INPUT_INJECTION_OPERATION_FREQUENT;
        }
        return INPUT_SERVICE_EXCEPTION;
    }
    AUTHORIZE_QUERY_STATE recvStatus = static_cast<AUTHORIZE_QUERY_STATE>(status);
    switch (recvStatus) {
        case AUTHORIZE_QUERY_STATE::OTHER_PID_IN_AUTHORIZATION_SELECTION:
        case AUTHORIZE_QUERY_STATE::CURRENT_PID_IN_AUTHORIZATION_SELECTION: {
            return INPUT_INJECTION_AUTHORIZING;
        }
        case AUTHORIZE_QUERY_STATE::OTHER_PID_AUTHORIZED: {
            return INPUT_INJECTION_AUTHORIZED_OTHERS;
        }
        case AUTHORIZE_QUERY_STATE::CURRENT_PID_AUTHORIZED: {
            return INPUT_INJECTION_AUTHORIZED;
        }
        case AUTHORIZE_QUERY_STATE::UNAUTHORIZED: {
            MMI_HILOGD("RequestInjection ok %{public}d", reqId);
            OHOS::MMI::InputManager::GetInstance()->InsertRequestInjectionCallback(reqId,
                [callback, reqId](int32_t status) {
                    AUTHORIZE_QUERY_STATE callStatus = static_cast<AUTHORIZE_QUERY_STATE>(status);
                    callback(callStatus == AUTHORIZE_QUERY_STATE::CURRENT_PID_AUTHORIZED ?
                        Input_InjectionStatus::AUTHORIZED : Input_InjectionStatus::UNAUTHORIZED);
                });
            return INPUT_SUCCESS;
        }
        default:
            return INPUT_SERVICE_EXCEPTION;
        }
}

Input_Result OH_Input_QueryAuthorizedStatus(Input_InjectionStatus* status)
{
    CALL_DEBUG_ENTER;
    CHKPR(status, INPUT_PARAMETER_ERROR);
    int32_t tmpStatus = 0;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->QueryAuthorizedStatus(tmpStatus);
    MMI_HILOGD("QueryAuthorizedStatus ret:%{public}d,%{public}d", ret, tmpStatus);
    if (ret != RET_OK) {
        MMI_HILOGE("QueryAuthorizedStatus fail, error:%{public}d", ret);
        return INPUT_SERVICE_EXCEPTION;
    }
    AUTHORIZE_QUERY_STATE recvStatus = static_cast<AUTHORIZE_QUERY_STATE>(tmpStatus);
    switch (recvStatus) {
        case AUTHORIZE_QUERY_STATE::OTHER_PID_IN_AUTHORIZATION_SELECTION:
        case AUTHORIZE_QUERY_STATE::OTHER_PID_AUTHORIZED:
        case AUTHORIZE_QUERY_STATE::UNAUTHORIZED: {
            *status = Input_InjectionStatus::UNAUTHORIZED;
            break;
        }
        case AUTHORIZE_QUERY_STATE::CURRENT_PID_IN_AUTHORIZATION_SELECTION: {
            *status = Input_InjectionStatus::AUTHORIZING;
            break;
        }
        case AUTHORIZE_QUERY_STATE::CURRENT_PID_AUTHORIZED: {
            *status = Input_InjectionStatus::AUTHORIZED;
            break;
        }
        default:
            MMI_HILOGE("QueryAuthorizedStatus fail, %{public}d", recvStatus);
            return INPUT_SERVICE_EXCEPTION;
        }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetPointerLocation(int32_t *displayId, double *displayX, double *displayY)
{
    CALL_DEBUG_ENTER;
    CHKPR(displayId, INPUT_PARAMETER_ERROR);
    CHKPR(displayX, INPUT_PARAMETER_ERROR);
    CHKPR(displayY, INPUT_PARAMETER_ERROR);
    int32_t tmpDisplayId = 0;
    double tmpX = 0.0;
    double tmpY = 0.0;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetPointerLocation(tmpDisplayId, tmpX, tmpY);
    if (ret != RET_OK) {
        MMI_HILOGE("Query pointer location failed, error:%{public}d", ret);
        if (ret == OHOS::MMI::ERROR_DEVICE_NO_POINTER) {
            MMI_HILOGE("The device has no pointer");
            return INPUT_DEVICE_NO_POINTER;
        }
        if (ret == OHOS::MMI::ERROR_APP_NOT_FOCUSED) {
            MMI_HILOGE("The app is not the focused app");
            return INPUT_APP_NOT_FOCUSED;
        }
        return INPUT_SERVICE_EXCEPTION;
    }
    *displayId = tmpDisplayId;
    *displayX = tmpX;
    *displayY = tmpY;
    return INPUT_SUCCESS;
}

static void TransformTouchActionDown(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent,
    OHOS::MMI::PointerEvent::PointerItem &item, int64_t time)
{
    CALL_INFO_TRACE;
    CHKPV(pointerEvent);
    auto pointIds = pointerEvent->GetPointerIds();
    if (pointIds.empty()) {
        pointerEvent->SetActionStartTime(time);
        pointerEvent->SetTargetDisplayId(0);
    }
    pointerEvent->SetActionTime(time);
    pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_DOWN);
    item.SetDownTime(time);
    item.SetPressed(true);
}

static int32_t TransformTouchAction(const struct Input_TouchEvent *touchEvent,
    std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent, OHOS::MMI::PointerEvent::PointerItem &item)
{
    CALL_INFO_TRACE;
    CHKPR(touchEvent, INPUT_PARAMETER_ERROR);
    CHKPR(pointerEvent, INPUT_PARAMETER_ERROR);
    int64_t time = touchEvent->actionTime;
    if (time < 0) {
        MMI_HILOGW("Invalid parameter for the actionTime");
        time = OHOS::MMI::GetSysClockTime();
    }
    switch (touchEvent->action) {
        case TOUCH_ACTION_CANCEL:{
            pointerEvent->SetActionTime(time);
            pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_CANCEL);
            item.SetPressed(false);
            break;
        }
        case TOUCH_ACTION_DOWN: {
            TransformTouchActionDown(pointerEvent, item, time);
            break;
        }
        case TOUCH_ACTION_MOVE: {
            pointerEvent->SetActionTime(time);
            pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
            break;
        }
        case TOUCH_ACTION_UP: {
            pointerEvent->SetActionTime(time);
            pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_UP);
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

static int32_t TransformTouchProperty(const struct Input_TouchEvent *touchEvent,
    std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent,
    OHOS::MMI::PointerEvent::PointerItem &item, int32_t windowX, int32_t windowY)
{
    CALL_INFO_TRACE;
    CHKPR(touchEvent, INPUT_PARAMETER_ERROR);
    CHKPR(pointerEvent, INPUT_PARAMETER_ERROR);
    int32_t screenX = touchEvent->displayX;
    int32_t screenY = touchEvent->displayY;
    if (screenX < 0 || screenY < 0) {
        MMI_HILOGE("touchEvent parameter is less 0, can not process");
        return INPUT_PARAMETER_ERROR;
    }
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);

    int32_t globalX = touchEvent->globalX;
    int32_t globalY = touchEvent->globalY;
    item.SetGlobalX(globalX);
    item.SetGlobalY(globalY);
    item.SetWindowX(windowX);
    item.SetWindowY(windowY);
    item.SetWindowXPos(windowX);
    item.SetWindowYPos(windowY);

    int32_t id = touchEvent->id;
    if (id < 0) {
        MMI_HILOGE("displayId is less 0, can not process");
        return INPUT_PARAMETER_ERROR;
    }
    item.SetOriginPointerId(id);
    if (id < SIMULATE_POINTER_EVENT_START_ID) {
        item.SetPointerId(id + SIMULATE_POINTER_EVENT_START_ID);
        pointerEvent->SetPointerId(id + SIMULATE_POINTER_EVENT_START_ID);
    } else {
        item.SetPointerId(id);
        pointerEvent->SetPointerId(id);
    }
    item.SetTargetWindowId(touchEvent->windowId);
    pointerEvent->SetTargetDisplayId(touchEvent->displayId);
    pointerEvent->UpdateId();
    pointerEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    if (touchEvent->action == TOUCH_ACTION_DOWN) {
        pointerEvent->AddPointerItem(item);
    } else if ((touchEvent->action == TOUCH_ACTION_MOVE) || (touchEvent->action == TOUCH_ACTION_UP) ||
        (touchEvent->action == TOUCH_ACTION_CANCEL)) {
        pointerEvent->UpdatePointerItem(id, item);
    }
    return INPUT_SUCCESS;
}

std::shared_ptr<OHOS::MMI::PointerEvent> OH_Input_TouchEventToPointerEvent(Input_TouchEvent *touchEvent,
    int32_t windowX, int32_t windowY)
{
    CALL_INFO_TRACE;
    if (touchEvent == nullptr) {
        MMI_HILOGE("touchEvent is null");
        return nullptr;
    }
    if (windowX < 0 || windowY < 0) {
        MMI_HILOGE("window coordination is less 0");
        return nullptr;
    }
    std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent = OHOS::MMI::PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEventis null");
        return nullptr;
    }
    OHOS::MMI::PointerEvent::PointerItem item;
    int32_t ret = TransformTouchAction(touchEvent, pointerEvent, item);
    if (ret != INPUT_SUCCESS) {
        return nullptr;
    }

    ret = TransformTouchProperty(touchEvent, pointerEvent, item, windowX, windowY);
    if (ret != INPUT_SUCCESS) {
        return nullptr;
    }
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_SIMULATE);
    return pointerEvent;
}

Input_Result OH_Input_GetKeyEventId(const struct Input_KeyEvent* keyEvent, int32_t* eventId)
{
    CHKPR(keyEvent, INPUT_PARAMETER_ERROR);
    CHKPR(eventId, INPUT_PARAMETER_ERROR);
    *eventId = keyEvent->id;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_AddKeyEventHook(Input_KeyEventCallback callback)
{
    CALL_INFO_TRACE;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    if (auto hookCallback = GetHookCallback(); callback == hookCallback) {
        MMI_HILOGE("Repeatedly set the hook function.");
        return INPUT_REPEAT_INTERCEPTOR;
    }
    if (g_keyEventHookId.load() != INVALID_INTERCEPTOR_ID) {
        MMI_HILOGE("Repeatedly set the hook function. A process can only have one key hook function.");
        return INPUT_REPEAT_INTERCEPTOR;
    }
    SetHookCallback(callback);
    int32_t hookId { INVALID_INTERCEPTOR_ID };
    int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().AddKeyEventHook(
        KeyEventHookCallback, hookId);
    if (ret != RET_OK) {
        auto errCode = NormalizeHookResult(ret);
        MMI_HILOGE("AddKeyEventHook failed, errCode:%{public}d", errCode);
        g_keyEventHookId.store(INVALID_INTERCEPTOR_ID);
        SetHookCallback(nullptr);
        return errCode;
    }
    g_keyEventHookId.store(hookId);
    ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().SetHookIdUpdater([](int32_t hookId) {
        MMI_HILOGI("Update keyHookId:%{public}d", hookId);
        g_keyEventHookId.store(hookId);
    });
    if (ret != RET_OK) {
        auto errCode = NormalizeHookResult(ret);
        MMI_HILOGE("SetHookIdUpdater failed, errCode:%{public}d", errCode);
        g_keyEventHookId.store(INVALID_INTERCEPTOR_ID);
        SetHookCallback(nullptr);
        return errCode;
    }
    MMI_HILOGI("OH_Input_AddKeyEventHook success, hookId:%{public}d", g_keyEventHookId.load());
    return INPUT_SUCCESS;
}

Input_Result OH_Input_RemoveKeyEventHook(Input_KeyEventCallback callback)
{
    CALL_INFO_TRACE;
    CHKPR(callback, INPUT_PARAMETER_ERROR);
    if (auto hookCallback = GetHookCallback(); hookCallback != callback) {
        MMI_HILOGE("The callback has not been added before, return success");
        return INPUT_SUCCESS;
    }
    if (int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().RemoveKeyEventHook(g_keyEventHookId);
        ret != RET_OK) {
        auto errCode = NormalizeHookResult(ret);
        MMI_HILOGE("RemoveKeyEventHook failed, service exception, keyEventHookId:%{public}d", g_keyEventHookId.load());
        return errCode;
    }
    MMI_HILOGI("OH_Input_RemoveKeyEventHook success, hookId:%{public}d", g_keyEventHookId.load());
    g_keyEventHookId.store(INVALID_INTERCEPTOR_ID);
    SetHookCallback(nullptr);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_DispatchToNextHandler(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    if (auto hookCallback = GetHookCallback(); hookCallback == nullptr ||
        g_keyEventHookId.load() == INVALID_INTERCEPTOR_ID) {
        MMI_HILOGE("No hook existed.");
        return INPUT_PARAMETER_ERROR;
    }
    if (int32_t ret = OHOS::Singleton<OHOS::MMI::InputManagerImpl>::GetInstance().DispatchToNextHandler(eventId);
        ret != RET_OK) {
        auto errCode = NormalizeHookResult(ret);
        MMI_HILOGE("DispatchToNextHandler failed, eventId:%{public}d, errCode:%{public}d", eventId, errCode);
        return errCode;
    }
    MMI_HILOGD("OH_Input_DispatchToNextHandler success, eventId:%{public}d", eventId);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetPointerVisible(bool visible)
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerVisible(visible);
    if (ret != RET_OK) {
        MMI_HILOGE("SetPointerVisible fail, error: %{public}d", ret);
        return ret == INPUT_DEVICE_NOT_SUPPORTED ? INPUT_DEVICE_NOT_SUPPORTED : INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetPointerStyle(int32_t windowId, int32_t *pointerStyle)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerStyle, INPUT_PARAMETER_ERROR);
    if (windowId < 0 && windowId != OHOS::MMI::GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowId");
        return INPUT_PARAMETER_ERROR;
    }
    OHOS::MMI::PointerStyle style;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetPointerStyle(windowId, style);
    if (ret != RET_OK) {
        MMI_HILOGE("GetPointerStyle fail, windowid: %{public}d, error: %{public}d", windowId, ret);
        return INPUT_SERVICE_EXCEPTION;
    }
    *pointerStyle = style.id;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetPointerStyle(int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0 && windowId != OHOS::MMI::GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        return INPUT_PARAMETER_ERROR;
    }
    if ((pointerStyle < OHOS::MMI::DEFAULT && pointerStyle != OHOS::MMI::DEVELOPER_DEFINED_ICON) ||
        pointerStyle > OHOS::MMI::SCREENRECORDER_CURSOR) {
        MMI_HILOGE("Undefined pointer style");
        return INPUT_PARAMETER_ERROR;
    }
    OHOS::MMI::PointerStyle style;
    style.id = pointerStyle;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetPointerStyle(windowId, style);
    if (ret != RET_OK) {
        MMI_HILOGE("SetPointerStyle fail, windowId: %{public}d, error: %{public}d", windowId, ret);
        return INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}

Input_CustomCursor* OH_Input_CustomCursor_Create(OH_PixelmapNative* pixelMap, int32_t anchorX, int32_t anchorY)
{
    CALL_DEBUG_ENTER;
    CHKPP(pixelMap);
    Input_CustomCursor* customCursor = new (std::nothrow) Input_CustomCursor();
    CHKPP(customCursor);
    customCursor->pixelMap = pixelMap;
    customCursor->anchorX = anchorX;
    customCursor->anchorY = anchorY;
    return customCursor;
}

void OH_Input_CustomCursor_Destroy(Input_CustomCursor** customCursor)
{
    CALL_DEBUG_ENTER;
    CHKPV(customCursor);
    CHKPV(*customCursor);
    delete *customCursor;
    *customCursor = nullptr;
}

Input_Result OH_Input_CustomCursor_GetPixelMap(Input_CustomCursor* customCursor, OH_PixelmapNative* pixelMap)
{
    CALL_DEBUG_ENTER;
    CHKPR(customCursor, INPUT_PARAMETER_ERROR);
    CHKPR(pixelMap, INPUT_PARAMETER_ERROR);
    pixelMap = customCursor->pixelMap;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_CustomCursor_GetAnchor(Input_CustomCursor* customCursor, int32_t* anchorX, int32_t* anchorY)
{
    CALL_DEBUG_ENTER;
    CHKPR(customCursor, INPUT_PARAMETER_ERROR);
    CHKPR(anchorX, INPUT_PARAMETER_ERROR);
    CHKPR(anchorY, INPUT_PARAMETER_ERROR);
    *anchorX = customCursor->anchorX;
    *anchorY = customCursor->anchorY;
    return INPUT_SUCCESS;
}

Input_CursorConfig* OH_Input_CursorConfig_Create(bool followSystem)
{
    CALL_DEBUG_ENTER;
    Input_CursorConfig* cursorConfig = new (std::nothrow) Input_CursorConfig();
    CHKPP(cursorConfig);
    cursorConfig->followSystem = followSystem;
    return cursorConfig;
}

void OH_Input_CursorConfig_Destroy(Input_CursorConfig** cursorConfig)
{
    CALL_DEBUG_ENTER;
    CHKPV(cursorConfig);
    CHKPV(*cursorConfig);
    delete *cursorConfig;
    *cursorConfig = nullptr;
}

Input_Result OH_Input_CursorConfig_IsFollowSystem(Input_CursorConfig* cursorConfig, bool* followSystem)
{
    CALL_DEBUG_ENTER;
    CHKPR(cursorConfig, INPUT_PARAMETER_ERROR);
    CHKPR(followSystem, INPUT_PARAMETER_ERROR);
    *followSystem = cursorConfig->followSystem;
    return INPUT_SUCCESS;
}

Input_Result OH_Input_GetPixelMapOptions(OH_PixelmapNative* pixelMap, OHOS::Media::InitializationOptions* options)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, INPUT_PARAMETER_ERROR);
    CHKPR(options, INPUT_PARAMETER_ERROR);
    OH_Pixelmap_ImageInfo* imageInfo = nullptr;
    Image_ErrorCode imageResult = OH_PixelmapImageInfo_Create(&imageInfo);
    if (imageResult != IMAGE_SUCCESS) {
        return INPUT_SERVICE_EXCEPTION;
    }
    imageResult = OH_PixelmapNative_GetImageInfo(pixelMap, imageInfo);
    if (imageResult != IMAGE_SUCCESS) {
        return INPUT_PARAMETER_ERROR;
    }
    bool ret = true;
    uint32_t width = 0;
    uint32_t height = 0;
    int32_t alphaType = 0;
    uint32_t rowStride = 0;
    int32_t pixelFormat = 0;
    ret &= OH_PixelmapImageInfo_GetWidth(imageInfo, &width) == IMAGE_SUCCESS;
    ret &= OH_PixelmapImageInfo_GetHeight(imageInfo, &height) == IMAGE_SUCCESS;
    ret &= OH_PixelmapImageInfo_GetAlphaType(imageInfo, &alphaType) == IMAGE_SUCCESS;
    ret &= OH_PixelmapImageInfo_GetRowStride(imageInfo, &rowStride) == IMAGE_SUCCESS;
    ret &= OH_PixelmapImageInfo_GetPixelFormat(imageInfo, &pixelFormat) == IMAGE_SUCCESS;
    OH_PixelmapImageInfo_Release(imageInfo);
    if (!ret) {
        return INPUT_PARAMETER_ERROR;
    }
    options->alphaType = static_cast<OHOS::Media::AlphaType>(alphaType);
    options->srcPixelFormat = static_cast<OHOS::Media::PixelFormat>(pixelFormat);
    options->pixelFormat = static_cast<OHOS::Media::PixelFormat>(pixelFormat);
    options->srcRowStride = rowStride;
    options->size.height = static_cast<int32_t>(height);
    options->size.width = static_cast<int32_t>(width);
    return INPUT_SUCCESS;
}

Input_Result OH_Input_SetCustomCursor(int32_t windowId, Input_CustomCursor* customCursor,
                                      Input_CursorConfig* cursorConfig)
{
    CALL_DEBUG_ENTER;
    CHKPR(customCursor, INPUT_PARAMETER_ERROR);
    CHKPR(cursorConfig, INPUT_PARAMETER_ERROR);
    if (windowId < 0 && windowId != OHOS::MMI::GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowId");
        return INPUT_PARAMETER_ERROR;
    }
    if (customCursor->anchorX < 0 || customCursor->anchorY < 0 || customCursor->pixelMap == nullptr) {
        MMI_HILOGE("customCursor is invalid");
        return INPUT_PARAMETER_ERROR;
    }
    OHOS::Media::InitializationOptions options;
    Input_Result inputResult = OH_Input_GetPixelMapOptions(customCursor->pixelMap, &options);
    if (inputResult != INPUT_SUCCESS) {
        MMI_HILOGE("pixelMap is invalid");
        return INPUT_PARAMETER_ERROR;
    }
    uint32_t byteCount = 0;
    Image_ErrorCode imageResult = OH_PixelmapNative_GetByteCount(customCursor->pixelMap, &byteCount);
    if (imageResult != IMAGE_SUCCESS) {
        MMI_HILOGE("pixelMap is invalid");
        return INPUT_PARAMETER_ERROR;
    }
    size_t pixelBufferSize = static_cast<size_t>(byteCount);
    uint8_t *pixelBuffer = new uint8_t[static_cast<size_t>(byteCount)]();
    imageResult = OH_PixelmapNative_ReadPixels(customCursor->pixelMap, pixelBuffer, &pixelBufferSize);
    if (imageResult != IMAGE_SUCCESS) {
        MMI_HILOGE("pixelMap is invalid");
        delete[] pixelBuffer;
        return INPUT_PARAMETER_ERROR;
    }
    auto tmpPixelmapPtr = OHOS::Media::PixelMap::Create(reinterpret_cast<uint32_t*>(pixelBuffer),
                                                        static_cast<uint32_t>(pixelBufferSize), options);
    delete[] pixelBuffer;
    CHKPR(tmpPixelmapPtr, INPUT_PARAMETER_ERROR);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMapPtr = std::move(tmpPixelmapPtr);
    OHOS::MMI::CustomCursor cursor;
    cursor.focusX = customCursor->anchorX;
    cursor.focusY = customCursor->anchorY;
    cursor.pixelMap = (void *)pixelMapPtr.get();
    OHOS::MMI::CursorOptions cursorOptions;
    cursorOptions.followSystem = cursorConfig->followSystem;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->SetCustomCursor(windowId, cursor, cursorOptions);
    if (ret != RET_OK) {
        MMI_HILOGE("SetCustomCursor fail, error:%{public}d", ret);
        return ret == OHOS::MMI::ERROR_UNSUPPORT ? INPUT_DEVICE_NOT_SUPPORTED : INPUT_SERVICE_EXCEPTION;
    }
    return INPUT_SUCCESS;
}