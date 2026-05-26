/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "inputEventClient.h"

#include <map>
#include <memory>
#include <thread>
#include <chrono>
#include <sstream>
#include <iostream>
#include <mutex>

#include "define_multimodal.h"
#include "input_manager.h"
#include "input_event.h"
#include "ipc_skeleton.h"
#include "key_event.h"
#include "mmi_api_metrics_histograms.h"
#include "mmi_log.h"
#include "oh_input_manager.h"
#include "ohos.multimodalInput.inputEventClient.proj.hpp"
#include "ohos.multimodalInput.inputEventClient.impl.hpp"
#include "pointer_event.h"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "ani_common.h"
#include "mouse_controller_impl.h"
#include "keyboard_controller_impl.h"
#include "touch_controller_impl.h"
#include "ohos.multimodalInput.mouseEvent.impl.h"
#include "ohos.multimodalInput.keyCode.impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "aniInputEventClient"

using namespace taihe;
using namespace ohos::multimodalInput::inputEventClient;
using namespace OHOS::MMI;
using TaiheError_t = OHOS::MMI::TaiheError;

namespace {

const std::string INJECT_INPUT_PERMISSION_NAME = "ohos.permission.INJECT_INPUT_EVENT";
const std::string MODULE_NAME = "inputEventClient";

// Controller operation enums
enum class MouseControllerOperation {
    CREATE,
    MOVE_TO,
    PRESS_BUTTON,
    RELEASE_BUTTON,
    BEGIN_AXIS,
    UPDATE_AXIS,
    END_AXIS,
};
 
enum class KeyboardControllerOperation {
    CREATE,
    PRESS_KEY,
    RELEASE_KEY,
};
 
enum class TouchControllerOperation {
    CREATE,
    DOWN,
    MOVE,
    UP,
};
 
// Forward declarations for helper functions
void SetMouseControllerBusinessError(int32_t errorCode, MouseControllerOperation operation);
void SetKeyboardControllerBusinessError(int32_t errorCode, KeyboardControllerOperation operation);
void SetTouchControllerBusinessError(int32_t errorCode, TouchControllerOperation operation);

std::string MakePermissionCheckErrMsg(const std::string &moduleName,
    const std::string &permissionName)
{
    std::stringstream ss;
    ss << "Permission denied. An attempt was made to " <<
        moduleName << " forbidden by permission:" <<
        permissionName << ".";
    return ss.str();
}

bool IsSystemApp()
{
    static bool isSystemApp = []() {
        uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
        return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    }();
    return isSystemApp;
}
 	 
bool CheckPermission(const std::string &permissionCode)
{
    uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    using OHOS::Security::AccessToken::AccessTokenID;
    auto tokenType = OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(tokenId));
    if ((tokenType == OHOS::Security::AccessToken::TOKEN_HAP) ||
        (tokenType == OHOS::Security::AccessToken::TOKEN_NATIVE)) {
        int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionCode);
        if (ret != OHOS::Security::AccessToken::PERMISSION_GRANTED) {
            MMI_HILOGE("Check permission failed ret:%{public}d permission:%{public}s", ret, permissionCode.c_str());
            return false;
        }
        MMI_HILOGD("Check interceptor permission success permission:%{public}s", permissionCode.c_str());
        return true;
    } else if (tokenType == OHOS::Security::AccessToken::TOKEN_SHELL) {
        MMI_HILOGI("Token type is shell");
        return true;
    } else {
        MMI_HILOGE("Unsupported token type:%{public}d", tokenType);
        return false;
    }
}

bool CheckInputEventClentPermission(std::function<void(int32_t)> histogramError)
{
    if (!IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        histogramError(COMMON_USE_SYSAPI_ERROR);
        return false;
    }
    if (!CheckPermission(INJECT_INPUT_PERMISSION_NAME)) {
        std::string errMsg = MakePermissionCheckErrMsg(MODULE_NAME, INJECT_INPUT_PERMISSION_NAME);
        taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR, errMsg);
        histogramError(COMMON_PERMISSION_CHECK_ERROR);
        return false;
    }
    return  true;
}

// Axis枚举转换：Taihe → Native
int32_t ConvertTaiheAxisToNative(::ohos::multimodalInput::mouseEvent::Axis axis) {
    static const std::map<int32_t, int32_t> AXIS_MAP = {
        { static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Axis::key_t::SCROLL_VERTICAL),
          static_cast<int32_t>(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL) },
        { static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Axis::key_t::SCROLL_HORIZONTAL),
          static_cast<int32_t>(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL) },
        { static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Axis::key_t::PINCH),
          static_cast<int32_t>(PointerEvent::AXIS_TYPE_PINCH) }
    };

    int32_t axisValue = static_cast<int32_t>(axis);
    auto it = AXIS_MAP.find(axisValue);
    if (it != AXIS_MAP.end()) {
        return it->second;
    }
    MMI_HILOGW("Unknown Taihe axis: %{public}d, using as-is", axisValue);
    return axisValue;
}

bool IsValidEtsButton(::ohos::multimodalInput::mouseEvent::Button button)
{
    int32_t buttonValue = static_cast<int32_t>(button);
    return (buttonValue >= static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Button::key_t::LEFT) &&
            buttonValue <= static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Button::key_t::TASK));
}

bool IsValidEtsAxis(::ohos::multimodalInput::mouseEvent::Axis axis)
{
    int32_t axisValue = static_cast<int32_t>(axis);
    return (axisValue >= static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Axis::key_t::SCROLL_VERTICAL) &&
            axisValue <= static_cast<int32_t>(::ohos::multimodalInput::mouseEvent::Axis::key_t::PINCH));
}


static std::unordered_map<int32_t, int32_t> THMouseButton2Native = {
    { JS_MOUSE_BUTTON_LEFT, PointerEvent::MOUSE_BUTTON_LEFT },
    { JS_MOUSE_BUTTON_RIGHT, PointerEvent::MOUSE_BUTTON_RIGHT },
    { JS_MOUSE_BUTTON_MIDDLE, PointerEvent::MOUSE_BUTTON_MIDDLE },
    { JS_MOUSE_BUTTON_SIDE, PointerEvent::MOUSE_BUTTON_SIDE },
    { JS_MOUSE_BUTTON_EXTRA, PointerEvent::MOUSE_BUTTON_EXTRA },
    { JS_MOUSE_BUTTON_FORWARD, PointerEvent::MOUSE_BUTTON_FORWARD },
    { JS_MOUSE_BUTTON_BACK, PointerEvent::MOUSE_BUTTON_BACK },
    { JS_MOUSE_BUTTON_TASK, PointerEvent::MOUSE_BUTTON_TASK }
};

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
void GetInjectionEventDataNative(Input_KeyEvent* keyEventNative,
    ::ohos::multimodalInput::inputEventClient::KeyEvent const& thKeyEvent,
    std::function<void(int32_t)> histogramError)
{
    if (thKeyEvent.keyCode < 0) {
        set_business_error(INPUT_PARAMETER_ERROR, "keyCode must be greater than or equal to 0");
        histogramError(INPUT_PARAMETER_ERROR);
        return;
    }
    if (thKeyEvent.keyDownDuration < 0) {
        MMI_HILOGE("keyDownDuration:%{public}d is less 0, can not process", thKeyEvent.keyDownDuration);
        set_business_error(INPUT_PARAMETER_ERROR, "keyDownDuration must be greater than or equal to 0");
        histogramError(INPUT_PARAMETER_ERROR);
        return;
    }

    auto keyAction = thKeyEvent.isPressed ? Input_KeyEventAction::KEY_ACTION_DOWN : Input_KeyEventAction::KEY_ACTION_UP;
    OH_Input_SetKeyEventAction(keyEventNative, keyAction);
    OH_Input_SetKeyEventKeyCode(keyEventNative, thKeyEvent.keyCode);
    OH_Input_SetKeyEventActionTime(keyEventNative, static_cast<int64_t>(thKeyEvent.keyDownDuration));
    Input_Result result = static_cast<Input_Result>(OH_Input_InjectKeyEvent(keyEventNative));
    if (result != INPUT_SUCCESS) {
        MMI_HILOGE("OH_Input_InjectKeyEvent error");
    }
}
#else
void GetInjectionEventData(std::shared_ptr<OHOS::MMI::KeyEvent> keyEventNative,
    ::ohos::multimodalInput::inputEventClient::KeyEvent const& thKeyEvent,
    std::function<void(int32_t)> histogramError)
{
    if (keyEventNative == nullptr) {
        MMI_HILOGE("keyEventNative is null");
        return;
    }
    if (thKeyEvent.keyDownDuration < 0) {
        MMI_HILOGE("keyDownDuration value is invalid.value:%{public}d", thKeyEvent.keyDownDuration);
        set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.");
        histogramError(INPUT_PARAMETER_ERROR);
        return;
    }
    if (thKeyEvent.keyCode < 0) {
        MMI_HILOGE("keyCode value is invalid, can not process");
        set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.");
        histogramError(INPUT_PARAMETER_ERROR);
        return;
    }
    keyEventNative->SetRepeat(true);
    keyEventNative->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_NO_INTERCEPT);
    keyEventNative->SetKeyCode(thKeyEvent.keyCode);
    auto keyAction = thKeyEvent.isPressed ? OHOS::MMI::KeyEvent::KEY_ACTION_DOWN : OHOS::MMI::KeyEvent::KEY_ACTION_UP;
    keyEventNative->SetKeyAction(keyAction);
    OHOS::MMI::KeyEvent::KeyItem item;
    item.SetKeyCode(thKeyEvent.keyCode);
    item.SetPressed(thKeyEvent.isPressed);
    item.SetDownTime(static_cast<int64_t>(thKeyEvent.keyDownDuration));
    keyEventNative->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEventNative);
    std::this_thread::sleep_for(std::chrono::milliseconds(thKeyEvent.keyDownDuration));
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void InjectKeyEventSync(::ohos::multimodalInput::inputEventClient::KeyEventData const& keyEvent)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputEventClient.injectKeyEvent.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectKeyEvent.Error", errorCode);
    };
    if (!CheckInputEventClentPermission(histogramError)) {
        return;
    }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    Input_KeyEvent* keyEventNative = OH_Input_CreateKeyEvent();
    GetInjectionEventDataNative(keyEventNative, keyEvent.keyEvent, histogramError);
    OH_Input_DestroyKeyEvent(&keyEventNative);
#else
    auto newKeyEvent = OHOS::MMI::KeyEvent::Create();
    GetInjectionEventData(newKeyEvent, keyEvent.keyEvent, histogramError);
#endif
}

void InjectEventSync(::ohos::multimodalInput::inputEventClient::KeyEventInfo const& keyEvent)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputEventClient.injectEvent.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectEvent.Error", errorCode);
    };
    if (!CheckInputEventClentPermission(histogramError)) {
        return;
    }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    Input_KeyEvent* keyEventNative = OH_Input_CreateKeyEvent();
    GetInjectionEventDataNative(keyEventNative, keyEvent.KeyEvent, histogramError);
    OH_Input_DestroyKeyEvent(&keyEventNative);
#else
    auto lkeyEvent = OHOS::MMI::KeyEvent::Create();
    GetInjectionEventData(lkeyEvent, keyEvent.KeyEvent, histogramError);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

void HandleMouseButton(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, int32_t action)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    int32_t button = static_cast<int32_t>(mouseEvent.button.get_value());
    if (button < 0) {
        MMI_HILOGE("button:%{public}d is less 0, can not process", button);
        set_business_error(INPUT_PARAMETER_ERROR, "button must be greater than or equal to 0");
    }
    if (THMouseButton2Native.find(button) != THMouseButton2Native.end()) {
        button = THMouseButton2Native[button];
    } else {
        MMI_HILOGE("button is unknown!");
    }
    pointerEvent->SetButtonId(button);
    if (action == TH_MOUSE_CALLBACK_EVENT::JS_CALLBACK_MOUSE_ACTION_BUTTON_DOWN) {
        pointerEvent->SetButtonPressed(button);
    } else if (action == TH_MOUSE_CALLBACK_EVENT::JS_CALLBACK_MOUSE_ACTION_BUTTON_UP) {
        pointerEvent->DeleteReleaseButton(button);
    }
}

void HandleMouseAction(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    int32_t action = static_cast<int32_t>(mouseEvent.action.get_value());
    switch (action) {
        case TAHE_MOVE:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        case TAHE_BUTTON_DOWN:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
            item.SetPressed(true);
            break;
        case TAHE_BUTTON_UP:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
            item.SetPressed(false);
            break;
        case TAHE_ACTION_DOWN:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            item.SetPressed(true);
            break;
        case TAHE_ACTION_UP:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            item.SetPressed(false);
            break;
        default:
            MMI_HILOGE("action is unknown");
            break;
    }

    if (action == TAHE_BUTTON_DOWN || action == TAHE_BUTTON_UP|| action == TAHE_MOVE) {
        HandleMouseButton(mouseEvent, pointerEvent, action);
    }
}

void HandleMousePropertyInt32(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    int32_t screenX = mouseEvent.screenX;
    int32_t screenY = mouseEvent.screenY;
    int32_t toolType = mouseEvent.toolType.get_value();
    if (toolType < 0) {
        MMI_HILOGE("toolType:%{public}d is less 0, can not process", toolType);
        ::taihe::set_business_error(INPUT_PARAMETER_ERROR, "toolType must be greater than or equal to 0");
    }
    double globalX = INT32_MAX;
    if (mouseEvent.globalX.has_value()) {
        globalX = mouseEvent.globalX.value();
    }
    double globalY = INT32_MAX;
    if (mouseEvent.globalY.has_value()) {
        globalY = mouseEvent.globalY.value();
    }
    pointerEvent->SetSourceType(toolType);
    item.SetPointerId(0);
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
    if (globalX != INT32_MAX && globalY != INT32_MAX) {
        item.SetGlobalX(globalX);
        item.SetGlobalY(globalY);
    }
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
}

void HandleMousePressedButtons(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    std::vector<int32_t> jsPressedButtons {};
    for (auto it = mouseEvent.pressedButtons.begin(); it != mouseEvent.pressedButtons.end(); ++it) {
        jsPressedButtons.push_back(static_cast<int32_t>(*it));
    }

    std::vector<int32_t> nativePressedButtons { };
    for (const auto jsButton : jsPressedButtons) {
        if (THMouseButton2Native.find(jsButton) == THMouseButton2Native.end()) {
            MMI_HILOGE("Unknown jsButton:%{public}d", jsButton);
            continue;
        }
        nativePressedButtons.push_back(THMouseButton2Native[jsButton]);
    }

    auto buttonId = pointerEvent->GetButtonId();
    auto iter = std::find_if(nativePressedButtons.begin(), nativePressedButtons.end(),
        [buttonId] (int32_t elem) { return elem == buttonId; }
    );
    if (iter != nativePressedButtons.end()) {
        item.SetPressed(true);
    }
    for (const auto button : nativePressedButtons) {
        pointerEvent->SetButtonPressed(button);
    }
}

void InjectMouseEventSync(::ohos::multimodalInput::inputEventClient::MouseEventData const& mouseEvent)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputEventClient.injectMouseEvent.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectMouseEvent.Error", errorCode);
    };
    if (!CheckInputEventClentPermission(histogramError)) {
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    PointerEvent::PointerItem item;
    HandleMouseAction(mouseEvent.mouseEvent, pointerEvent, item);
    HandleMousePropertyInt32(mouseEvent.mouseEvent, pointerEvent, item);
    HandleMousePressedButtons(mouseEvent.mouseEvent, pointerEvent, item);
    bool useGlobalCoordinate = mouseEvent.useGlobalCoordinate.value_or(false);
    int32_t useCoordinate = PointerEvent::DISPLAY_COORDINATE;
    if (useGlobalCoordinate) {
        MMI_HILOGD("useGlobalCoordinate");
        if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
            if (!item.IsValidGlobalXY()) {
                MMI_HILOGE("globalX globalY is invalid");
                ::taihe::set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.globalX globalY is invalid");
                return;
            }
        }
        useCoordinate = PointerEvent::GLOBAL_COORDINATE;
    }
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, true, useCoordinate);
}

int32_t HandleTouchAction(::ohos::multimodalInput::touchEvent::TouchEvent touchEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return RET_ERR;
    }
    int32_t action = static_cast<int32_t>(touchEvent.action.get_value());
    switch (action) {
        case TH_TOUCH_CALLBACK_EVENT::JS_CALLBACK_TOUCH_ACTION_DOWN:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            item.SetPressed(true);
            break;
        case TH_TOUCH_CALLBACK_EVENT::JS_CALLBACK_TOUCH_ACTION_MOVE:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        case TH_TOUCH_CALLBACK_EVENT::JS_CALLBACK_TOUCH_ACTION_UP:
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            item.SetPressed(false);
            break;
        default:
            action = RET_ERR;
            MMI_HILOGE("action is unknown");
            break;
    }
    return action;
}

void HandleTouchAttribute(std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item,
    ::ohos::multimodalInput::touchEvent::Touch& touch, int32_t isTouch)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    int32_t pointerId = touch.id;
    int32_t screenX = touch.screenX;
    int32_t screenY = touch.screenY;
    int64_t pressedTime = touch.pressedTime;
    int32_t toolType = static_cast<int32_t>(touch.toolType.get_value());
    double pressure = touch.pressure;
    int32_t globalX = touch.globalX.has_value()? touch.globalX.value() : INT_MAX;
    int32_t globalY = touch.globalY.has_value()? touch.globalY.value() : INT_MAX;

    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
    item.SetRawDisplayX(screenX);
    item.SetRawDisplayY(screenY);
    item.SetPointerId(pointerId);
    item.SetToolType(toolType);
    item.SetPressure(pressure);
    if (globalX != INT_MAX && globalY != INT_MAX) {
        item.SetGlobalX(globalX);
        item.SetGlobalY(globalY);
    }
    if (isTouch) {
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetActionTime(pressedTime);
    }
}

void HandleTouchesProperty(std::shared_ptr<PointerEvent> pointerEvent,
    ::taihe::array_view<::ohos::multimodalInput::touchEvent::Touch>& touches,
    std::vector<PointerEvent::PointerItem>& pointerItems)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    for (auto it = touches.begin(); it != touches.end(); ++it) {
        PointerEvent::PointerItem pointerItem;
        HandleTouchAttribute(pointerEvent, pointerItem, *it, false);
        pointerItems.push_back(pointerItem);
    }
}

bool HandleTouchPropertyInt32(::ohos::multimodalInput::touchEvent::TouchEvent touchEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item, int32_t action)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return false;
    }
    int32_t sourceType = touchEvent.sourceType.get_value();
    if (sourceType < 0) {
        MMI_HILOGE("sourceType must be greater than or equal to 0");
        return false;
    }
    if (sourceType == TH_TOUCH_CALLBACK_SOURCETYPE::TOUCH_SCREEN || sourceType == TH_TOUCH_CALLBACK_SOURCETYPE::PEN) {
        sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    }
    int32_t screenId = touchEvent.base.screenId;
    HandleTouchAttribute(pointerEvent, item, touchEvent.touch, true);
    bool autoToVirtualScreen = true;
    int32_t fixedMode = 1;
    if (touchEvent.fixedMode.has_value()) {
        fixedMode = static_cast<int32_t>(touchEvent.fixedMode.value());
        if (fixedMode < static_cast<int32_t>(PointerEvent::FixedMode::NORMAL) ||
            fixedMode >= static_cast<int32_t>(PointerEvent::FixedMode::SCREEN_MODE_MAX)) {
                MMI_HILOGE("fixedMode is not defined");
                return false;
        }
        if (fixedMode != static_cast<int32_t>(PointerEvent::FixedMode::AUTO)) {
            autoToVirtualScreen = false;
        }
    }

    pointerEvent->AddPointerItem(item);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetTargetDisplayId(screenId);
    pointerEvent->SetAutoToVirtualScreen(autoToVirtualScreen);

    std::vector<PointerEvent::PointerItem> pointerItems;
    HandleTouchesProperty(pointerEvent, touchEvent.touches, pointerItems);
    for (auto &pointeritem : pointerItems) {
        pointerEvent->AddPointerItem(pointeritem);
    }

    if ((action == TH_TOUCH_CALLBACK_EVENT::JS_CALLBACK_TOUCH_ACTION_MOVE) ||
        (action == TH_TOUCH_CALLBACK_EVENT::JS_CALLBACK_TOUCH_ACTION_UP)) {
        pointerEvent->UpdatePointerItem(item.GetPointerId(), item);
    }
    return true;
}

void InjectTouchEventSync(::ohos::multimodalInput::inputEventClient::TouchEventData const& touchEvent)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputEventClient.injectTouchEvent.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectTouchEvent.Error", errorCode);
    };
    if (!CheckInputEventClentPermission(histogramError)) {
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    if (pointerEvent == nullptr) {
        MMI_HILOGE("pointerEvent is null");
        return;
    }
    PointerEvent::PointerItem item;
    int32_t action = HandleTouchAction(touchEvent.touchEvent, pointerEvent, item);
    if (action == RET_ERR) {
        MMI_HILOGE("touch action type invaild");
        set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.");
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectTouchEvent.Error", INPUT_PARAMETER_ERROR);
        return;
    }
    if (!HandleTouchPropertyInt32(touchEvent.touchEvent, pointerEvent, item, action)) {
        MMI_HILOGE("touch property invaild");
        set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.");
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectTouchEvent.Error", INPUT_PARAMETER_ERROR);
        return;
    }
    bool useGlobalCoordinate = touchEvent.useGlobalCoordinate.value_or(false);
    int32_t useCoordinate = PointerEvent::DISPLAY_COORDINATE;
    if (useGlobalCoordinate) {
        MMI_HILOGD("useGlobalCoordinate");
        if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
            if (!item.IsValidGlobalXY()) {
                MMI_HILOGE("globalX globalY is invalid");
                ::taihe::set_business_error(INPUT_PARAMETER_ERROR, "Parameter error.globalX globalY is invalid");
                MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.injectTouchEvent.Error", INPUT_PARAMETER_ERROR);
                return;
            }
        }
        useCoordinate = PointerEvent::GLOBAL_COORDINATE;
    }
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent,
        pointerEvent->GetAutoToVirtualScreen(), useCoordinate);
}

void PermitInjectionSync(bool result)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputEventClient.permitInjection.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputEventClient.permitInjection.Error", errorCode);
    };
    if (!CheckInputEventClentPermission(histogramError)) {
        return;
    }
    InputManager::GetInstance()->Authorize(result);
}

class MouseControllerImpl {
public:
    // 构造函数：接收Native实现
    explicit MouseControllerImpl(std::shared_ptr<OHOS::MMI::MouseControllerImpl> impl)
        : nativeImpl_(impl) {
        MMI_HILOGD("MouseControllerImpl created with native impl");
    }

    // 默认构造函数：用于错误情况
    MouseControllerImpl() : nativeImpl_(nullptr) {
        MMI_HILOGW("MouseControllerImpl created without native impl (error case)");
    }

    ~MouseControllerImpl() = default;

    void MoveToSync(int32_t displayId, int32_t displayX, int32_t displayY)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::MOVE_TO);
            return;
        }

        int32_t ret = nativeImpl_->MoveTo(displayId, displayX, displayY);
        if (ret != RET_OK) {
            MMI_HILOGE("MoveTo failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::MOVE_TO);
        }
    }

    void PressButtonSync(::ohos::multimodalInput::mouseEvent::Button button)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::PRESS_BUTTON);
            return;
        }

        if (!IsValidEtsButton(button)) {
            int32_t buttonValue = static_cast<int32_t>(button);
            MMI_HILOGE("Invalid button value: %{public}d", buttonValue);
            taihe::set_business_error(OHOS::MMI::TaiheErrorCode::COMMON_PARAMETER_ERROR,
                "Parameter error. Invalid button value");
            return;
        }

        int32_t nativeButton = TaiheMouseButonConverter::ConvertEts2Native(button);
        int32_t ret = nativeImpl_->PressButton(nativeButton);
        if (ret != RET_OK) {
            MMI_HILOGE("PressButton failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::PRESS_BUTTON);
        }
    }

    void ReleaseButtonSync(::ohos::multimodalInput::mouseEvent::Button button)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::RELEASE_BUTTON);
            return;
        }

        if (!IsValidEtsButton(button)) {
            int32_t buttonValue = static_cast<int32_t>(button);
            MMI_HILOGE("Invalid button value: %{public}d", buttonValue);
            taihe::set_business_error(OHOS::MMI::TaiheErrorCode::COMMON_PARAMETER_ERROR,
                "Parameter error. Invalid button value");
            return;
        }

        int32_t nativeButton = TaiheMouseButonConverter::ConvertEts2Native(button);
        int32_t ret = nativeImpl_->ReleaseButton(nativeButton);
        if (ret != RET_OK) {
            MMI_HILOGE("ReleaseButton failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::RELEASE_BUTTON);
        }
    }

    void BeginAxisSync(::ohos::multimodalInput::mouseEvent::Axis axis, int32_t value)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::BEGIN_AXIS);
            return;
        }

        if (!IsValidEtsAxis(axis)) {
            int32_t axisValue = static_cast<int32_t>(axis);
            MMI_HILOGE("Invalid axis value: %{public}d", axisValue);
            taihe::set_business_error(OHOS::MMI::TaiheErrorCode::COMMON_PARAMETER_ERROR,
                "Parameter error. Invalid axis value");
            return;
        }

        int32_t nativeAxis = ConvertTaiheAxisToNative(axis);
        int32_t ret = nativeImpl_->BeginAxis(nativeAxis, value);
        if (ret != RET_OK) {
            MMI_HILOGE("BeginAxis failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::BEGIN_AXIS);
        }
    }

    void UpdateAxisSync(::ohos::multimodalInput::mouseEvent::Axis axis, int32_t value)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::UPDATE_AXIS);
            return;
        }

        if (!IsValidEtsAxis(axis)) {
            int32_t axisValue = static_cast<int32_t>(axis);
            MMI_HILOGE("Invalid axis value: %{public}d", axisValue);
            taihe::set_business_error(OHOS::MMI::TaiheErrorCode::COMMON_PARAMETER_ERROR,
                "Parameter error. Invalid axis value");
            return;
        }

        int32_t nativeAxis = ConvertTaiheAxisToNative(axis);
        int32_t ret = nativeImpl_->UpdateAxis(nativeAxis, value);
        if (ret != RET_OK) {
            MMI_HILOGE("UpdateAxis failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::UPDATE_AXIS);
        }
    }

    void EndAxisSync(::ohos::multimodalInput::mouseEvent::Axis axis)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetMouseControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                            MouseControllerOperation::END_AXIS);
            return;
        }

        if (!IsValidEtsAxis(axis)) {
            int32_t axisValue = static_cast<int32_t>(axis);
            MMI_HILOGE("Invalid axis value: %{public}d", axisValue);
            taihe::set_business_error(OHOS::MMI::TaiheErrorCode::COMMON_PARAMETER_ERROR,
                "Parameter error. Invalid axis value");
            return;
        }

        int32_t nativeAxis = ConvertTaiheAxisToNative(axis);
        int32_t ret = nativeImpl_->EndAxis(nativeAxis);
        if (ret != RET_OK) {
            MMI_HILOGE("EndAxis failed, ret=%{public}d", ret);
            SetMouseControllerBusinessError(ret, MouseControllerOperation::END_AXIS);
        }
    }

private:
    std::shared_ptr<OHOS::MMI::MouseControllerImpl> nativeImpl_;
};

::ohos::multimodalInput::inputEventClient::MouseController CreateMouseControllerSync()
{
    CALL_DEBUG_ENTER;

    // 创建Native实现，返回错误码
    std::shared_ptr<OHOS::MMI::MouseControllerImpl> nativeImpl = nullptr;
    int32_t ret = InputManager::GetInstance()->CreateMouseController(nativeImpl);
    if (ret != RET_OK || nativeImpl == nullptr) {
        MMI_HILOGE("Failed to create native MouseControllerImpl, ret=%{public}d", ret);
        SetMouseControllerBusinessError(ret, MouseControllerOperation::CREATE);
        return make_holder<MouseControllerImpl,
                          ::ohos::multimodalInput::inputEventClient::MouseController>();
    }

    MMI_HILOGD("MouseController created successfully");
    // 包装为Taihe对象
    return make_holder<MouseControllerImpl,
                      ::ohos::multimodalInput::inputEventClient::MouseController>(nativeImpl);
}

constexpr const char* CONTROL_DEVICE_PERMISSION = "ohos.permission.CONTROL_DEVICE";

std::string GetTouchControllerActionName(TouchControllerOperation operation)
{
    switch (operation) {
        case TouchControllerOperation::DOWN:
            return "touch down";
        case TouchControllerOperation::MOVE:
            return "touch move";
        case TouchControllerOperation::UP:
            return "touch up";
        case TouchControllerOperation::CREATE:
        default:
            return "create TouchController";
    }
}

std::string GetMouseControllerActionName(MouseControllerOperation operation)
{
    switch (operation) {
        case MouseControllerOperation::MOVE_TO:
            return "move mouse";
        case MouseControllerOperation::PRESS_BUTTON:
            return "press button";
        case MouseControllerOperation::RELEASE_BUTTON:
            return "release button";
        case MouseControllerOperation::BEGIN_AXIS:
            return "begin axis";
        case MouseControllerOperation::UPDATE_AXIS:
            return "update axis";
        case MouseControllerOperation::END_AXIS:
            return "end axis";
        case MouseControllerOperation::CREATE:
        default:
            return "create MouseController";
    }
}

std::string GetKeyboardControllerActionName(KeyboardControllerOperation operation)
{
    switch (operation) {
        case KeyboardControllerOperation::PRESS_KEY:
            return "press key";
        case KeyboardControllerOperation::RELEASE_KEY:
            return "release key";
        case KeyboardControllerOperation::CREATE:
        default:
            return "create KeyboardController";
    }
}

int32_t NormalizeControllerErrorCode(int32_t errorCode)
{
    if (errorCode == ERROR_NO_PERMISSION) {
        return OHOS::MMI::TaiheErrorCode::COMMON_PERMISSION_CHECK_ERROR;
    }
    if (errorCode == CAPABILITY_NOT_SUPPORTED) {
        return OHOS::MMI::TaiheErrorCode::INPUT_DEVICE_NOT_SUPPORTED;
    }
    return errorCode;
}

void SetTouchControllerBusinessError(int32_t errorCode, TouchControllerOperation operation)
{
    errorCode = NormalizeControllerErrorCode(errorCode);
    if (errorCode == OHOS::MMI::TaiheErrorCode::COMMON_PERMISSION_CHECK_ERROR) {
        std::string msg = MakePermissionCheckErrMsg(GetTouchControllerActionName(operation), CONTROL_DEVICE_PERMISSION);
        taihe::set_business_error(errorCode, msg);
        return;
    }
    TaiheError_t codeMsg;
    if (TaiheConverter::GetApiError(errorCode, codeMsg)) {
        taihe::set_business_error(errorCode, codeMsg.msg);
        return;
    }
    if (TaiheConverter::GetApiError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION, codeMsg)) {
        taihe::set_business_error(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION, codeMsg.msg);
        return;
    }
    taihe::set_business_error(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION, "Input service exception.");
}

void SetMouseControllerBusinessError(int32_t errorCode, MouseControllerOperation operation)
{
    errorCode = NormalizeControllerErrorCode(errorCode);
    if (errorCode == OHOS::MMI::TaiheErrorCode::COMMON_PERMISSION_CHECK_ERROR) {
        std::string msg = MakePermissionCheckErrMsg(GetMouseControllerActionName(operation), CONTROL_DEVICE_PERMISSION);
        taihe::set_business_error(errorCode, msg);
        return;
    }
    TaiheError_t codeMsg;
    TaiheConverter::GetErrorCodeOrDefault(errorCode, codeMsg);
    taihe::set_business_error(codeMsg.errorCode, codeMsg.msg);
}

void SetKeyboardControllerBusinessError(int32_t errorCode, KeyboardControllerOperation operation)
{
    errorCode = NormalizeControllerErrorCode(errorCode);
    if (errorCode == OHOS::MMI::TaiheErrorCode::COMMON_PERMISSION_CHECK_ERROR) {
        std::string msg = MakePermissionCheckErrMsg(GetKeyboardControllerActionName(operation),
            CONTROL_DEVICE_PERMISSION);
        taihe::set_business_error(errorCode, msg);
        return;
    }
    TaiheError_t codeMsg;
    TaiheConverter::GetErrorCodeOrDefault(errorCode, codeMsg);
    taihe::set_business_error(codeMsg.errorCode, codeMsg.msg);
}

class TaiheTouchControllerImpl {
public:
    explicit TaiheTouchControllerImpl(std::shared_ptr<OHOS::MMI::TouchControllerImpl> impl) : nativeImpl_(impl)
    {
        MMI_HILOGD("TaiheTouchControllerImpl created with native impl");
    }

    TaiheTouchControllerImpl() : nativeImpl_(nullptr)
    {
        MMI_HILOGW("TaiheTouchControllerImpl created without native impl");
    }

    ~TaiheTouchControllerImpl() = default;

    void TouchDownSync(::ohos::multimodalInput::inputEventClient::TouchPoint touch)
    {
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetTouchControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                TouchControllerOperation::DOWN);
            return;
        }

        int32_t ret = nativeImpl_->TouchDown(touch.id, touch.displayId, touch.displayX, touch.displayY);
        if (ret != RET_OK) {
            MMI_HILOGE("TouchDown failed, ret=%{public}d", ret);
            SetTouchControllerBusinessError(ret, TouchControllerOperation::DOWN);
        }
    }

    void TouchMoveSync(::ohos::multimodalInput::inputEventClient::TouchPoint touch)
    {
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetTouchControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                TouchControllerOperation::MOVE);
            return;
        }

        int32_t ret = nativeImpl_->TouchMove(touch.id, touch.displayId, touch.displayX, touch.displayY);
        if (ret != RET_OK) {
            MMI_HILOGE("TouchMove failed, ret=%{public}d", ret);
            SetTouchControllerBusinessError(ret, TouchControllerOperation::MOVE);
        }
    }

    void TouchUpSync(::ohos::multimodalInput::inputEventClient::TouchPoint touch)
    {
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetTouchControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                TouchControllerOperation::UP);
            return;
        }

        int32_t ret = nativeImpl_->TouchUp(touch.id, touch.displayId, touch.displayX, touch.displayY);
        if (ret != RET_OK) {
            MMI_HILOGE("TouchUp failed, ret=%{public}d", ret);
            SetTouchControllerBusinessError(ret, TouchControllerOperation::UP);
        }
    }

private:
    std::shared_ptr<OHOS::MMI::TouchControllerImpl> nativeImpl_;
};

::ohos::multimodalInput::inputEventClient::TouchController CreateTouchControllerSync()
{
    CALL_DEBUG_ENTER;

    std::shared_ptr<OHOS::MMI::TouchControllerImpl> nativeImpl = nullptr;
    int32_t ret = InputManager::GetInstance()->CreateTouchController(nativeImpl);
    if (ret != RET_OK || nativeImpl == nullptr) {
        MMI_HILOGE("Failed to create native TouchControllerImpl, ret=%{public}d", ret);
        SetTouchControllerBusinessError(ret, TouchControllerOperation::CREATE);
        return make_holder<TaiheTouchControllerImpl,
            ::ohos::multimodalInput::inputEventClient::TouchController>();
    }

    MMI_HILOGD("TouchController created successfully");
    return make_holder<TaiheTouchControllerImpl,
        ::ohos::multimodalInput::inputEventClient::TouchController>(nativeImpl);
}

class KeyboardControllerImpl {
public:
    // 构造函数：接收Native实现
    explicit KeyboardControllerImpl(std::shared_ptr<OHOS::MMI::KeyboardControllerImpl> impl)
        : nativeImpl_(impl) {
        MMI_HILOGD("KeyboardControllerImpl created with native impl");
    }

    // 默认构造函数：用于错误情况
    KeyboardControllerImpl() : nativeImpl_(nullptr) {
        MMI_HILOGW("KeyboardControllerImpl created without native impl (error case)");
    }

    ~KeyboardControllerImpl() = default;

    void PressKeySync(::ohos::multimodalInput::keyCode::KeyCode keyCode)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetKeyboardControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                               KeyboardControllerOperation::PRESS_KEY);
            return;
        }

        int32_t nativeKeyCode = TaiheKeyCodeConverter::GetKeyCodeByValue(keyCode);
        int32_t ret = nativeImpl_->PressKey(nativeKeyCode);
        if (ret != RET_OK) {
            MMI_HILOGE("PressKey failed, ret=%{public}d", ret);
            SetKeyboardControllerBusinessError(ret, KeyboardControllerOperation::PRESS_KEY);
        }
    }

    void ReleaseKeySync(::ohos::multimodalInput::keyCode::KeyCode keyCode)
    {
        CALL_DEBUG_ENTER;
        if (nativeImpl_ == nullptr) {
            MMI_HILOGE("Native implementation is null");
            SetKeyboardControllerBusinessError(OHOS::MMI::TaiheErrorCode::INPUT_SERVICE_EXCEPTION,
                                               KeyboardControllerOperation::RELEASE_KEY);
            return;
        }

        int32_t nativeKeyCode = TaiheKeyCodeConverter::GetKeyCodeByValue(keyCode);
        int32_t ret = nativeImpl_->ReleaseKey(nativeKeyCode);
        if (ret != RET_OK) {
            MMI_HILOGE("ReleaseKey failed, ret=%{public}d", ret);
            SetKeyboardControllerBusinessError(ret, KeyboardControllerOperation::RELEASE_KEY);
        }
    }

private:
    std::shared_ptr<OHOS::MMI::KeyboardControllerImpl> nativeImpl_;
};

::ohos::multimodalInput::inputEventClient::KeyboardController CreateKeyboardControllerSync()
{
    CALL_DEBUG_ENTER;

    // 创建Native实现，返回错误码
    std::shared_ptr<OHOS::MMI::KeyboardControllerImpl> nativeImpl = nullptr;
    int32_t ret = InputManager::GetInstance()->CreateKeyboardController(nativeImpl);
    if (ret != RET_OK || nativeImpl == nullptr) {
        MMI_HILOGE("Failed to create native KeyboardControllerImpl, ret=%{public}d", ret);
        SetKeyboardControllerBusinessError(ret, KeyboardControllerOperation::CREATE);
        return make_holder<KeyboardControllerImpl,
                          ::ohos::multimodalInput::inputEventClient::KeyboardController>();
    }

    MMI_HILOGD("KeyboardController created successfully");
    // 包装为Taihe对象
    return make_holder<KeyboardControllerImpl,
                      ::ohos::multimodalInput::inputEventClient::KeyboardController>(nativeImpl);
}

} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_InjectKeyEventSync(InjectKeyEventSync);
TH_EXPORT_CPP_API_InjectEventSync(InjectEventSync);
TH_EXPORT_CPP_API_InjectMouseEventSync(InjectMouseEventSync);
TH_EXPORT_CPP_API_InjectTouchEventSync(InjectTouchEventSync);
TH_EXPORT_CPP_API_PermitInjectionSync(PermitInjectionSync);
TH_EXPORT_CPP_API_CreateMouseControllerSync(CreateMouseControllerSync);
TH_EXPORT_CPP_API_CreateTouchControllerSync(CreateTouchControllerSync);
TH_EXPORT_CPP_API_CreateKeyboardControllerSync(CreateKeyboardControllerSync);
// NOLINTEND
