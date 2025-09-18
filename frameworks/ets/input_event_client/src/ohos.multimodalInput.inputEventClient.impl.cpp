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

#include "ohos.multimodalInput.inputEventClient.proj.hpp"
#include "ohos.multimodalInput.inputEventClient.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include <thread>
#include <chrono>
#include "key_event.h"
#include "input_manager.h"
#include "input_event.h"
#include "oh_input_manager.h"
#include "pointer_event.h"
#include "inputEventClient.h"

using namespace taihe;
using namespace ohos::multimodalInput::inputEventClient;
using namespace OHOS::MMI;

namespace {
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
void GetInjectionEventDataNative(Input_KeyEvent* keyEventNative,
    ::ohos::multimodalInput::inputEventClient::KeyEvent const& thKeyEvent)
{
    auto keyAction = thKeyEvent.isPressed ? Input_KeyEventAction::KEY_ACTION_DOWN : Input_KeyEventAction::KEY_ACTION_UP;
    OH_Input_SetKeyEventAction(keyEventNative, keyAction);
    OH_Input_SetKeyEventKeyCode(keyEventNative, thKeyEvent.keyCode);
    OH_Input_SetKeyEventActionTime(keyEventNative, static_cast<int64_t>(thKeyEvent.keyDownDuration));
    Input_Result result = static_cast<Input_Result>(OH_Input_InjectKeyEvent(keyEventNative));
    if (result != INPUT_SUCCESS) {
        TH_THROW(std::runtime_error, "OH_Input_InjectKeyEvent error");
    }
}
#else
void GetInjectionEventData(std::shared_ptr<OHOS::MMI::KeyEvent> keyEventNative,
    ::ohos::multimodalInput::inputEventClient::KeyEvent const& thKeyEvent)
{
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
    OHOS::MMI::InputManager::GetInstance()->SimulateInputEvent(keyEventNative);
    std::this_thread::sleep_for(std::chrono::milliseconds(thKeyEvent.keyDownDuration));
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void InjectKeyEventSync(::ohos::multimodalInput::inputEventClient::KeyEventData const& keyEvent)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    Input_KeyEvent* keyEventNative = OH_Input_CreateKeyEvent();
    GetInjectionEventDataNative(keyEventNative, keyEvent.keyEvent);
#else
    auto lkeyEvent = OHOS::MMI::KeyEvent::Create();
    GetInjectionEventData(lkeyEvent, keyEvent.keyEvent);
#endif
}

void InjectEventSync(::ohos::multimodalInput::inputEventClient::KeyEventInfo const& keyEvent)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    Input_KeyEvent* keyEventNative = OH_Input_CreateKeyEvent();
    GetInjectionEventDataNative(keyEventNative, keyEvent.KeyEvent);
#else
    auto lkeyEvent = OHOS::MMI::KeyEvent::Create();
    GetInjectionEventData(lkeyEvent, keyEvent.KeyEvent);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

void HandleMouseButton(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, int32_t action)
{
    int32_t button = static_cast<int32_t>(mouseEvent.button.get_value());
    if (THMouseButton2Native.find(button) != THMouseButton2Native.end()) {
        button = THMouseButton2Native[button];
    } else {
        TH_THROW(std::runtime_error, "button is unknown");
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
            TH_THROW(std::runtime_error, "action is unknown");
            break;
    }

    if (action == TAHE_BUTTON_DOWN || action == TAHE_BUTTON_UP
        || action == TAHE_MOVE) {
        HandleMouseButton(mouseEvent, pointerEvent, action);
    }
}

void HandleMousePropertyInt32(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    int32_t screenX = mouseEvent.screenX;
    int32_t screenY = mouseEvent.screenY;
    int32_t toolType = mouseEvent.toolType.get_value();
#ifdef FLAG_NEED_TO_CONFIRM // 0702 The sdk of does not have this property
    double globalX = 0;
    if (mouseEvent.globalX.has_value()) {
        globalX = mouseEvent.globalX.value();
    }
    double globalY = 0;
    if (mouseEvent.globalY.has_value()) {
        globalY = mouseEvent.globalY.value();
    }
#endif
    pointerEvent->SetSourceType(toolType);
    item.SetPointerId(0);
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
#ifdef FLAG_NEED_TO_CONFIRM // 0702 The sdk of does not have this property
    if (globalX != DBL_MAX && globalY != DBL_MAX) {
        item.SetGlobalX(globalX);
        item.SetGlobalY(globalY);
    }
#endif
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
}

void HandleMousePressedButtons(::ohos::multimodalInput::mouseEvent::MouseEvent mouseEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
    std::vector<int32_t> jsPressedButtons {};
    for (auto it = mouseEvent.pressedButtons.begin(); it != mouseEvent.pressedButtons.end(); ++it) {
        jsPressedButtons.push_back(static_cast<int32_t>(*it));
    }

    std::vector<int32_t> nativePressedButtons { };
    for (const auto jsButton : jsPressedButtons) {
        if (THMouseButton2Native.find(jsButton) == THMouseButton2Native.end()) {
            TH_THROW(std::runtime_error, "Unknown jsButton");
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
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    HandleMouseAction(mouseEvent.mouseEvent, pointerEvent, item);
    HandleMousePropertyInt32(mouseEvent.mouseEvent, pointerEvent, item);
    HandleMousePressedButtons(mouseEvent.mouseEvent, pointerEvent, item);
#ifdef FLAG_NEED_TO_CONFIRM  // 0702 The sdk of does not have this property.
    int32_t useCoordinate = PointerEvent::DISPLAY_COORDINATE;
    bool useGlobalCoordinate = mouseEvent.useGlobalCoordinate;
    if (useGlobalCoordinate) {
        MMI_HILOGD("useGlobalCoordinate");
        useCoordinate = PointerEvent::GLOBAL_COORDINATE;
    }
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, true, useCoordinate);
#endif
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
}

int32_t HandleTouchAction(::ohos::multimodalInput::touchEvent::TouchEvent touchEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item)
{
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
            TH_THROW(std::runtime_error, "action is unknown");
            break;
    }
    return action;
}

void HandleTouchAttribute(std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item,
    ::ohos::multimodalInput::touchEvent::Touch& touch, int32_t isTouch)
{
    int32_t pointerId = touch.id;
    int32_t screenX = touch.screenX;
    int32_t screenY = touch.screenY;
    int64_t pressedTime = touch.pressedTime;
    int32_t toolType = static_cast<int32_t>(touch.toolType.get_value());
    double pressure = touch.pressure;
#ifdef FLAG_NEED_TO_CONFIRM    // 0702 SDK The branch does not have these fields
     int32_t globalX = touch.globalX;
     int32_t globalY = touch.globalY;
#endif

    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetDisplayXPos(screenX);
    item.SetDisplayYPos(screenY);
    item.SetPointerId(pointerId);
    item.SetToolType(toolType);
    item.SetPressure(pressure);
#ifdef FLAG_NEED_TO_CONFIRM  // 0702 SDK The branch does not have these fields
     if (globalX != INT_MAX && globalY != INT_MAX) {
         item.SetGlobalX(globalX);
         item.SetGlobalY(globalY);
     }
#endif
    if (isTouch) {
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetActionTime(pressedTime);
    }
}

void HandleTouchesProperty(std::shared_ptr<PointerEvent> pointerEvent,
    ::taihe::array_view<::ohos::multimodalInput::touchEvent::Touch>& touches,
    std::vector<PointerEvent::PointerItem>& pointerItems)
{
    for (auto it = touches.begin(); it != touches.end(); ++it) {
        PointerEvent::PointerItem pointerItem;
        HandleTouchAttribute(pointerEvent, pointerItem, *it, false);
        pointerItems.push_back(pointerItem);
    }
}

bool HandleTouchPropertyInt32(::ohos::multimodalInput::touchEvent::TouchEvent touchEvent,
    std::shared_ptr<PointerEvent> pointerEvent, PointerEvent::PointerItem &item, int32_t action)
{
    int32_t sourceType = touchEvent.sourceType.get_value();
    if (sourceType < 0) {
        TH_THROW(std::runtime_error, "sourceType must be greater than or equal to 0");
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
            TH_THROW(std::runtime_error, "fixedMode is not defined");
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
#ifdef FLAG_NEED_TO_CONFIRM    // 0702 The branch does not have these fields useGlobalCoordinate
   bool useGlobalCoordinate = false;
#endif
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    int32_t action = HandleTouchAction(touchEvent.touchEvent, pointerEvent, item);
    HandleTouchPropertyInt32(touchEvent.touchEvent, pointerEvent, item, action);

    #ifdef FLAG_NEED_TO_CONFIRM    // 0702 The branch does not have these fields useGlobalCoordinate
    int32_t useCoordinate = PointerEvent::DISPLAY_COORDINATE;
    if (useGlobalCoordinate) {
        TH_THROW(std::runtime_error, "useGlobalCoordinate");
        useCoordinate = PointerEvent::GLOBAL_COORDINATE;
    }
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, pointerEvent->GetAutoToVirtualScreen(),
        useCoordinate);
#endif
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent, pointerEvent->GetAutoToVirtualScreen());
}

void PermitInjectionSync(bool result)
{
    InputManager::GetInstance()->Authorize(result);
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_InjectKeyEventSync(InjectKeyEventSync);
TH_EXPORT_CPP_API_InjectEventSync(InjectEventSync);
TH_EXPORT_CPP_API_InjectMouseEventSync(InjectMouseEventSync);
TH_EXPORT_CPP_API_InjectTouchEventSync(InjectTouchEventSync);
TH_EXPORT_CPP_API_PermitInjectionSync(PermitInjectionSync);
// NOLINTEND