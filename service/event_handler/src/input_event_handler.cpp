/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "input_event_handler.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "libinput.h"
#include "key_command_handler.h"
#include "timer_manager.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MT_TOOL_PALM { 2 };
constexpr int32_t TIMEOUT_MS { 1500 };
constexpr uint32_t KEY_ESC { 1 };
constexpr uint32_t KEY_KPASTERISK { 55 };
constexpr uint32_t KEY_F1 { 59 };
constexpr uint32_t KEY_LEFTCTRL { 29 };
constexpr uint32_t KEY_RIGHTCTRL { 97 };
constexpr uint32_t KEY_LEFTALT { 56 };
constexpr uint32_t KEY_RIGHTALT { 100 };
constexpr uint32_t KEY_LEFTSHIFT { 42 };
constexpr uint32_t KEY_RIGHTSHIFT { 54 };
constexpr uint32_t KEY_FN { 0x1d0 };
constexpr uint32_t KEY_CAPSLOCK { 58 };
constexpr uint32_t KEY_TAB { 15 };
constexpr uint32_t KEY_COMPOSE { 127 };
constexpr uint32_t KEY_RIGHTMETA { 126 };
constexpr uint32_t KEY_LEFTMETA { 125 };
} // namespace

InputEventHandler::InputEventHandler()
{
    lastEventBeginTime_ = GetSysClockTime();
    udsServer_ = nullptr;
}

InputEventHandler::~InputEventHandler() {}

void InputEventHandler::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    BuildInputHandlerChain();
}

void InputEventHandler::OnEvent(void *event, int64_t frameTime)
{
    CHKPV(eventNormalizeHandler_);
    if (event == nullptr) {
        eventNormalizeHandler_->HandleEvent(nullptr, frameTime);
        return;
    }

    idSeed_ += 1;
    const uint64_t maxUInt64 = (std::numeric_limits<uint64_t>::max)() - 1;
    if (idSeed_ >= maxUInt64) {
        MMI_HILOGE("The value is flipped. id:%{public}" PRId64, idSeed_);
        idSeed_ = 1;
    }

    auto *lpEvent = static_cast<libinput_event *>(event);
    CHKPV(lpEvent);
    int32_t eventType = libinput_event_get_type(lpEvent);
    int64_t beginTime = GetSysClockTime();
    lastEventBeginTime_ = beginTime;
    MMI_HILOGD("Event reporting. id:%{public}" PRId64 ",tid:%{public}" PRId64 ",eventType:%{public}d,"
               "beginTime:%{public}" PRId64, idSeed_, GetThisThreadId(), eventType, beginTime);
    
    UpdateDwtRecord(lpEvent);
    if (IsTouchpadMistouch(lpEvent)) {
        return;
    }

    ResetLogTrace();
    eventNormalizeHandler_->HandleEvent(lpEvent, frameTime);
    int64_t endTime = GetSysClockTime();
    int64_t lostTime = endTime - beginTime;
    if (lostTime >= TIMEOUT_MS) {
        MMI_HILOGE("Event handling completed. id:%{public}" PRId64 ",endTime:%{public}" PRId64
               ",lostTime:%{public}" PRId64, idSeed_, endTime, lostTime);
    }
    MMI_HILOGD("Event handling completed. id:%{public}" PRId64 ",endTime:%{public}" PRId64
               ",lostTime:%{public}" PRId64, idSeed_, endTime, lostTime);
}

void InputEventHandler::UpdateDwtRecord(libinput_event *event)
{
    CHKPV(event);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_DOWN || type == LIBINPUT_EVENT_TOUCHPAD_MOTION) {
        UpdateDwtTouchpadRecord(event);
    }
    if (type == LIBINPUT_EVENT_KEYBOARD_KEY) {
        UpdateDwtKeyboardRecord(event);
    }
}

void InputEventHandler::UpdateDwtTouchpadRecord(libinput_event *event)
{
    auto touchpadEvent = libinput_event_get_touchpad_event(event);
    CHKPV(touchpadEvent);
    auto type = libinput_event_get_type(event);
    auto touchpadDevice = libinput_event_get_device(event); // guaranteed valid during event lifetime
    CHKPV(touchpadDevice);
    double touchpadSizeX;
    double touchpadSizeY;
    if (libinput_device_get_size(touchpadDevice, &touchpadSizeX, &touchpadSizeY) != 0) {
        MMI_HILOGW("Failed to get touchpad device size");
        return;
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_DOWN) {
        touchpadEventDownAbsX_ = libinput_event_touchpad_get_x(touchpadEvent);
        touchpadEventDownAbsY_ = libinput_event_touchpad_get_y(touchpadEvent);
        touchpadEventAbsX_ = touchpadEventDownAbsX_;
        touchpadEventAbsY_ = touchpadEventDownAbsY_;
        if (touchpadEventDownAbsX_ > TOUCHPAD_EDGE_WIDTH &&
            touchpadEventDownAbsX_ < touchpadSizeX - TOUCHPAD_EDGE_WIDTH) {
            isDwtEdgeAreaForTouchpadMotionActing_ = false;
            MMI_HILOGD("Pointer edge dwt unlocked, coordX = %{private}f", touchpadEventDownAbsX_);
        }
        if (touchpadEventDownAbsX_ > TOUCHPAD_EDGE_WIDTH_FOR_BUTTON &&
            touchpadEventDownAbsX_ < touchpadSizeX - TOUCHPAD_EDGE_WIDTH_FOR_BUTTON) {
            isDwtEdgeAreaForTouchpadButtonActing_ = false;
            MMI_HILOGD("Button edge dwt unlocked, coordX = %{private}f", touchpadEventDownAbsX_);
        }
        if (touchpadEventDownAbsX_ > TOUCHPAD_EDGE_WIDTH_FOR_TAP &&
            touchpadEventDownAbsX_ < touchpadSizeX - TOUCHPAD_EDGE_WIDTH_FOR_TAP) {
            isDwtEdgeAreaForTouchpadTapActing_ = false;
            MMI_HILOGD("Tap edge dwt unlocked, coordX = %{private}f", touchpadEventDownAbsX_);
        }
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_MOTION) {
        touchpadEventAbsX_ = libinput_event_touchpad_get_x(touchpadEvent);
        touchpadEventAbsY_ = libinput_event_touchpad_get_y(touchpadEvent);
        int32_t toolType = libinput_event_touchpad_get_tool_type(touchpadEvent);
        if (touchpadEventAbsX_ > TOUCHPAD_EDGE_WIDTH_RELEASE &&
            touchpadEventAbsX_ < touchpadSizeX - TOUCHPAD_EDGE_WIDTH_RELEASE &&
            toolType != MT_TOOL_PALM) {
            isDwtEdgeAreaForTouchpadMotionActing_ = false;
            MMI_HILOGD("Pointer edge dwt unlocked, coordX = %{private}f", touchpadEventDownAbsX_);
        }
    }
}

void InputEventHandler::UpdateDwtKeyboardRecord(libinput_event *event)
{
    auto keyboardEvent = libinput_event_get_keyboard_event(event);
    CHKPV(keyboardEvent);
    uint32_t key = libinput_event_keyboard_get_key(keyboardEvent);
    if (IsStandaloneFunctionKey(key)) {
        return;
    }

    auto keyState = libinput_event_keyboard_get_key_state(keyboardEvent);
    if (IsModifierKey(key)) {
        modifierPressedCount_ += (keyState == LIBINPUT_KEY_STATE_PRESSED) ? 1 : -1;
    }
    if (keyState == LIBINPUT_KEY_STATE_PRESSED && modifierPressedCount_ > 0) {
        isKeyPressedWithAnyModifiers_[key] = true; // set flag when key is pressed with modifiers
    }
    if (!IsModifierKey(key) && !isKeyPressedWithAnyModifiers_[key]) {
        RefreshDwtActingState();
    }
    if (keyState == LIBINPUT_KEY_STATE_RELEASED) {
        isKeyPressedWithAnyModifiers_[key] = false; // always reset flag when key is released
    }
}

bool InputEventHandler::IsStandaloneFunctionKey(uint32_t keycode)
{
    if (IsModifierKey(keycode)) {
        return false;
    }
    switch (keycode) {
        case KEY_ESC:
        case KEY_KPASTERISK:
            return true;
        default:
            return keycode >= KEY_F1;
    }
}

bool InputEventHandler::IsModifierKey(uint32_t keycode)
{
    switch (keycode) {
        case KEY_LEFTCTRL:
        case KEY_RIGHTCTRL:
        case KEY_LEFTALT:
        case KEY_RIGHTALT:
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
        case KEY_FN:
        case KEY_CAPSLOCK:
        case KEY_TAB:
        case KEY_COMPOSE:
        case KEY_RIGHTMETA:
        case KEY_LEFTMETA:
            return true;
        default:
            return false;
    }
}

void InputEventHandler::RefreshDwtActingState()
{
    isDwtEdgeAreaForTouchpadMotionActing_ = true;
    isDwtEdgeAreaForTouchpadButtonActing_ = true;
    isDwtEdgeAreaForTouchpadTapActing_ = true;
}

bool InputEventHandler::IsTouchpadMistouch(libinput_event *event)
{
    CHKPF(event);
    auto type = libinput_event_get_type(event);
    if (type >= LIBINPUT_EVENT_TOUCHPAD_DOWN && type <= LIBINPUT_EVENT_TOUCHPAD_MOTION) {
        auto touchpadEvent = libinput_event_get_touchpad_event(event);
        CHKPF(touchpadEvent);
        int32_t toolType = libinput_event_touchpad_get_tool_type(touchpadEvent);
        if (toolType == MT_TOOL_PALM) {
            MMI_HILOGD("Touchpad event is palm");
            return false;
        }
    }

    if (type == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        return IsTouchpadButtonMistouch(event);
    }
    if (type == LIBINPUT_EVENT_POINTER_TAP) {
        return IsTouchpadTapMistouch(event);
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_MOTION) {
        return IsTouchpadMotionMistouch(event);
    }
    if (type == LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD) {
        return IsTouchpadPointerMotionMistouch(event);
    }

    return false;
}

bool InputEventHandler::IsTouchpadButtonMistouch(libinput_event* event)
{
    CHKPF(event);
    auto touchpadButtonEvent = libinput_event_get_pointer_event(event);
    CHKPF(touchpadButtonEvent);
    auto buttonState = libinput_event_pointer_get_button_state(touchpadButtonEvent);
    if (buttonState == LIBINPUT_BUTTON_STATE_PRESSED) {
        auto touchpadDevice = libinput_event_get_device(event); // guaranteed valid during event lifetime
        CHKPF(touchpadDevice);
        double touchpadSizeX;
        double touchpadSizeY;
        if (libinput_device_get_size(touchpadDevice, &touchpadSizeX, &touchpadSizeY) != 0) {
            return false;
        }
        double coordX = touchpadEventAbsX_;
        if (isDwtEdgeAreaForTouchpadButtonActing_ &&
            (coordX <= TOUCHPAD_EDGE_WIDTH_FOR_BUTTON || coordX >= touchpadSizeX - TOUCHPAD_EDGE_WIDTH_FOR_BUTTON)) {
            isButtonMistouch_ = true;
            MMI_HILOGD("The buttonPressed event is mistouch");
            return true;
        }
    }
    if (buttonState == LIBINPUT_BUTTON_STATE_RELEASED) {
        if (isButtonMistouch_) {
            isButtonMistouch_ = false;
            MMI_HILOGD("The buttonReleased event is mistouch");
            return true;
        }
    }
    return false;
}

bool InputEventHandler::IsTouchpadTapMistouch(libinput_event* event)
{
    CHKPF(event);
    auto data = libinput_event_get_pointer_event(event);
    CHKPF(data);
    auto state = libinput_event_pointer_get_button_state(data);
    if (state == LIBINPUT_BUTTON_STATE_PRESSED) {
        auto touchpadDevice = libinput_event_get_device(event); // guaranteed valid during event lifetime
        CHKPF(touchpadDevice);
        double touchpadSizeX;
        double touchpadSizeY;
        if (libinput_device_get_size(touchpadDevice, &touchpadSizeX, &touchpadSizeY) != 0) {
            return false;
        }
        double coordX = touchpadEventDownAbsX_;
        if (isDwtEdgeAreaForTouchpadTapActing_ &&
            (coordX <= TOUCHPAD_EDGE_WIDTH_FOR_TAP || coordX >= touchpadSizeX - TOUCHPAD_EDGE_WIDTH_FOR_TAP)) {
            isTapMistouch_ = true;
            MMI_HILOGD("Touchpad tap presse event is mistouch");
            return true;
        }
    }
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        if (isTapMistouch_) {
            isTapMistouch_ = false;
            MMI_HILOGD("Touchpad tap release event is mistouch");
            return true;
        }
    }
    return false;
}

bool InputEventHandler::IsTouchpadMotionMistouch(libinput_event *event)
{
    if (!isDwtEdgeAreaForTouchpadMotionActing_) {
        return false;
    }

    CHKPF(event);
    auto touchpadEvent = libinput_event_get_touchpad_event(event);
    CHKPF(touchpadEvent);
    auto touchpadDevice = libinput_event_get_device(event); // guaranteed valid during event lifetime
    CHKPF(touchpadDevice);
    double touchpadSizeX;
    double touchpadSizeY;
    if (libinput_device_get_size(touchpadDevice, &touchpadSizeX, &touchpadSizeY) != 0) {
        return false;
    }
    auto coordX = touchpadEventDownAbsX_;
    if (coordX <= TOUCHPAD_EDGE_WIDTH || coordX >= touchpadSizeX - TOUCHPAD_EDGE_WIDTH) {
        MMI_HILOGD("Touchpad event is edge mistouch");
        return true;
    }
    return false;
}

bool InputEventHandler::IsTouchpadPointerMotionMistouch(libinput_event *event)
{
    if (!isDwtEdgeAreaForTouchpadMotionActing_) {
        return false;
    }

    CHKPF(event);
    auto pointerEvent = libinput_event_get_pointer_event(event);
    CHKPF(pointerEvent);
    auto touchpadDevice = libinput_event_get_device(event); // guaranteed valid during event lifetime
    CHKPF(touchpadDevice);
    double touchpadSizeX;
    double touchpadSizeY;
    if (libinput_device_get_size(touchpadDevice, &touchpadSizeX, &touchpadSizeY) != 0) {
        return false;
    }
    double coordX = touchpadEventDownAbsX_;
    if (coordX <= TOUCHPAD_EDGE_WIDTH || coordX >= touchpadSizeX - TOUCHPAD_EDGE_WIDTH) {
        MMI_HILOGD("Touchpad pointer motion event is edge mistouch");
        return true;
    }
    return false;
}

int32_t InputEventHandler::BuildInputHandlerChain()
{
    eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
#if !defined(OHOS_BUILD_ENABLE_KEYBOARD) && !defined(OHOS_BUILD_ENABLE_POINTER) && !defined(OHOS_BUILD_ENABLE_TOUCH)
    return RET_OK;
#endif // !OHOS_BUILD_ENABLE_KEYBOARD && !OHOS_BUILD_ENABLE_POINTER && !OHOS_BUILD_ENABLE_TOUCH

    std::shared_ptr<IInputEventHandler> handler = eventNormalizeHandler_;
    inputActiveSubscriberHandler_ = std::make_shared<InputActiveSubscriberHandler>();
    if (inputActiveSubscriberHandler_) {
        handler->SetNext(inputActiveSubscriberHandler_);
        handler = inputActiveSubscriberHandler_;
    } else {
        MMI_HILOGE("failed to alloc InputActiveSubscriberHandler");
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    eventFilterHandler_ = std::make_shared<EventFilterHandler>();
    handler->SetNext(eventFilterHandler_);
    handler = eventFilterHandler_;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    eventInterceptorHandler_ = std::make_shared<EventInterceptorHandler>();
    handler->SetNext(eventInterceptorHandler_);
    handler = eventInterceptorHandler_;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_COMBINATION_KEY
    eventPreMonitorHandler_ = std::make_shared<EventPreMonitorHandler>();
    handler->SetNext(eventPreMonitorHandler_);
    handler = eventPreMonitorHandler_;
    eventKeyCommandHandler_ = std::make_shared<KeyCommandHandler>();
    handler->SetNext(eventKeyCommandHandler_);
    handler = eventKeyCommandHandler_;
#endif // OHOS_BUILD_ENABLE_COMBINATION_KEY
    eventSubscriberHandler_ = std::make_shared<KeySubscriberHandler>();
    handler->SetNext(eventSubscriberHandler_);
    handler = eventSubscriberHandler_;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_SWITCH
    switchEventSubscriberHandler_ = std::make_shared<SwitchSubscriberHandler>();
    handler->SetNext(switchEventSubscriberHandler_);
    handler = switchEventSubscriberHandler_;
#endif // OHOS_BUILD_ENABLE_SWITCH
#ifdef OHOS_BUILD_ENABLE_MONITOR
    eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    handler->SetNext(eventMonitorHandler_);
    handler = eventMonitorHandler_;
#endif // OHOS_BUILD_ENABLE_MONITOR
    eventDispatchHandler_ = std::make_shared<EventDispatchHandler>();
    handler->SetNext(eventDispatchHandler_);
    return RET_OK;
}

int32_t InputEventHandler::GetIntervalSinceLastInput(int64_t &timeInterval)
{
    int64_t currentSystemTime = GetSysClockTime();
    timeInterval = currentSystemTime - lastEventBeginTime_;
    return RET_OK;
}

UDSServer* InputEventHandler::GetUDSServer() const
{
    return udsServer_;
}

std::shared_ptr<EventNormalizeHandler> InputEventHandler::GetEventNormalizeHandler() const
{
    return eventNormalizeHandler_;
}

std::shared_ptr<EventInterceptorHandler> InputEventHandler::GetInterceptorHandler() const
{
    return eventInterceptorHandler_;
}

std::shared_ptr<KeySubscriberHandler> InputEventHandler::GetSubscriberHandler() const
{
    return eventSubscriberHandler_;
}

std::shared_ptr<SwitchSubscriberHandler> InputEventHandler::GetSwitchSubscriberHandler() const
{
    return switchEventSubscriberHandler_;
}

std::shared_ptr<KeyCommandHandler> InputEventHandler::GetKeyCommandHandler() const
{
    return eventKeyCommandHandler_;
}

std::shared_ptr<EventMonitorHandler> InputEventHandler::GetMonitorHandler() const
{
    return eventMonitorHandler_;
}

std::shared_ptr<EventFilterHandler> InputEventHandler::GetFilterHandler() const
{
    return eventFilterHandler_;
}

std::shared_ptr<EventDispatchHandler> InputEventHandler::GetEventDispatchHandler() const
{
    return eventDispatchHandler_;
}

std::shared_ptr<EventPreMonitorHandler> InputEventHandler::GetEventPreMonitorHandler() const
{
    return eventPreMonitorHandler_;
}

int32_t InputEventHandler::SetMoveEventFilters(bool flag)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    CHKPR(eventNormalizeHandler_, INVALID_HANDLER_ID);
    return eventNormalizeHandler_->SetMoveEventFilters(flag);
#else
    MMI_HILOGW("Set move event filters does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
}

std::shared_ptr<InputActiveSubscriberHandler> InputEventHandler::GetInputActiveSubscriberHandler() const
{
    return inputActiveSubscriberHandler_;
}
} // namespace MMI
} // namespace OHOS