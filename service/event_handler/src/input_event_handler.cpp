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
} // namespace

InputEventHandler::InputEventHandler()
{
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
    MMI_HILOGD("Event reporting. id:%{public}" PRId64 ",tid:%{public}" PRId64 ",eventType:%{public}d,"
               "beginTime:%{public}" PRId64, idSeed_, GetThisThreadId(), eventType, beginTime);
    if (IsTouchpadMistouch(lpEvent)) {
        return;
    }
    ResetLogTrace();
    eventNormalizeHandler_->HandleEvent(lpEvent, frameTime);
    int64_t endTime = GetSysClockTime();
    int64_t lostTime = endTime - beginTime;
    MMI_HILOGD("Event handling completed. id:%{public}" PRId64 ",endTime:%{public}" PRId64
               ",lostTime:%{public}" PRId64, idSeed_, endTime, lostTime);
}

bool InputEventHandler::IsTouchpadMistouch(libinput_event* event)
{
    CHKPF(event);
    auto touchpad = libinput_event_get_touchpad_event(event);
    if (touchpad != nullptr) {
        int32_t toolType = libinput_event_touchpad_get_tool_type(touchpad);
        if (toolType == MT_TOOL_PALM) {
            MMI_HILOGD("Touchpad event is palm");
            return false;
        }
    }

    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        MMI_HILOGD("Touchpad event is button");
        return false;
    }

    if (type == LIBINPUT_EVENT_POINTER_TAP) {
        auto isTapMistouch = IsTouchpadTapMistouch(event);
        return isTapMistouch;
    }

    if (type == LIBINPUT_EVENT_KEYBOARD_KEY) {
        isTyping_ = true;
        if (TimerMgr->IsExist(timerId_)) {
            TimerMgr->ResetTimer(timerId_);
        } else {
            static constexpr int32_t timeout = 400;
            std::weak_ptr<InputEventHandler> weakPtr = shared_from_this();
            timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
                CALL_DEBUG_ENTER;
                auto sharedPtr = weakPtr.lock();
                CHKPV(sharedPtr);
                MMI_HILOGD("Mistouch timer:%{public}d", sharedPtr->timerId_);
                sharedPtr->timerId_ = -1;
                sharedPtr->isTyping_ = false;
            });
        }
    }
    if (isTyping_ && (type == LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD || type == LIBINPUT_EVENT_TOUCHPAD_MOTION)) {
        MMI_HILOGD("The touchpad event is mistouch");
        return true;
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
        if (isTyping_) {
            isTapMistouch_ = true;
            MMI_HILOGD("The tapPressed event is mistouch");
            return true;
        }
    }
    if (state == LIBINPUT_BUTTON_STATE_RELEASED) {
        if (isTapMistouch_) {
            isTapMistouch_ = false;
            MMI_HILOGD("The tapReleased event is mistouch");
            return true;
        }
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
} // namespace MMI
} // namespace OHOS