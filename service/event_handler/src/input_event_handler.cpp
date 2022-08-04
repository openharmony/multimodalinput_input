/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_event_handler.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>
#include <cinttypes>

#include <sys/stat.h>
#include <unistd.h>

#include "libinput.h"

#include "key_command_manager.h"
#include "timer_manager.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputEventHandler" };
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

void InputEventHandler::OnEvent(void *event)
{
    CHKPV(event);
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
    CHKPV(inputEventNormalizeHandler_);
    inputEventNormalizeHandler_->HandleEvent(lpEvent);
    int64_t endTime = GetSysClockTime();
    int64_t lostTime = endTime - beginTime;
    MMI_HILOGD("Event handling completed. id:%{public}" PRId64 ",endTime:%{public}" PRId64
               ",lostTime:%{public}" PRId64, idSeed_, endTime, lostTime);
}

int32_t InputEventHandler::BuildInputHandlerChain()
{
    inputEventNormalizeHandler_ = std::make_shared<InputEventNormalizeHandler>();
    CHKPR(inputEventNormalizeHandler_, ERROR_NULL_POINTER);
#if !defined(OHOS_BUILD_ENABLE_KEYBOARD) && !defined(OHOS_BUILD_ENABLE_POINTER) && !defined(OHOS_BUILD_ENABLE_TOUCH)
    return RET_OK;
#endif // !OHOS_BUILD_ENABLE_KEYBOARD && !OHOS_BUILD_ENABLE_POINTER && !OHOS_BUILD_ENABLE_TOUCH

    std::shared_ptr<IInputEventHandler> tmp = inputEventNormalizeHandler_;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    eventfilterHandler_ = std::make_shared<EventFilterWrap>();
    CHKPR(eventfilterHandler_, ERROR_NULL_POINTER);
    tmp->SetNext(eventfilterHandler_);
    tmp = eventfilterHandler_;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    interceptorHandler_  = std::make_shared<EventInterceptorHandler>();
    CHKPR(interceptorHandler_, ERROR_NULL_POINTER);
    tmp->SetNext(interceptorHandler_);
    tmp = interceptorHandler_;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_COMBINATION_KEY
    auto keyCommandHandler = std::make_shared<KeyCommandManager>();
    CHKPR(keyCommandHandler, ERROR_NULL_POINTER);
    tmp->SetNext(keyCommandHandler);
    tmp = keyCommandHandler;
#endif // OHOS_BUILD_ENABLE_COMBINATION_KEY
    subscriberHandler_ = std::make_shared<KeyEventSubscriber>();
    CHKPR(subscriberHandler_, ERROR_NULL_POINTER);
    tmp->SetNext(subscriberHandler_);
    tmp = subscriberHandler_;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_MONITOR
    monitorHandler_ = std::make_shared<EventMonitorHandler>();
    CHKPR(monitorHandler_, ERROR_NULL_POINTER);
    tmp->SetNext(monitorHandler_);
    tmp = monitorHandler_;
#endif // OHOS_BUILD_ENABLE_MONITOR
    auto dispatchHandler = std::make_shared<EventDispatch>();
    CHKPR(dispatchHandler, ERROR_NULL_POINTER);
    tmp->SetNext(dispatchHandler);
    return RET_OK;
}

UDSServer* InputEventHandler::GetUDSServer() const
{
    return udsServer_;
}

std::shared_ptr<InputEventNormalizeHandler> InputEventHandler::GetInputEventNormalizeHandler() const
{
    return inputEventNormalizeHandler_;
}

std::shared_ptr<EventInterceptorHandler> InputEventHandler::GetInterceptorHandler() const
{
    return interceptorHandler_;
}

std::shared_ptr<KeyEventSubscriber> InputEventHandler::GetSubscriberHandler() const
{
    return subscriberHandler_;
}

std::shared_ptr<EventMonitorHandler> InputEventHandler::GetMonitorHandler() const
{
    return monitorHandler_;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputEventHandler::AddInputEventFilter(sptr<IEventFilter> filter)
{
    CHKPR(eventfilterHandler_, ERROR_NULL_POINTER);
    eventfilterHandler_->AddInputEventFilter(filter);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
} // namespace MMI
} // namespace OHOS