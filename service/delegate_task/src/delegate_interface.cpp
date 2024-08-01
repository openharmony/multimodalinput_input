/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "delegate_interface.h"

#include "display_event_monitor.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "touch_drawing_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateInterface"

namespace OHOS {
namespace MMI {
void DelegateInterface::Init()
{
    TOUCH_DRAWING_MGR->SetDelegateProxy(shared_from_this());
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    DISPLAY_MONITOR->SetDelegateProxy(shared_from_this());
#endif // #ifdef OHOS_BUILD_ENABLE_KEYBOARD
}

int32_t DelegateInterface::OnPostSyncTask(DTaskCallback cb) const
{
    CHKPR(delegateTasks_, ERROR_NULL_POINTER);
    int32_t ret = delegateTasks_(cb);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to execute the task, ret: %{public}d", ret);
    }
    return ret;
}

void DelegateInterface::OnInputEvent(
    InputHandlerType type, std::shared_ptr<PointerEvent> event) const
{
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    OnInputEventHandler(type, event);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
}

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
void DelegateInterface::OnInputEventHandler(
    InputHandlerType type, std::shared_ptr<PointerEvent> event) const
{
    CHKPV(event);
    for (const auto &handler : handlers) {
        auto summary = handler.second;
        if (handler.first != type) {
            continue;
        }
#ifdef OHOS_BUILD_ENABLE_MONITOR
        if (type == InputHandlerType::MONITOR &&
            (summary.eventType & HANDLE_EVENT_TYPE_POINTER) != HANDLE_EVENT_TYPE_POINTER) {
            continue;
        }
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
        uint32_t deviceTags = 0;
        if (type == InputHandlerType::INTERCEPTOR &&
            ((deviceTags & summary.deviceTags) == summary.deviceTags) &&
            !EventInterceptorHandler::CheckInputDeviceSource(event, summary.deviceTags)) {
            continue;
        }
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
        CHKPV(summary.cb);
        if (summary.mode == HandlerMode::SYNC) {
            summary.cb(event);
        } else {
            if (OnPostSyncTask(std::bind(summary.cb, event)) != RET_OK) {
                MMI_HILOGE("Failed to execute the task(%{public}s)", summary.handlerName.c_str());
            }
        }
    }
}

int32_t DelegateInterface::AddHandler(InputHandlerType type, HandlerSummary summary)
{
    CHKPR(summary.cb, ERROR_NULL_POINTER);
    int32_t ret = RET_OK;
    for (const auto &handler : handlers) {
        if (handler.second.handlerName == summary.handlerName) {
            MMI_HILOGW("The current handler(%{public}s) already exists", summary.handlerName.c_str());
            return ret;
        }
    }
    const HandleEventType currentType = GetEventType(type);
    uint32_t currentTags = GetDeviceTags(type);
    handlers.emplace(type, summary);
    const HandleEventType newType = GetEventType(type);
    if (currentType != newType || ((currentTags & summary.deviceTags) != summary.deviceTags)) {
        uint32_t allDeviceTags = GetDeviceTags(type);
        if (type == InputHandlerType::INTERCEPTOR) {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            auto interceptorHandler = InputHandler->GetInterceptorHandler();
            CHKPR(interceptorHandler, ERROR_NULL_POINTER);
            ret = interceptorHandler->AddInputHandler(type,
                newType, summary.priority, allDeviceTags, nullptr);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
        } else if (type == InputHandlerType::MONITOR) {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPR(monitorHandler, ERROR_NULL_POINTER);
            ret = monitorHandler->AddInputHandler(type,
                newType, shared_from_this());
#endif // OHOS_BUILD_ENABLE_MONITOR
        }
    }
    if (ret != RET_OK) {
        RemoveLocal(type, summary.handlerName, currentTags);
    } else {
        MMI_HILOGI("Service Add Monitor Success, size:%{public}zu", handlers.size());
    }
    return ret;
}

HandleEventType DelegateInterface::GetEventType(InputHandlerType type) const
{
    uint32_t eventType {HANDLE_EVENT_TYPE_NONE};
    if (handlers.empty()) {
        MMI_HILOGW("handlers is empty");
        return HANDLE_EVENT_TYPE_NONE;
    }
    for (const auto &handler : handlers) {
        if (handler.first == type) {
            eventType |= handler.second.eventType;
        }
    }
    return eventType;
}

uint32_t DelegateInterface::GetDeviceTags(InputHandlerType type) const
{
    uint32_t deviceTags = 0;
    if (type == InputHandlerType::MONITOR) {
        return deviceTags;
    }
    if (handlers.empty()) {
        MMI_HILOGW("handlers is empty");
        return deviceTags;
    }
    for (const auto &handler : handlers) {
        if (handler.first == type) {
            deviceTags |= handler.second.deviceTags;
        }
    }
    return deviceTags;
}

void DelegateInterface::RemoveLocal(InputHandlerType type, std::string name, uint32_t &deviceTags)
{
    for (auto it = handlers.cbegin(); it != handlers.cend(); ++it) {
        if (type != it->first) {
            continue;
        }
        if (it->second.handlerName != name) {
            continue;
        }
        handlers.erase(it);
        if (type == InputHandlerType::INTERCEPTOR) {
            deviceTags = it->second.deviceTags;
        }
        break;
    }
}

int32_t DelegateInterface::GetPriority(InputHandlerType type) const
{
    for (auto it = handlers.cbegin(); it != handlers.cend(); ++it) {
        if (type == it->first) {
            return it->second.priority;
        }
    }
    return DEFUALT_INTERCEPTOR_PRIORITY;
}

void DelegateInterface::RemoveHandler(InputHandlerType type, std::string name)
{
    const HandleEventType currentType = GetEventType(type);
    uint32_t currentTags = GetDeviceTags(type);
    uint32_t deviceTags = 0;
    RemoveLocal(type, name, deviceTags);
    const HandleEventType newType = GetEventType(type);
    const int32_t newLevel = GetPriority(type);
    const uint64_t newTags = GetDeviceTags(type);
    if (currentType != newType || ((currentTags & deviceTags) != 0)) {
        if (type == InputHandlerType::INTERCEPTOR) {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
            auto interceptorHandler = InputHandler->GetInterceptorHandler();
            CHKPV(interceptorHandler);
            interceptorHandler->RemoveInputHandler(type,
                newType, newLevel, newTags, nullptr);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
        }
        if (type == InputHandlerType::MONITOR) {
#ifdef OHOS_BUILD_ENABLE_MONITOR
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPV(monitorHandler);
            monitorHandler->RemoveInputHandler(type,
                newType, shared_from_this());
#endif // OHOS_BUILD_ENABLE_MONITOR
        }
    }
    MMI_HILOGI("Remove Handler:%{public}d:%{public}s-%{public}d:%{public}d, size:%{public}zu", type,
               name.c_str(), currentType, currentTags, handlers.size());
}
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
} // namespace MMI
} // namespace OHOS