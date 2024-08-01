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

#ifndef DELEGATE_INTERFACE_H
#define DELEGATE_INTERFACE_H

#include <functional>

#include "nocopyable.h"

#include "delegate_tasks.h"
#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
enum class HandlerMode {
    SYNC,
    ASYNC
};
using TaskCallback = std::function<int32_t(std::shared_ptr<PointerEvent>)>;
class DelegateInterface final :
    public IInputEventHandler::IInputEventConsumer,
    public std::enable_shared_from_this<DelegateInterface> {
public:
    DISALLOW_COPY_AND_MOVE(DelegateInterface);
    explicit DelegateInterface(std::function<int32_t(DTaskCallback)> delegate)
        : delegateTasks_(delegate) {}
    void Init();
    int32_t OnPostSyncTask(DTaskCallback cb) const;

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    struct HandlerSummary {
        std::string handlerName;
        HandleEventType eventType;
        HandlerMode mode;
        int32_t priority;
        uint32_t deviceTags;
        TaskCallback cb;
    };
    void RemoveHandler(InputHandlerType handlerType, std::string name);
    int32_t AddHandler(InputHandlerType handlerType, HandlerSummary summary);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

private:
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    uint32_t GetDeviceTags(InputHandlerType type) const;
    int32_t GetPriority(InputHandlerType type) const;
    HandleEventType GetEventType(InputHandlerType type) const;
    void RemoveLocal(InputHandlerType type, std::string name, uint32_t &deviceTags);
    void OnInputEventHandler(InputHandlerType type, std::shared_ptr<PointerEvent> event) const;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<KeyEvent> event) const override {}
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<PointerEvent> event) const override;
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<AxisEvent> event) const override {}

private:
    std::function<int32_t(DTaskCallback)> delegateTasks_;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    std::unordered_multimap<InputHandlerType, HandlerSummary> handlers;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
};
} // namespace MMI
} // namespace OHOS
#endif // DELEGATE_INTERFACE_H