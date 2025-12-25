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

#include "nocopyable.h"

#include "delegate_tasks.h"
#include "i_delegate_interface.h"
#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
class DelegateInterface final :
    public IDelegateInterface,
    public IInputEventHandler::IInputEventConsumer,
    public std::enable_shared_from_this<DelegateInterface> {
public:
    DISALLOW_COPY_AND_MOVE(DelegateInterface);
    explicit DelegateInterface(std::function<int32_t(DTaskCallback)> delegate,
        std::function<int32_t(DTaskCallback)> asyncFun) : delegateTasks_(delegate), asyncDelegateTasks_(asyncFun) {}
    void Init();
    int32_t OnPostSyncTask(DTaskCallback cb) const override;
    int32_t OnPostAsyncTask(DTaskCallback cb) const override;

#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    void RemoveHandler(InputHandlerType handlerType, const std::string &name) override;
    int32_t AddHandler(InputHandlerType handlerType, const HandlerSummary &summary) override;
    bool HasHandler(const std::string &name) const override;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR

private:
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    uint32_t GetDeviceTags(InputHandlerType type) const;
    int32_t GetPriority(InputHandlerType type) const;
    HandleEventType GetEventType(InputHandlerType type) const;
    std::optional<HandlerSummary> RemoveLocal(InputHandlerType type, const std::string &name, uint32_t &deviceTags);
    void OnInputEventHandler(InputHandlerType type, std::shared_ptr<PointerEvent> event) const;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<KeyEvent> event) const override {}
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<PointerEvent> event) const override;
    virtual void OnInputEvent(InputHandlerType type, std::shared_ptr<AxisEvent> event) const override {}
#ifdef OHOS_BUILD_ENABLE_MONITOR
    bool MonitorExpectEvent(const HandlerSummary &monitor, std::shared_ptr<PointerEvent> event) const;
#endif // OHOS_BUILD_ENABLE_MONITOR

private:
    std::function<int32_t(DTaskCallback)> delegateTasks_;
    std::function<int32_t(DTaskCallback)> asyncDelegateTasks_;
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    std::unordered_multimap<InputHandlerType, HandlerSummary> handlers_;
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
};
} // namespace MMI
} // namespace OHOS
#endif // DELEGATE_INTERFACE_H