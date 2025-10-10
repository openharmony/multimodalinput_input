/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_INPUT_EVENT_HANDLER_MOCK_H
#define MMI_INPUT_EVENT_HANDLER_MOCK_H
#include "event_dispatch_handler.h"
#include "event_filter_handler.h"
#include "event_interceptor_handler.h"
#include "event_monitor_handler.h"
#include "event_normalize_handler.h"
#include "key_command_handler.h"
#include "key_subscriber_handler.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class IInputEventHandlerManager {
public:
    IInputEventHandlerManager() = default;
    virtual ~IInputEventHandlerManager() = default;

    virtual UDSServer* GetUDSServer() const = 0;
    virtual std::shared_ptr<EventNormalizeHandler> GetEventNormalizeHandler() const = 0;
    virtual std::shared_ptr<EventInterceptorHandler> GetInterceptorHandler() const = 0;
    virtual std::shared_ptr<KeySubscriberHandler> GetSubscriberHandler() const = 0;
    virtual std::shared_ptr<SwitchSubscriberHandler> GetSwitchSubscriberHandler() const = 0;
    virtual std::shared_ptr<KeyCommandHandler> GetKeyCommandHandler() const = 0;
    virtual std::shared_ptr<EventMonitorHandler> GetMonitorHandler() const = 0;
    virtual std::shared_ptr<EventFilterHandler> GetFilterHandler() const = 0;
    virtual std::shared_ptr<EventDispatchHandler> GetEventDispatchHandler() const = 0;
};

class InputEventHandlerManager final : public IInputEventHandlerManager {
public:
    InputEventHandlerManager() = default;
    ~InputEventHandlerManager() override = default;

    MOCK_METHOD(UDSServer*, GetUDSServer, (), (const));
    MOCK_METHOD(std::shared_ptr<EventNormalizeHandler>, GetEventNormalizeHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<EventInterceptorHandler>, GetInterceptorHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<KeySubscriberHandler>, GetSubscriberHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<SwitchSubscriberHandler>, GetSwitchSubscriberHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<KeyCommandHandler>, GetKeyCommandHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<EventMonitorHandler>, GetMonitorHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<EventFilterHandler>, GetFilterHandler, (), (const));
    MOCK_METHOD(std::shared_ptr<EventDispatchHandler>, GetEventDispatchHandler, (), (const));

    static std::shared_ptr<InputEventHandlerManager> GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<InputEventHandlerManager> instance_;
};

#define InputHandler InputEventHandlerManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_INPUT_EVENT_HANDLER_MOCK_H