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

#ifndef INPUT_EVENT_HANDLER_H
#define INPUT_EVENT_HANDLER_H

#include <memory>

#include "nocopyable.h"
#include "singleton.h"

#include "event_dispatch.h"
#include "i_event_filter.h"
#include "i_input_event_handler.h"
#include "event_interceptor_handler.h"
#include "event_monitor_handler.h"
#include "key_event_subscriber.h"
#include "mouse_event_handler.h"
#include "event_filter_wrap.h"
#include "input_event_normalize_handler.h"

namespace OHOS {
namespace MMI {
using EventFun = std::function<int32_t(libinput_event *event)>;
using NotifyDeviceChange = std::function<void(int32_t, int32_t, char *)>;
class InputEventHandler : public DelayedSingleton<InputEventHandler> {
public:
    InputEventHandler();
    DISALLOW_COPY_AND_MOVE(InputEventHandler);
    virtual ~InputEventHandler() override;
    void Init(UDSServer& udsServer);
    void OnEvent(void *event);
    UDSServer *GetUDSServer() const;

    std::shared_ptr<InputEventNormalizeHandler> GetInputEventNormalizeHandler() const;
    std::shared_ptr<EventInterceptorHandler> GetInterceptorHandler() const;
    std::shared_ptr<KeyEventSubscriber> GetSubscriberHandler() const;
    std::shared_ptr<EventMonitorHandler> GetMonitorHandler() const;
    std::shared_ptr<EventFilterWrap> GetFilterHandler() const;

private:
    int32_t BuildInputHandlerChain();

    UDSServer *udsServer_ = nullptr;
    std::shared_ptr<InputEventNormalizeHandler> inputEventNormalizeHandler_ = nullptr;
    std::shared_ptr<EventFilterWrap> eventfilterHandler_ = nullptr;
    std::shared_ptr<EventInterceptorHandler> interceptorHandler_ = nullptr;
    std::shared_ptr<KeyEventSubscriber> subscriberHandler_ = nullptr;
    std::shared_ptr<EventMonitorHandler> monitorHandler_ = nullptr;

    uint64_t idSeed_ = 0;
};
#define InputHandler InputEventHandler::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_HANDLER_H
