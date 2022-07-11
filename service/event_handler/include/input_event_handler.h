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
#include "interceptor_handler_global.h"
#include "input_handler_manager_global.h"
#include "key_event_subscriber.h"
#include "mouse_event_handler.h"
#include "event_filter_wrap.h"
#include "msg_handler.h"
#include "input_event_normalize_handler.h"

namespace OHOS {
namespace MMI {
using EventFun = std::function<int32_t(libinput_event *event)>;
using NotifyDeviceChange = std::function<void(int32_t, int32_t, char *)>;
class InputEventHandler : public MsgHandler<MmiMessageId, EventFun>, public DelayedSingleton<InputEventHandler> {
public:
    InputEventHandler();
    DISALLOW_COPY_AND_MOVE(InputEventHandler);
    virtual ~InputEventHandler() override;
    void Init(UDSServer& udsServer);
    void OnEvent(void *event);
    UDSServer *GetUDSServer() const;
    std::shared_ptr<KeyEvent> GetKeyEvent() const;
    int32_t AddInputEventFilter(sptr<IEventFilter> filter);

    std::shared_ptr<InputEventNormalizeHandler> GetInputEventNormalizeHandler() const;
    std::shared_ptr<InterceptorHandlerGlobal> GetInterceptorHandler() const;
    std::shared_ptr<KeyEventSubscriber> GetSubscriberHandler() const;
    std::shared_ptr<InputHandlerManagerGlobal> GetMonitorHandler() const;

protected:
    int32_t OnEventDeviceAdded(libinput_event *event);
    int32_t OnEventDeviceRemoved(libinput_event *event);
    int32_t OnEventPointer(libinput_event *event);
    int32_t OnEventTouch(libinput_event *event);
    int32_t OnEventGesture(libinput_event *event);
    int32_t OnEventTouchpad(libinput_event *event);
    int32_t OnTabletToolEvent(libinput_event *event);
    int32_t OnEventKey(libinput_event *event);

private:
    int32_t OnEventHandler(libinput_event *event);
    int32_t BuildInputHandlerChain();

    UDSServer *udsServer_ = nullptr;
    NotifyDeviceChange notifyDeviceChange_;
    std::shared_ptr<KeyEvent> keyEvent_ = nullptr;

    std::shared_ptr<InputEventNormalizeHandler> inputEventNormalizeHandler_ = nullptr;
    std::shared_ptr<EventFilterWrap> eventfilterHandler_ = nullptr;
    std::shared_ptr<InterceptorHandlerGlobal> interceptorHandler_ = nullptr;
    std::shared_ptr<KeyEventSubscriber> subscriberHandler_ = nullptr;
    std::shared_ptr<InputHandlerManagerGlobal> monitorHandler_ = nullptr;

    uint64_t idSeed_ = 0;
};
#define InputHandler InputEventHandler::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_HANDLER_H
