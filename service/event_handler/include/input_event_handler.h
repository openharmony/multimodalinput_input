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
#include "event_dispatch.h"
#include "event_package.h"
#include "i_event_filter.h"
#include "mouse_event_handler.h"
#include "msg_handler.h"
#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
using EventFun = std::function<int32_t(libinput_event *event)>;
using NotifyDeviceChange = std::function<void(int32_t, int32_t, char *)>;
class InputEventHandler : public MsgHandler<EventFun>, public DelayedSingleton<InputEventHandler> {
public:
    InputEventHandler();
    DISALLOW_COPY_AND_MOVE(InputEventHandler);
    virtual ~InputEventHandler() override;
    void Init(UDSServer& udsServer);
    void OnEvent(void *event);
    void OnCheckEventReport();
    int32_t OnMouseEventEndTimerHandler(std::shared_ptr<PointerEvent> pointerEvent);
    UDSServer *GetUDSServer() const;
    int32_t AddInputEventFilter(sptr<IEventFilter> filter);
    void AddHandleTimer();
protected:
    int32_t OnEventDeviceAdded(libinput_event *event);
    int32_t OnEventDeviceRemoved(libinput_event *event);
    int32_t OnEventPointer(libinput_event *event);
    int32_t OnEventTouch(libinput_event *event);
    int32_t OnEventTouchSecond(libinput_event *event);
    int32_t OnEventTouchPadSecond(libinput_event *event);
    int32_t OnEventGesture(libinput_event *event);
    int32_t OnEventTouchpad(libinput_event *event);
    int32_t OnGestureEvent(libinput_event *event);
    int32_t OnEventKey(libinput_event *event);
    
    int32_t OnMouseEventHandler(struct libinput_event *event);
    bool SendMsg(const int32_t fd, NetPacket& pkt) const;

private:
    int32_t OnEventHandler(libinput_event *event);
    UDSServer *udsServer_ = nullptr;
    EventDispatch eventDispatch_;
    EventPackage eventPackage_;
    NotifyDeviceChange notifyDeviceChange_;
    std::shared_ptr<KeyEvent> keyEvent_ = nullptr;

    uint64_t idSeed_ = 0;
    int32_t eventType_ = 0;
    int64_t initSysClock_ = 0;
    int64_t lastSysClock_ = 0;
    int32_t timerId_ = -1;
};

#define InputHandler InputEventHandler::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_HANDLER_H
