/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_INPUT_EVENT_HANDLER_H
#define OHOS_INPUT_EVENT_HANDLER_H
#include "key_event_input_subscribe_filter.h"
#include "msg_handler.h"
#include "event_dispatch.h"
#include "event_package.h"
#include "c_singleton.h"
#include "i_event_filter.h"
#include "mouse_event_handler.h"
#include <memory>

namespace OHOS {
namespace MMI {
using EventFun = std::function<int32_t(multimodal_libinput_event &ev)>;
using NotifyDeviceChange = std::function<void(int32_t, int32_t, char *)>;
class InputEventHandler : public MsgHandler<EventFun>, public CSingleton<InputEventHandler> {
public:
    InputEventHandler();
    virtual ~InputEventHandler() override;
    bool Init(UDSServer& udsServer);
    void OnEvent(void *event);
    void OnCheckEventReport();
    void RegistnotifyDeviceChange(NotifyDeviceChange cb);
    int32_t OnMouseEventTimerHanler(std::shared_ptr<OHOS::MMI::PointerEvent> mouse_event);
    UDSServer *GetUDSServer();
    int32_t AddInputEventFilter(sptr<IEventFilter> filter);
protected:
    int32_t OnEventDeviceAdded(multimodal_libinput_event& event);
    int32_t OnEventDeviceRemoved(multimodal_libinput_event& event);
    int32_t OnEventKeyboard(multimodal_libinput_event& event);
    int32_t OnEventPointer(multimodal_libinput_event& event);
    int32_t OnEventTouch(multimodal_libinput_event& event);
    int32_t OnEventTouchSecond(libinput_event *event);
    int32_t OnEventTouchPadSecond(libinput_event *event);
    int32_t OnEventGesture(multimodal_libinput_event& event);
    int32_t OnEventTouchpad(multimodal_libinput_event& event);
    int32_t OnGestureEvent(libinput_event *event);
    int32_t OnEventTabletTool(multimodal_libinput_event& event);
    int32_t OnEventTabletPad(multimodal_libinput_event& event);
    int32_t OnEventSwitchToggle(multimodal_libinput_event& event);
    int32_t OnEventJoyStickKey(multimodal_libinput_event& event, const uint64_t time);
    int32_t OnEventTabletPadKey(multimodal_libinput_event& event);
    int32_t OnEventJoyStickAxis(multimodal_libinput_event& event, const uint64_t time);
    int32_t OnKeyboardEvent(libinput_event *event);
    int32_t OnEventKey(libinput_event *event);
    int32_t OnKeyEventDispatch(multimodal_libinput_event& event);
    
    int32_t OnMouseEventHandler(libinput_event *event, const int32_t deviceId);
    bool SendMsg(const int32_t fd, NetPacket& pkt) const;
    bool OnSystemEvent(const KeyEventValueTransformations& temp, const enum KEY_STATE state) const;

private:
    int32_t OnEventHandler(multimodal_libinput_event& ev);
    std::mutex mu_;
    UDSServer *udsServer_ = nullptr;
    WindowSwitch winSwitch_;
    EventDispatch eventDispatch_;
    EventPackage eventPackage_;
    KeyEventValueTransformation xkbKeyboardHandlerKey_;
    NotifyDeviceChange notifyDeviceChange_;
    std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent;

    uint64_t idSeed_ = 0;
    int32_t eventType_ = 0;
    uint64_t initSysClock_ = 0;
    uint64_t lastSysClock_ = 0;
};
}
}
#define InputHandler OHOS::MMI::InputEventHandler::GetInstance()
#endif
