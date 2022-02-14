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
#ifndef EVENT_DISPATCH_H
#define EVENT_DISPATCH_H
#include "uds_server.h"
#include "register_event.h"
#include "key_event.h"
#include "key_event_value_transformation.h"
#include "standard_event_handler.h"
#include "app_register.h"
#include "event_package.h"
#include "pointer_event.h"
#include "i_event_filter.h"

namespace OHOS {
namespace MMI {
class EventDispatch : public std::enable_shared_from_this<EventDispatch> {
public:
    EventDispatch();
    virtual ~EventDispatch();
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter);
    int32_t DispatchGestureNewEvent(UDSServer& udsServer, libinput_event *event,
        std::shared_ptr<PointerEvent> pointer, const uint64_t preHandlerTime);
    int32_t DispatchGestureEvent(UDSServer& udsServer, libinput_event *event, const EventGesture& gesture,
        const uint64_t preHandlerTime);
    int32_t DispatchKeyEvent(UDSServer& udsServer, libinput_event *event, const KeyEventValueTransformations& trs,
        EventKeyboard& key, const uint64_t preHandlerTime);
    int32_t DispatchKeyEventByPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key,
        const uint64_t preHandlerTime);
    int32_t DispatchTouchEvent(UDSServer& udsServer, libinput_event *event,
        const EventTouch& touch, const uint64_t preHandlerTime);
    int32_t DispatchTabletPadEvent(UDSServer& udsServer, libinput_event *event,
        const EventTabletPad& tabletPad, const uint64_t preHandlerTime);
    int32_t DispatchJoyStickEvent(UDSServer& udsServer, libinput_event *event,
        const EventJoyStickAxis& eventJoyStickAxis, const uint64_t preHandlerTime);
    int32_t DispatchCommonPointEvent(UDSServer& udsServer, libinput_event *event,
        const EventPointer& point, const uint64_t preHandlerTime);
    int32_t DispatchPointerEvent(UDSServer& udsServer, libinput_event *event,
        EventPointer& point, const uint64_t preHandlerTime);
    int32_t DispatchTabletToolEvent(UDSServer& udsServer, libinput_event *event,
        const EventTabletTool& tableTool, const uint64_t preHandlerTime);
    int32_t DispatchTouchTransformPointEvent(UDSServer& udsServer, std::shared_ptr<PointerEvent> point);
    int32_t HandlePointerEvent(std::shared_ptr<PointerEvent> point);
    void OnKeyboardEventTrace(const std::shared_ptr<KeyEvent> &key, int32_t number);

protected:
    bool HandlePointerEventFilter(std::shared_ptr<PointerEvent> point);
    void OnEventTouchGetPointEventType(const EventTouch& touch, const int32_t fingerCount,
        POINT_EVENT_TYPE& pointEventType);
    int32_t GestureRegisteredEventDispatch(const MmiMessageId& idMsg, UDSServer& udsServer,
        RegisteredEvent& registeredEvent, uint64_t preHandlerTime);
    int32_t DispatchRegEvent(const MmiMessageId& idMsg, UDSServer& udsServer,
        const RegisteredEvent& data, int32_t inputDeviceType, uint64_t preHandlerTime);
    int32_t KeyBoardRegEveHandler(const EventKeyboard& key, UDSServer& udsServer,
        libinput_event *event, int32_t inputDeviceType, uint64_t preHandlerTime);

protected:
    int32_t touchDownFocusSurfaceId_ = 0;
    EventPackage eventPackage_;
    StandardEventHandler standardEvent_;
#ifdef DEBUG_CODE_TEST
private:
    const size_t windowCount_ = 2;
#endif
    };
} // namespace MMI
} // namespace OHOS
#endif // EVENT_DISPATCH_H