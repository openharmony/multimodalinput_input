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
#ifndef EVENT_DISPATCH_H
#define EVENT_DISPATCH_H
#include "uds_server.h"
#include "key_event.h"
#include "key_event_value_transformation.h"
#include "event_package.h"
#include "nocopyable.h"
#include "pointer_event.h"
#include "i_event_filter.h"

namespace OHOS {
namespace MMI {
class EventDispatch : public std::enable_shared_from_this<EventDispatch> {
public:
    EventDispatch();
    DISALLOW_COPY_AND_MOVE(EventDispatch);
    virtual ~EventDispatch();
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter);
    int32_t DispatchGestureNewEvent(UDSServer& udsServer, struct libinput_event *event,
        std::shared_ptr<PointerEvent> pointer, const int64_t preHandlerTime);
    int32_t DispatchGestureEvent(UDSServer& udsServer, struct libinput_event *event, const EventGesture& gesture,
        const int64_t preHandlerTime);
    int32_t DispatchKeyEvent(UDSServer& udsServer, struct libinput_event *event,
        const KeyEventValueTransformations& trs, EventKeyboard& key, const int64_t preHandlerTime);
    int32_t DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key,
        const int64_t preHandlerTime);
    int32_t DispatchTouchEvent(UDSServer& udsServer, struct libinput_event *event,
        const EventTouch& touch, const int64_t preHandlerTime);
    int32_t DispatchTabletPadEvent(UDSServer& udsServer, struct libinput_event *event,
        const EventTabletPad& tabletPad, const int64_t preHandlerTime);
    int32_t DispatchJoyStickEvent(UDSServer& udsServer, struct libinput_event *event,
        const EventJoyStickAxis& eventJoyStickAxis, const int64_t preHandlerTime);
    int32_t DispatchCommonPointEvent(UDSServer& udsServer, struct libinput_event *event,
        const EventPointer& point, const int64_t preHandlerTime);
    int32_t DispatchPointerEvent(UDSServer& udsServer, struct libinput_event *event,
        EventPointer& point, const int64_t preHandlerTime);
    int32_t DispatchTabletToolEvent(UDSServer& udsServer, struct libinput_event *event,
        const EventTabletTool& tableTool, const int64_t preHandlerTime);
    int32_t HandlePointerEvent(std::shared_ptr<PointerEvent> point);

protected:
    bool HandlePointerEventFilter(std::shared_ptr<PointerEvent> point);
    void OnEventTouchGetPointEventType(const EventTouch& touch, const int32_t fingerCount,
        POINT_EVENT_TYPE& pointEventType);
    int32_t GestureRegisteredEventDispatch(const MmiMessageId& idMsg, UDSServer& udsServer,
        RegisteredEvent& registeredEvent, int64_t preHandlerTime);
    int32_t KeyBoardRegEveHandler(const EventKeyboard& key, UDSServer& udsServer,
        struct libinput_event *event, int32_t inputDeviceType, int64_t preHandlerTime);
    bool IsANRProcess(int64_t time, SessionPtr ss);

private:
    int32_t DispatchTouchEvent(const EventTouch& touch, const int fd,
        const int64_t preHandlerTime, UDSServer& udsServer, NetPacket &pkt) const;

private:
    EventPackage eventPackage_;
    /*
     * Differentiated event handling
     */
    enum IsEventHandler {
        KEY_FILTER_EVENT = 1,
        KEY_CHECKLAUNABILITY_EVENT = 2,
        KEY_SUBSCRIBE_EVENT = 3,
        KEY_DISPATCH_EVENT = 4
    };
    void OnKeyboardEventTrace(const std::shared_ptr<KeyEvent> &key, IsEventHandler isEventHandler);
    void HandlePointerEventTrace(const std::shared_ptr<PointerEvent> &point);
    };
} // namespace MMI
} // namespace OHOS
#endif // EVENT_DISPATCH_H