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
#ifndef OHOS_EVENT_DISPATCH_H
#define OHOS_EVENT_DISPATCH_H
#include "uds_server.h"
#include "register_event.h"
#include "key_event.h"
#include "key_event_value_transformation.h"
#include "standard_event_handler.h"
#include "app_register.h"
#include "event_package.h"
#include "pointer_event.h"
#include "i_event_filter.h"

namespace OHOS::MMI {
class EventDispatch : public std::enable_shared_from_this<EventDispatch> {
public:
    EventDispatch();
    virtual ~EventDispatch();
    virtual int32_t SetInputEventFilter(sptr<IEventFilter> filter);
    int32_t DispatchGestureNewEvent(UDSServer& udsServer, libinput_event& event,
        std::shared_ptr<PointerEvent> pointer, const uint64_t preHandlerTime);
    int32_t DispatchGestureEvent(UDSServer& udsServer, libinput_event& event, EventGesture& gesture,
        const uint64_t preHandlerTime);
    int32_t DispatchKeyEvent(UDSServer& udsServer, libinput_event& event, const KeyEventValueTransformations& trs,
        EventKeyboard& key, const uint64_t preHandlerTime);
    int32_t DispatchKeyEventByPid(UDSServer& udsServer, std::shared_ptr<OHOS::MMI::KeyEvent> key,
        const uint64_t preHandlerTime);
    int32_t DispatchTouchEvent(UDSServer& udsServer, libinput_event& event,
        EventTouch& touch, const uint64_t preHandlerTime, WindowSwitch& windowSwitch);
    int32_t DispatchTabletPadEvent(UDSServer& udsServer, libinput_event& event,
        EventTabletPad& tabletPad, const uint64_t preHandlerTime);
    int32_t DispatchJoyStickEvent(UDSServer& udsServer, libinput_event& event,
        EventJoyStickAxis& eventJoyStickAxis, const uint64_t preHandlerTime);
    int32_t DispatchCommonPointEvent(UDSServer& udsServer, libinput_event& event,
        EventPointer& point, const uint64_t preHandlerTime);
    int32_t DispatchPointerEvent(UDSServer& udsServer, libinput_event& event,
        EventPointer& point, const uint64_t preHandlerTime, WindowSwitch& windowSwitch);
    int32_t DispatchTabletToolEvent(UDSServer& udsServer, libinput_event& event,
        EventTabletTool& tableTool, const uint64_t preHandlerTime, WindowSwitch& windowSwitch);
    int32_t DispatchTouchTransformPointEvent(UDSServer& udsServer, std::shared_ptr<PointerEvent> point);
    int32_t handlePointerEvent(std::shared_ptr<PointerEvent> point);
    bool HandleTouchScreenEvent(std::shared_ptr<PointerEvent> point);
    bool HandleMouseEvent(std::shared_ptr<PointerEvent> point);
    bool HandleTouchPadEvent(std::shared_ptr<PointerEvent> point);
#ifdef OHOS_AUTO_TEST_FRAME
    int32_t SendLibPktToAutoTest(UDSServer& udsServer, const AutoTestLibinputPkt& autoTestLibinputPkt);
    int32_t SendMappingPktToAutoTest(UDSServer& udsServer, int32_t sourceType);
    int32_t SendKeyTypePktToAutoTest(UDSServer& udsServer, const AutoTestKeyTypePkt& autoTestKeyTypePkt);
    int32_t SendDispatcherPktToAutoTest(UDSServer& udsServer, const AutoTestDispatcherPkt& autoTestDispatcherPkt) const;
    void AutoTestSetStandardValue(EventJoyStickAxis& eventJoyStickAxis);
#endif  // OHOS_AUTO_TEST_FRAME

protected:
    bool HandlePointerEventFilter(std::shared_ptr<PointerEvent> point);
    void OnEventTouchGetPointEventType(const EventTouch& touch, POINT_EVENT_TYPE& pointEventType,
        const int32_t fingerCount);
    int32_t GestureRegisteredEventDispatch(const MmiMessageId& idMsg, OHOS::MMI::UDSServer& udsServer,
        RegisteredEvent& registeredEvent, uint64_t preHandlerTime);
    int32_t RegisteredEventDispatch(const MmiMessageId& idMsg, UDSServer& udsServer,
        RegisteredEvent& eventData, int32_t inputDeviceType, uint64_t preHandlerTime);
    int32_t KeyBoardRegisteredEventHandler(EventKeyboard& key, UDSServer& udsServer,
        libinput_event& event, int32_t inputDeviceType, uint64_t preHandlerTime);
#ifdef OHOS_AUTO_TEST_FRAME
        int32_t SendStandardPktToAutoTest(UDSServer& udsServer, const AutoTestStandardPkt& autoTestStandardPkt);
        int32_t SendManagePktToAutoTest(UDSServer& udsServer, const OHOS::MMI::AppInfo& appInfo,
            const int32_t focusId, const std::vector<int32_t>& fds, AutoTestCoordinate coordinate) const;
#endif  // OHOS_AUTO_TEST_FRAME

protected:
    int32_t touchDownFocusSurfaceId_ = 0;
    EventPackage eventPackage_;
    StandardEventHandler standardEvent_;
    std::mutex lockInputEventFilter_;
    sptr<IEventFilter> filter_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> eventFilterRecipient_ {nullptr};
#ifdef DEBUG_CODE_TEST
private:
    const size_t windowCount_ = 2;
#endif
    };
}
#endif
