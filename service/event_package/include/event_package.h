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
#ifndef OHOS_EVENT_PACKAGE_H
#define OHOS_EVENT_PACKAGE_H
#include "mouse_state_gesture.h"
#include "pointer_event.h"
#include "key_event.h"
#include "window_switch.h"
#include "uds_server.h"
#include "util.h"

namespace OHOS::MMI {
    class EventPackage {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventPackage" };
        static constexpr uint32_t TabletPadButtonNumberPrefix = 0x100;
    public:
        EventPackage();
        virtual ~EventPackage();
        template<class EventType>
        int32_t PackageEventDeviceInfo(libinput_event& event, EventType& eventData, UDSServer& udsServer);
        template<class T>
        int32_t PackageRegisteredEvent(RegisteredEvent& registeredEvent, T& eventData);
        int32_t PackageTabletToolEvent(libinput_event& event, EventTabletTool& tableTool, UDSServer& udsServer);
        int32_t PackageTabletPadEvent(libinput_event& event, EventTabletPad& tabletPad, UDSServer& udsServer);
        int32_t PackageDeviceManageEvent(libinput_event& event, DeviceManage& deviceManage, UDSServer& udsServer);
        int32_t PackageKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer);
        int32_t PackageGestureEvent(libinput_event& event, EventGesture& gesture, UDSServer& udsServer);
        int32_t PackagePointerEvent(libinput_event& event, EventPointer& point,
            WindowSwitch& windowSwitch, UDSServer& udsServer);
        int32_t PackageTouchEvent(libinput_event& event, EventTouch& touch, WindowSwitch& windowSwitch,
            UDSServer& udsServer);
        int32_t PackageJoyStickAxisEvent(libinput_event& event, EventJoyStickAxis& eventJoyStickAxis,
            UDSServer& udsServer);
        int32_t PackageJoyStickKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer);
        int32_t PackageTabletPadKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer);
        static int32_t PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key, UDSServer& udsServer);
        static int32_t KeyboardToKeyEvent(EventKeyboard& key, std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr,
            UDSServer& udsServer);
        static std::shared_ptr<OHOS::MMI::PointerEvent> GestureToPointerEvent(EventGesture& gesture,
           UDSServer& udsServer);
    private:
        uint32_t SEAT_BUTTON_OR_KEY_COUNT_ONE = 1;
        uint32_t SEAT_BUTTON_OR_KEY_COUNT_ZERO = 0;
        void PackageTabletPadOtherParams(libinput_event& event, EventTabletPad& tabletPad);
        int32_t PackageTabletToolOtherParams(libinput_event& event, EventTabletTool& tableTool);
        void PackageTabletToolTypeParam(libinput_event& event, EventTabletTool& tableTool);
        void PackagePointerEventByMotion(libinput_event& event, EventPointer& point, WindowSwitch& windowSwitch);
        void PackagePointerEventByMotionAbs(libinput_event& event, EventPointer& point, WindowSwitch& windowSwitch);
        int32_t PackagePointerEventByButton(libinput_event& event, EventPointer& point, WindowSwitch& windowSwitch);
        void PackagePointerEventByAxis(libinput_event& event, EventPointer& point, WindowSwitch& windowSwitch);
    };
    template<class T>
    int32_t EventPackage::PackageRegisteredEvent(RegisteredEvent& registeredEvent, T& eventData)
    {
        const std::string uid = GetUUid();
        CHKR(EOK == memcpy_s(registeredEvent.devicePhys, MAX_DEVICENAME, eventData.devicePhys, MAX_DEVICENAME),
             MEMCPY_SEC_FUN_FAIL, RET_ERR);
        CHKR(EOK == memcpy_s(registeredEvent.uuid, MAX_UUIDSIZE, uid.c_str(), uid.size()),
             MEMCPY_SEC_FUN_FAIL, RET_ERR);
        registeredEvent.deviceId = eventData.deviceId;
        registeredEvent.eventType = eventData.eventType;
        registeredEvent.deviceType = eventData.deviceType;
        registeredEvent.occurredTime = eventData.time;
        return RET_OK;
    }
}
#endif