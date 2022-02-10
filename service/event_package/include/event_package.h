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
#include "pointer_event.h"
#include "key_event.h"
#include "input_windows_manager.h"
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
        int32_t PackageEventDeviceInfo(libinput_event *event, EventType& data);
        template<class T>
        int32_t PackageRegisteredEvent(const T& data, RegisteredEvent& event);
        int32_t PackageTabletToolEvent(libinput_event *event, EventTabletTool& tableTool);
        int32_t PackageTabletPadEvent(libinput_event *event, EventTabletPad& tabletPad);
        int32_t PackageDeviceManageEvent(libinput_event *event, DeviceManage& deviceManage);
        int32_t PackageKeyEvent(libinput_event *event, EventKeyboard& key);
        int32_t PackageKeyEvent(libinput_event *event, std::shared_ptr<KeyEvent> kevnPtr);
        int32_t PackageGestureEvent(libinput_event *event, EventGesture& gesture);
        int32_t PackagePointerEvent(libinput_event *event, EventPointer& point);
        int32_t PackageTouchEvent(libinput_event *event, EventTouch& touch);
        int32_t PackageJoyStickAxisEvent(libinput_event *event, EventJoyStickAxis& eventJoyStickAxis);
        int32_t PackageJoyStickKeyEvent(libinput_event *event, EventKeyboard& key);
        int32_t PackageTabletPadKeyEvent(libinput_event *event, EventKeyboard& key);
        static int32_t PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key);
        static int32_t KeyboardToKeyEvent(const EventKeyboard& key, std::shared_ptr<KeyEvent> keyEventPtr);
    private:
        void PackageTabletPadOtherParams(libinput_event *event, EventTabletPad& tabletPad);
        int32_t PackageTabletToolOtherParams(libinput_event *event, EventTabletTool& tableTool);
        void PackageTabletToolTypeParam(libinput_event *event, EventTabletTool& tableTool);
        int32_t PackagePointerEventByMotion(libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventByMotionAbs(libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventByButton(libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventByAxis(libinput_event *event, EventPointer& point);
        void PackageTouchEventByType(int32_t type, libinput_event_touch *data, EventTouch& touch);
    };
    template<class T>
    int32_t EventPackage::PackageRegisteredEvent(const T& data, RegisteredEvent& event)
    {
        int32_t ret = memcpy_s(event.physical, MAX_DEVICENAME, data.physical, MAX_DEVICENAME);
        CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
        const std::string uid = GetUUid();
        ret = memcpy_s(event.uuid, MAX_UUIDSIZE, uid.c_str(), uid.size());
        CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
        event.deviceId = data.deviceId;
        event.eventType = data.eventType;
        event.deviceType = data.deviceType;
        event.occurredTime = data.time;
        return RET_OK;
    }
}
#endif