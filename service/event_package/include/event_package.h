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
#ifndef EVENT_PACKAGE_H
#define EVENT_PACKAGE_H
#include "pointer_event.h"
#include "key_event.h"
#include "input_windows_manager.h"
#include "nocopyable.h"
#include "uds_server.h"
#include "util.h"
#define KEYSTATUS 0

namespace OHOS {
namespace MMI {
    class EventPackage {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventPackage" };
        static constexpr uint32_t TabletPadButtonNumberPrefix = 0x100;
    public:
        EventPackage();
        DISALLOW_COPY_AND_MOVE(EventPackage);
        virtual ~EventPackage();
        template<class EventType>
        int32_t PackageEventDeviceInfo(struct libinput_event *event, EventType& data);
        template<class T>
        int32_t PackageRegisteredEvent(const T& data, RegisteredEvent& event);
        int32_t PackageTabletToolEvent(struct libinput_event *event, EventTabletTool& tableTool);
        int32_t PackageTabletPadEvent(struct libinput_event *event, EventTabletPad& tabletPad);
        int32_t PackageDeviceManageEvent(struct libinput_event *event, DeviceManage& deviceManage);
        int32_t PackageKeyEvent(struct libinput_event *event, EventKeyboard& key);
        int32_t PackageKeyEvent(struct libinput_event *event, std::shared_ptr<KeyEvent> kevnPtr);
        int32_t PackageGestureEvent(struct libinput_event *event, EventGesture& gesture);
        int32_t PackagePointerEvent(struct libinput_event *event, EventPointer& point);
        int32_t PackageTouchEvent(struct libinput_event *event, EventTouch& touch);
        int32_t PackageJoyStickAxisEvent(struct libinput_event *event, EventJoyStickAxis& eventJoyStickAxis);
        int32_t PackageJoyStickKeyEvent(struct libinput_event *event, EventKeyboard& key);
        int32_t PackageTabletPadKeyEvent(struct libinput_event *event, EventKeyboard& key);
        static int32_t PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key);
        static int32_t KeyboardToKeyEvent(const EventKeyboard& key, std::shared_ptr<KeyEvent> keyEventPtr);
    private:
        void PackageTabletPadOtherParams(struct libinput_event *event, EventTabletPad& tabletPad);
        int32_t PackageTabletToolOtherParams(struct libinput_event *event, EventTabletTool& tableTool);
        void PackageTabletToolTypeParam(struct libinput_event *event, EventTabletTool& tableTool);
        int32_t PackagePointerEventMotion(struct libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventMotionAbs(struct libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventButton(struct libinput_event *event, EventPointer& point);
        int32_t PackagePointerEventAxis(struct libinput_event *event, EventPointer& point);
        void PackageTouchEventType(int32_t type, struct libinput_event_touch *data, EventTouch& touch);
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
} // namespace MMI
} // namespace OHOS
#endif // EVENT_PACKAGE_H