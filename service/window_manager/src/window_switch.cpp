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
#include "window_switch.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "WindowSwitch" };
    }
}

OHOS::MMI::WindowSwitch::WindowSwitch()
{
    const int32_t SIZE_INIT = 3;
    pointer_ = {};
    eventPointer_ = {};
    size_ = SIZE_INIT;
    windowId_ = 0;
}

OHOS::MMI::WindowSwitch::~WindowSwitch()
{
}

void OHOS::MMI::WindowSwitch::SetCommonPointer(const EventPointer& point)
{
    eventPointer_.absolute.x = point.absolute.x;
    eventPointer_.absolute.y = point.absolute.y;
    eventPointer_.delta.x = point.delta.x;
    eventPointer_.delta.y = point.delta.y;
    eventPointer_.delta_raw.x = point.delta_raw.x;
    eventPointer_.delta_raw.y = point.delta_raw.y;
    eventPointer_.button = point.button;
    eventPointer_.seat_button_count = point.seat_button_count;
    eventPointer_.state = point.state;
    eventPointer_.deviceType = point.deviceType;
    eventPointer_.eventType = point.eventType;
    eventPointer_.deviceId = point.deviceId;
    CHK(EOK == memcpy_s(eventPointer_.deviceName, sizeof(eventPointer_.deviceName), point.deviceName,
                        sizeof(point.deviceName)), MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(eventPointer_.devicePhys, sizeof(eventPointer_.devicePhys), point.devicePhys,
                        sizeof(point.devicePhys)), MEMCPY_SEC_FUN_FAIL);
}

void OHOS::MMI::WindowSwitch::SetPointerByButton(const EventPointer& point)
{
    SetCommonPointer(point);
}

void OHOS::MMI::WindowSwitch::SetPointerByMotion(const EventPointer& point)
{
    SetCommonPointer(point);
    pointer_.absolute.x += point.delta_raw.x;
    if (pointer_.absolute.x >= DEF_SCREEN_MAX_WIDTH) {
        pointer_.absolute.x = DEF_SCREEN_MAX_WIDTH;
    }
    if (pointer_.absolute.x < 0) {
        pointer_.absolute.x = 0;
    }
    pointer_.absolute.y += point.delta_raw.y;
    if (pointer_.absolute.y >= DEF_SCREEN_MAX_HEIGHT) {
        pointer_.absolute.y = DEF_SCREEN_MAX_HEIGHT;
    }
    if (pointer_.absolute.y < 0) {
        pointer_.absolute.y = 0;
    }
}

void OHOS::MMI::WindowSwitch::SetPointerByAbsMotion(const EventPointer& point)
{
    SetCommonPointer(point);
    pointer_.absolute.x = point.absolute.x;
    pointer_.absolute.y = point.absolute.y;
}

void OHOS::MMI::WindowSwitch::SetPointerByTouch(const EventTouch& touch)
{
    pointer_.absolute.x = touch.point.x;
    pointer_.absolute.y = touch.point.y;
}

void OHOS::MMI::WindowSwitch::SetSize(size_t size)
{
    size_ = size;
}

size_t OHOS::MMI::WindowSwitch::GetSize()
{
    return size_;
}

void OHOS::MMI::WindowSwitch::SetSurfaceId(size_t windowId)
{
    windowId_ = windowId;
}

const EventPointer& OHOS::MMI::WindowSwitch::GetEventPointer()
{
    return eventPointer_;
}

const Pointer& OHOS::MMI::WindowSwitch::GetPointer()
{
    return pointer_;
}
