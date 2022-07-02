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

#include "device_base.h"

using namespace OHOS::MMI;

namespace {
constexpr int32_t FIRST_FINGER = 1;
constexpr int32_t SECOND_FINGER = 2;
constexpr int32_t THIRD_FINGER = 3;
constexpr int32_t FOURTH_FINGER = 4;
constexpr int32_t FIFTH_FINGER = 5;
constexpr int32_t EV_ABS_MISC_DEFAULT_VALUE = 15;
} // namespace

void DeviceBase::SetTimeToLibinputEvent(InjectEvent& injectEvent)
{
    struct timeval tm;
    gettimeofday(&tm, 0);
    injectEvent.event.input_event_sec = tm.tv_sec;
    injectEvent.event.input_event_usec = tm.tv_usec;
}

void DeviceBase::SetSynConfigReport(InputEventArray& inputEventArray, int64_t blockTime)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_SYN;
    injectEvent.event.code = SYN_REPORT;
    injectEvent.event.value = SYN_CONFIG;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetKeyLongPressEvent(InputEventArray& inputEventArray, int64_t blockTime, int32_t code)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = static_cast<uint16_t>(code);
    injectEvent.event.value = LONG_PRESS;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetSynReport(InputEventArray& inputEventArray, int64_t blockTime)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_SYN;
    injectEvent.event.code = SYN_REPORT;
    injectEvent.event.value = 0;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetKeyPressEvent(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = code;
    injectEvent.event.value = 1;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetKeyReleaseEvent(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = code;
    injectEvent.event.value = 0;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMtSlot(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_SLOT;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetTrackingId(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_TRACKING_ID;
    static int32_t trackingId = 0;
    injectEvent.event.value = ((value == 0) ? trackingId++ : value);
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetPositionX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_POSITION_X;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetPositionY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_POSITION_Y;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMtTouchMajor(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_TOUCH_MAJOR;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMtTouchMinor(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_TOUCH_MINOR;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMtOrientation(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MT_ORIENTATION;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetBtnTouch(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = BTN_TOUCH;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_X;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_Y;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMtTouchFingerType(InputEventArray& inputEventArray, int64_t blockTime,
    int32_t value, int32_t status)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    if (value == FIRST_FINGER) {
        injectEvent.event.code = BTN_TOOL_FINGER;
    } else if (value == SECOND_FINGER) {
        injectEvent.event.code = BTN_TOOL_DOUBLETAP;
    } else if (value == THIRD_FINGER) {
        injectEvent.event.code = BTN_TOOL_TRIPLETAP;
    } else if (value == FOURTH_FINGER) {
        injectEvent.event.code = BTN_TOOL_QUADTAP;
    } else if (value == FIFTH_FINGER) {
        injectEvent.event.code = BTN_TOOL_QUINTTAP;
    } else {
        injectEvent.event.code = BTN_TOOL_FINGER;
    }
    injectEvent.event.value = status;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsZ(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_Z;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsRx(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_RX;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsRy(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_RY;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsHat0X(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_HAT0X;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsHat0Y(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_HAT0Y;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsRz(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_RZ;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbs(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = code;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetRelX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_REL;
    injectEvent.event.code = REL_X;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetRelY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_REL;
    injectEvent.event.code = REL_Y;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetRelWheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_REL;
    injectEvent.event.code = REL_WHEEL;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetRelHwheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_REL;
    injectEvent.event.code = REL_HWHEEL;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetEvAbsWheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_WHEEL;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetAbsMisc(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_MISC;
    if (value == 1) {
        injectEvent.event.value = EV_ABS_MISC_DEFAULT_VALUE;
    } else {
        injectEvent.event.value = 0;
    }
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetAbsTiltX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_TILT_X;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetAbsTiltY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_TILT_Y;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetAbsPressure(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_PRESSURE;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetAbsDistance(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_DISTANCE;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetBtnPen(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = BTN_TOOL_PEN;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetBtnStylus(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code,
    int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = code;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetBtnRubber(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_KEY;
    injectEvent.event.code = BTN_TOOL_RUBBER;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetMscSerial(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_MSC;
    injectEvent.event.code = MSC_SERIAL;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetSynMtReport(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_SYN;
    injectEvent.event.code = SYN_MT_REPORT;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}

void DeviceBase::SetThrottle(InputEventArray& inputEventArray, int64_t blockTime, int32_t value)
{
    InjectEvent injectEvent = {};
    injectEvent.blockTime = blockTime;
    injectEvent.event.type = EV_ABS;
    injectEvent.event.code = ABS_THROTTLE;
    injectEvent.event.value = value;
    SetTimeToLibinputEvent(injectEvent);
    inputEventArray.events.push_back(injectEvent);
}