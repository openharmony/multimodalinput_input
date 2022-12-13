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

#ifndef DEVICE_BASE_H
#define DEVICE_BASE_H

#include "nocopyable.h"

#include "msg_head.h"

namespace OHOS {
namespace MMI {
class DeviceBase {
public:
    DeviceBase() = default;
    DISALLOW_COPY_AND_MOVE(DeviceBase);
    virtual ~DeviceBase() = default;
    virtual int32_t TransformJsonDataToInputData(const DeviceItem& inputEventArrays,
                                                 InputEventArray& inputEventArray) = 0;
    void SetTimeToLibinputEvent(InjectEvent& injectEvent);
    void SetSynReport(InputEventArray& inputEventArray, int64_t blockTime = 0);
    void SetSynConfigReport(InputEventArray& inputEventArray, int64_t blockTime);
    void SetKeyPressEvent(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code);
    void SetKeyLongPressEvent(InputEventArray& inputEventArray, int64_t blockTime, int32_t code);
    void SetKeyReleaseEvent(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code);
    void SetMtSlot(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetTrackingId(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetPositionX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetPositionY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetMtTouchMajor(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetMtTouchMinor(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetMtOrientation(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetBtnTouch(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetEvAbsX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetEvAbsY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetEvAbsZ(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetMtTouchFingerType(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0,
                              int32_t status = 1);
    void SetEvAbsRx(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetEvAbsRy(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetEvAbsRz(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetEvAbsHat0X(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetEvAbsHat0Y(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetEvAbs(InputEventArray& inputEventArray, int64_t blockTime, uint16_t code, int32_t value);
    void SetRelX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetRelY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetRelWheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetRelHwheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetEvAbsWheel(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetAbsMisc(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetAbsTiltX(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetAbsTiltY(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetAbsPressure(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetAbsDistance(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetBtnPen(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetBtnStylus(InputEventArray& inputEventArray, int64_t blockTime,
                      uint16_t code = BTN_STYLUS_DEFAULT_CODE, int32_t value = 0);
    void SetBtnRubber(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
    void SetMscSerial(InputEventArray& inputEventArray, int64_t blockTime,
                      int32_t value = BTN_MSC_SERIAL_DEFAULT_VALUE);
    void SetThrottle(InputEventArray& inputEventArray, int64_t blockTime, int32_t value);
    void SetSynMtReport(InputEventArray& inputEventArray, int64_t blockTime, int32_t value = 0);
private:
    static constexpr int32_t BTN_STYLUS_DEFAULT_CODE { 331 };
    static constexpr int32_t BTN_MSC_SERIAL_DEFAULT_VALUE { 0xA806D21 };
};
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_BASE_H