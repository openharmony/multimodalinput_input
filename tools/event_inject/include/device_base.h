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
#ifndef DEVICE_BASE_H
#define DEVICE_BASE_H

#include "msg_head.h"

namespace OHOS {
    namespace MMI {
        class DeviceBase {
        public:
            DeviceBase() = default;
            virtual ~DeviceBase() = default;
            virtual int32_t TransformJsonDataToInputData(const Json& inputEventArrays,
                                                         InputEventArray& inputEventArray) = 0;
            void SetTimeToLibinputEvent(InjectEvent& injectEvent);
            void SetSynReport(InputEventArray& inputEventArray, int32_t blockTime = 0);
            void SetSynConfigReport(InputEventArray& inputEventArray, int32_t blockTime);
            void SetKeyPressEvent(InputEventArray& inputEventArray, int32_t blockTime, uint16_t code);
            void SetKeyLongPressEvent(InputEventArray& inputEventArray, int32_t blockTime, int32_t code);
            void SetKeyReleaseEvent(InputEventArray& inputEventArray, int32_t blockTime, uint16_t code);
            void SetMtSlot(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetTrackingId(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetPositionX(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetPositionY(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetMtTouchMajor(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetMtTouchMinor(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetMtOrientation(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetBtnTouch(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetEvAbsX(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetEvAbsY(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetEvAbsZ(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetMtTouchFingerType(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0,
                int32_t status = 1);
            void SetEvAbsRx(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetEvAbsRy(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetEvAbsRz(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetEvAbsHat0X(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetEvAbsHat0Y(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetEvAbs(InputEventArray& inputEventArray, int32_t blockTime, uint16_t code, int32_t value);
            void SetRelX(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetRelY(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetRelWheel(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetRelHwheel(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetEvAbsWheel(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetAbsMisc(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetAbsTiltX(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetAbsTiltY(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetAbsPressure(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetAbsDistance(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetBtnPen(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetBtnStylus(InputEventArray& inputEventArray, int32_t blockTime,
                              uint16_t code = BTN_STYLUS_DEFAULT_CODE, int32_t value = 0);
            void SetBtnRubber(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
            void SetMscSerial(InputEventArray& inputEventArray, int32_t blockTime,
                              int32_t value = BTN_MSC_SERIAL_DEFAULT_VALUE);
            void SetThrottle(InputEventArray& inputEventArray, int32_t blockTime, int32_t value);
            void SetSynMtReport(InputEventArray& inputEventArray, int32_t blockTime, int32_t value = 0);
        private:
            static constexpr int32_t FIRST_FINGER = 1;
            static constexpr int32_t SECOND_FINGER = 2;
            static constexpr int32_t THIRD_FINGER = 3;
            static constexpr int32_t FOURTH_FINGER = 4;
            static constexpr int32_t FITTH_FINGER = 5;
            static constexpr int32_t BTN_STYLUS_DEFAULT_CODE = 331;
            static constexpr int32_t EV_ABS_MISC_DEFAULT_VALUE = 15;
            static constexpr int32_t BTN_MSC_SERIAL_DEFAULT_VALUE = 0xA806D21;
        };
    }
}
#endif // DEVICE_BASE_H