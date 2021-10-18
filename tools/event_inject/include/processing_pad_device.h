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
#ifndef OHOS_PROCESSING_PAD_DEVICE_H
#define OHOS_PROCESSING_PAD_DEVICE_H

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
    namespace MMI {
        class ProcessingPadDevice : public DeviceBase {
            struct PadEvent {
                std::string eventType;
                int32_t keyValue;
                std::vector<int32_t> ringEvents;
            };
        public:
            ProcessingPadDevice() = default;
            ~ProcessingPadDevice() = default;
            int32_t TransformJsonDataToInputData(const Json& inputEventArrays, InputEventArray& inputEventArray);
        private:
            int32_t AnalysisPadEvent(const Json& inputData, std::vector<PadEvent>& padEventArray);
            void TransformPadEventToInputEvent(const std::vector<PadEvent>& padEventArray,
                                               InputEventArray& inputEventArray);
            void TransformKeyPressEvent(const PadEvent& padEvent, InputEventArray& inputEventArray);
            void TransformKeyReleaseEvent(const PadEvent& padEvent, InputEventArray& inputEventArray);
            void TransformKeyClickEvent(const PadEvent& padEvent, InputEventArray& inputEventArray);
            void TransformRingEvent(const PadEvent& padEvent, InputEventArray& inputEventArray);
        };
    }
}
#endif