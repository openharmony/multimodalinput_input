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

#ifndef PROCESSING_KEYBOARD_DEVICE_H
#define PROCESSING_KEYBOARD_DEVICE_H

#include "device_base.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class ProcessingKeyboardDevice : public DeviceBase {
    struct KeyBoardEvent {
        std::string eventType;
        int32_t keyValue { 0 };
        int64_t blockTime { 0 };
    };
public:
    ProcessingKeyboardDevice() = default;
    DISALLOW_COPY_AND_MOVE(ProcessingKeyboardDevice);
    ~ProcessingKeyboardDevice() = default;
    int32_t TransformJsonDataToInputData(const DeviceItem& inputEventArrays, InputEventArray& inputEventArray);
private:
    int32_t AnalysisKeyBoardEvent(const std::vector<DeviceEvent>& inputData, std::vector<KeyBoardEvent>& keyBoardEvent);
    void TransformKeyBoardEventToInputEvent(const std::vector<KeyBoardEvent>& keyBoardEventArray,
        InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyLongPressEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_KEYBOARD_DEVICE_H