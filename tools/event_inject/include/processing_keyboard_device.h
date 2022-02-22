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

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingKeyboardDevice : public DeviceBase {
    struct KeyBoardEvent {
        std::string eventType;
        int32_t keyValue;
        int32_t blockTime;
    };
public:
    ProcessingKeyboardDevice() = default;
    ~ProcessingKeyboardDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& inputEventArrays, InputEventArray& inputEventArray);
private:
    int32_t AnalysisKeyBoardEvent(const Json& inputData, std::vector<KeyBoardEvent>& keyBoardEvent);
    void TransformKeyBoardEventToInputEvent(const std::vector<KeyBoardEvent>& keyBoardEventArray,
                                            InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyLongPressEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const KeyBoardEvent& keyBoardEvent, InputEventArray& inputEventArray);
private:
    static constexpr int32_t EV_ABS_MISC_DEFAULT_VALUE = 15;
    static constexpr int32_t EVENT_REPROT_COUNTS = 50;
    static constexpr int32_t EVENT_REPROT_TIMES = 20;
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_KEYBOARD_DEVICE_H