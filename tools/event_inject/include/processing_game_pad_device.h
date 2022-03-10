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
#ifndef PROCESSING_GAME_PAD_DEVICE_H
#define PROCESSING_GAME_PAD_DEVICE_H

#include "msg_head.h"
#include "device_base.h"

namespace OHOS {
namespace MMI {
class ProcessingGamePadDevice : public DeviceBase {
    struct GamePadEvent {
        std::string eventType;
        std::string direction;
        int32_t keyValue;
        int32_t blockTime;
        std::vector<uint32_t> gameEvents;
    };
public:
    ProcessingGamePadDevice() = default;
    ~ProcessingGamePadDevice() = default;
    int32_t TransformJsonDataToInputData(const Json& originalEvent, InputEventArray& inputEventArray);
private:
    int32_t AnalysisGamePadEvent(const Json& inputData, std::vector<GamePadEvent>& padEventArray);
    void TransformPadEventToInputEvent(const std::vector<GamePadEvent>& padEventArray,
                                       InputEventArray& inputEventArray);
    void TransformKeyPressEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
    void TransformKeyReleaseEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
    void TransformKeyClickEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
    void TransformRocker1Event(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
    void TransformRocker2Event(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
    void TransformDerectionKeyEvent(const GamePadEvent& padEvent, InputEventArray& inputEventArray);
};
} // namespace MMI
} // namespace OHOS
#endif // PROCESSING_GAME_PAD_DEVICE_H