/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INPUT_MANAGER_COMMAND_H
#define INPUT_MANAGER_COMMAND_H

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class InputManagerCommand {
public:
    InputManagerCommand() = default;
    DISALLOW_COPY_AND_MOVE(InputManagerCommand);
    int32_t ParseCommand(int32_t argc, char *argv[]);
    int32_t ConnectService();
    void ShowUsage();
private:
    void InitializeMouseDeathStub();
    void SleepAndUpdateTime(int64_t &currentTimeMs);
    void PrintMouseUsage();
    void PrintKeyboardUsage();
    void PrintStylusUsage();
    void PrintTouchUsage();
    void PrintKnuckleUsage();
    void PrintTouchPadUsage();
    void PrintEnableKeyStatusRecordUsage();
    bool IsCoordinateInvalid(int32_t firstDownX, int32_t firstDownY, int32_t secondDownX, int32_t secondDownY);
    int32_t SingleKnuckleClickEvent(int32_t downX, int32_t downY);
    int32_t DoubleKnuckleClickEvent(int32_t downX, int32_t downY);
    int32_t KnuckleGestureInputProcess(int32_t argc, char *argv[], int32_t c, int32_t optionIndex);
    int32_t SingleKnuckleGestureProcesser(int32_t argc, char *argv[]);
    int32_t DoubleKnuckleGestureProcesser(int32_t argc, char *argv[]);
    int32_t NextPos(int64_t begTimeMs, int64_t curtTimeMs, int32_t totalTimeMs, int32_t begPos, int32_t endPos);
    int32_t ProcessTouchPadGestureInput(int32_t argc, char *argv[], int32_t optionIndex);
    int32_t ProcessPinchGesture(int32_t argc, char *argv[]);
    int32_t InjectPinchEvent(int32_t fingerCount, int32_t scaleNumberator);
    int32_t ProcessRotateGesture(int32_t argc, char *argv[]);
    int32_t ProcessKeyboardTextInput(char *optarg, int32_t count);
    int32_t PrintKeyboardTextChar(int32_t keyCode, bool isPressShift);
    bool IsSpecialChar(char character, int32_t &keyCode, bool &isPressShift);
    int32_t ProcessTouchPadFingerSwipe(int32_t argc, char *argv[]);
    int32_t SwipeActionEvent(int32_t startX, int32_t startY, int32_t endX, int32_t endY);
    void SendTouchDownForPinch(int32_t topX, int32_t topY, int32_t bottomX, int32_t bottomY);
    std::shared_ptr<PointerEvent> CreateEvent(int32_t id, int32_t type, int32_t pId, int32_t srcType, int32_t finCount);
    void FillPointerItem(PointerEvent::PointerItem &itemFirst, int32_t pointX, int32_t pointY, int32_t id, bool press);
    int32_t ActionPinchEvent(int32_t centerX, int32_t centerY, int32_t scalePercentNumerator);
    uint32_t KeyCodeToUnicode(int32_t keyCode);
    std::atomic_bool isFoldPC_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_COMMAND_H
