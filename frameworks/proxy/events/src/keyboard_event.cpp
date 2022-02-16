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

#include "keyboard_event.h"

namespace OHOS {
KeyBoardEvent::~KeyBoardEvent() {};
void KeyBoardEvent::Initialize(int32_t windowId, bool handledByIme, int32_t unicode,
                               bool isSingleNonCharacter, bool isTwoNonCharacters,
                               bool isThreeNonCharacters, bool isPressed, int32_t keyCode,
                               int32_t keyDownDuration, int32_t highLevelEvent,
                               const std::string& uuid, int32_t sourceType,
                               uint64_t occurredTime, const std::string& deviceId,
                               int32_t inputDeviceId, bool isHighLevelEvent,
                               uint16_t deviceUdevTags, int32_t deviceEventType,
                               bool isIntercepted)
{
    KeyEvent::Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent,
                         uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                         isHighLevelEvent, deviceUdevTags, deviceEventType, isIntercepted);
    mHandledByIme_ = handledByIme;
    mUnicode_ = unicode;
}

void KeyBoardEvent::Initialize(KeyBoardEvent& keyBoardEvent)
{
    KeyEvent::Initialize(keyBoardEvent);
    mHandledByIme_ = keyBoardEvent.IsHandledByIme();
    mUnicode_ = keyBoardEvent.GetUnicode();
}

void KeyBoardEvent::EnableIme()
{
    mHandledByIme_ = true;
}

void KeyBoardEvent::DisableIme()
{
    mHandledByIme_ = false;
}

bool KeyBoardEvent::IsHandledByIme()
{
    return mHandledByIme_;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int32_t keycodeOne)
{
    return false;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int32_t keycodeOne, int32_t keycodeTwo)
{
    return false;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int32_t keycodeOne, int32_t keycodeTwo, int32_t keycodeThree)
{
    return false;
}

int32_t KeyBoardEvent::GetUnicode() const
{
    return mUnicode_;
}
} // namespace OHOS
