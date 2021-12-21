/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "key_event_pre.h"

namespace OHOS {
KeyEvent::~KeyEvent() {}
void KeyEvent::Initialize(int32_t windowId, bool isPressed, int32_t keyCode, int32_t keyDownDuration,
                          int32_t highLevelEvent, const std::string& uuid, int32_t sourceType,
                          uint64_t occurredTime, const std::string& deviceId, int32_t inputDeviceId,
                          bool isHighLevelEvent, uint16_t deviceUdevTags, int32_t deviceEventType,
                          bool isIntercepted)
{
    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
                                inputDeviceId, isHighLevelEvent, deviceUdevTags, isIntercepted);
    mIsPressed_ = isPressed;
    mKeyCode_ = keyCode;
    mKeyDownDuration_ = keyDownDuration;
    mDeviceEventType_ = deviceEventType;
}

void KeyEvent::Initialize(const KeyEvent &keyEvent)
{
    MultimodalEvent::Initialize(keyEvent);
    mDeviceEventType_ = keyEvent.GetOriginEventType();
    mIsPressed_ = keyEvent.IsKeyDown();
    mKeyCode_ = keyEvent.GetKeyCode();
    mKeyDownDuration_ = keyEvent.GetKeyDownDuration();
}

int32_t KeyEvent::GetMaxKeyCode() const
{
    return NOW_MAX_KEY;
}

bool KeyEvent::IsKeyDown() const
{
    return mIsPressed_;
}

int32_t KeyEvent::GetKeyCode() const
{
    return mKeyCode_;
}

int32_t KeyEvent::GetKeyDownDuration() const
{
    return mKeyDownDuration_;
}

int32_t KeyEvent::GetOriginEventType() const
{
    return mDeviceEventType_;
}
}
