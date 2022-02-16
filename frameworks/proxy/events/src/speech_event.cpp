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

#include "speech_event.h"

namespace OHOS {
SpeechEvent::~SpeechEvent() {}
void SpeechEvent::Initialize(int32_t windowId, int32_t action, int32_t scene, int32_t mode, const std::string& actionProperty,
                             int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
                             const std::string& deviceId, int32_t inputDeviceId,  bool isHighLevelEvent,
                             uint16_t deviceUdevTags)
{
    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
                                inputDeviceId, isHighLevelEvent, deviceUdevTags);
    mAction_ = action;
    mScene_ = scene;
    mMode_ = mode;
    mActionProperty_ = actionProperty;
}

void SpeechEvent::Initialize(SpeechEvent& speechEvent)
{
    MultimodalEvent::Initialize(speechEvent);
    mAction_ = speechEvent.GetAction();
    mScene_ = speechEvent.GetScene();
    mMode_ = speechEvent.GetMatchMode();
    mActionProperty_ = speechEvent.GetActionProperty();
}

int32_t SpeechEvent::GetAction() const
{
    return mAction_;
}

int32_t SpeechEvent::GetScene() const
{
    return mScene_;
}

std::string SpeechEvent::GetActionProperty() const
{
    return mActionProperty_;
}

int32_t SpeechEvent::GetMatchMode() const
{
    return mMode_;
}
} // namespace OHOS
