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

#include "rotation_event.h"

namespace OHOS {
RotationEvent::~RotationEvent() {}
void RotationEvent::Initialize(int32_t windowId, float rotationValue, int32_t highLevelEvent, const std::string& uuid,
                               int32_t sourceType, int32_t occurredTime, const std::string& deviceId,
                               int32_t inputDeviceId, bool isHighLevelEvent, uint16_t deviceUdevTags)
{
    MultimodalEvent::Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                isHighLevelEvent, deviceUdevTags);
    rotationValue_ = rotationValue;
}

void RotationEvent::Initialize(RotationEvent& rotationEvent)
{
    MultimodalEvent::Initialize(rotationEvent);
    rotationValue_ = rotationEvent.GetRotationValue();
}

float RotationEvent::GetRotationValue() const
{
    return rotationValue_;
}
} // namespace OHOS
