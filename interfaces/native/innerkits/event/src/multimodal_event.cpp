/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "multimodal_event.h"

namespace OHOS {
void MultimodalEvent::Initialize(MultimodalProperty &multimodalProperty)
{
    multiProperty_.uuid = multimodalProperty.uuid;
    multiProperty_.occurredTime = multimodalProperty.occurredTime;
    multiProperty_.sourceType = multimodalProperty.sourceType;
    multiProperty_.highLevelEvent = multimodalProperty.highLevelEvent;
    multiProperty_.deviceId = multimodalProperty.deviceId;
    multiProperty_.inputDeviceId = multimodalProperty.inputDeviceId;
    multiProperty_.isHighLevelEvent = multimodalProperty.isHighLevelEvent;
}

bool MultimodalEvent::Marshalling(Parcel &parcel) const
{
    return false;
}

MultimodalEvent *MultimodalEvent::Unmarshalling(Parcel &parcel)
{
    MultimodalEvent *event = new (std::nothrow) MultimodalEvent();
    if (event == nullptr) {
        return nullptr;
    }
    return event;
}

bool MultimodalEvent::IsSameEvent(const std::string &id)
{
    return multiProperty_.uuid == id;
}

bool MultimodalEvent::IsHighLevelInput()
{
    return multiProperty_.isHighLevelEvent;
}

int MultimodalEvent::GetHighLevelEvent()
{
    return multiProperty_.highLevelEvent;
}

int MultimodalEvent::GetSourceDevice()
{
    return multiProperty_.sourceType;
}

std::string MultimodalEvent::GetDeviceId()
{
    return multiProperty_.deviceId;
}

int MultimodalEvent::GetInputDeviceId()
{
    return multiProperty_.inputDeviceId;
}

int MultimodalEvent::GetOccurredTime()
{
    return multiProperty_.occurredTime;
}

std::string MultimodalEvent::GetUuid()
{
    return multiProperty_.uuid;
}
}  // namespace OHOS
