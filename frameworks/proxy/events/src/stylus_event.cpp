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

#include "stylus_event.h"
#include <memory>

namespace OHOS {
StylusEvent::~StylusEvent() {}
void StylusEvent::Initialize(int32_t windowId, int32_t action, int32_t buttons, int64_t startTime,
                             int32_t operationState, int32_t pointerCount, fingerInfos fingersInfos[],
                             int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int64_t occurredTime,
                             const std::string& deviceId, int32_t inputDeviceId, bool isHighLevelEvent,
                             uint16_t deviceUdevTags)
{
    ManipulationEvent::Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                  highLevelEvent, uuid, sourceType, occurredTime, deviceId,
                                  inputDeviceId, isHighLevelEvent, deviceUdevTags);
    action_ = action;
    buttons_ = buttons;
    actionButtons_ = stylusButtonMapping(buttons);
}

void StylusEvent::Initialize(StylusEvent& stylusEvent)
{
    ManipulationEvent::Initialize(stylusEvent);
    action_ = stylusEvent.GetAction();
    buttons_ = stylusEvent.GetButtons();
}

int32_t StylusEvent::GetAction() const
{
    return action_;
}

int32_t StylusEvent::GetButtons() const
{
    return buttons_;
}

int32_t StylusEvent::GetActionButton() const
{
    return actionButtons_;
}

int32_t StylusEvent::stylusButtonMapping(int32_t stylusButton) const
{
    constexpr int32_t FIRST_BUTTON = 0x14b;   // stylus first button
    constexpr int32_t SECOND_BUTTON = 0x14c;  // stylus second button
    int32_t actionButton = stylusButton;

    switch (stylusButton) {
        case FIRST_BUTTON: {
            actionButton = BUTTON_STYLUS;
            break;
        }
        case SECOND_BUTTON: {
            actionButton = BUTTON_STYLUS2;
            break;
        }
        default: {
            actionButton = stylusButton;
            break;
        }
    }
    return actionButton;
}
} // namespace OHOS
