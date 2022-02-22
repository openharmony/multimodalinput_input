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

#include "touch_event.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

namespace OHOS {
    namespace {
        using namespace OHOS::MMI;
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TouchEvent"};
    }

TouchEvent::~TouchEvent() {}
void TouchEvent::Initialize(int32_t windowId, int32_t action, int32_t index, float forcePrecision, float maxForce, float tapCount,
                            int32_t startTime, int32_t operationState, int32_t pointerCount, fingerInfos fingersInfos[],
                            int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
                            const std::string& deviceId, int32_t inputDeviceId, bool isHighLevelEvent, bool isStandard,
                            uint16_t deviceUdevTags, int32_t deviceEventType)
{
    ManipulationEvent::Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                  highLevelEvent, uuid, sourceType, occurredTime, deviceId,
                                  inputDeviceId, isHighLevelEvent, deviceUdevTags);
    deviceEventType_ = deviceEventType;
    action_ = action;
    index_ = index;
    forcePrecision_ = forcePrecision;
    maxForce_ = maxForce;
    tapCount_ = tapCount;
    isStandard_  = isStandard;
}

void TouchEvent::Initialize(TouchEvent& touchEvent)
{
    ManipulationEvent::Initialize(touchEvent);
    deviceEventType_ = touchEvent.GetOriginEventType();
    action_ = touchEvent.GetAction();
    index_ = touchEvent.GetIndex();
    forcePrecision_ = touchEvent.GetForcePrecision();
    maxForce_ = touchEvent.GetMaxForce();
    tapCount_ = touchEvent.GetTapCount();
    isStandard_  = touchEvent.GetIsStandard();
}

void TouchEvent::Initialize(int32_t windowId, MultimodalEventPtr deviceEvent, int32_t deviceEventType, int32_t action,
                            int32_t index, float forcePrecision, float maxForce, float tapCount, int32_t startTime,
                            int32_t operationState, int32_t pointerCount, fingerInfos fingersInfos[], bool isStandard)
{
    CHKPV(deviceEvent);
    ManipulationEvent::Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                  deviceEvent->GetHighLevelEvent(), deviceEvent->GetUuid(),
                                  deviceEvent->GetEventType(), deviceEvent->GetOccurredTime(),
                                  deviceEvent->GetDeviceId(), deviceEvent->GetInputDeviceId(),
                                  deviceEvent->IsHighLevelInput(), deviceEvent->GetDeviceUdevTags());
    deviceEventType_ = deviceEventType;
    action_ = action;
    index_ = index;
    forcePrecision_ = forcePrecision;
    maxForce_ = maxForce;
    tapCount_ = tapCount;
    isStandard_  = isStandard;
    setMultimodalEvent(deviceEvent);
}

void TouchEvent::setMultimodalEvent(MultimodalEventPtr deviceEvent)
{
    deviceEvent_ = deviceEvent;
}

int32_t TouchEvent::GetAction() const
{
    return action_;
}

int32_t TouchEvent::GetIndex() const
{
    return index_;
}

float TouchEvent::GetForcePrecision() const
{
    return forcePrecision_;
}

float TouchEvent::GetMaxForce() const
{
    return maxForce_;
}

float TouchEvent::GetTapCount() const
{
    return tapCount_;
}

bool TouchEvent::GetIsStandard() const
{
    return isStandard_ ;
}

const MultimodalEvent *TouchEvent::GetMultimodalEvent() const
{
    return deviceEvent_;
}

int32_t TouchEvent::GetPointToolType(int32_t index) const
{
    if (index < 0) {
        return 0;
    }

    int32_t tableToolType = 0;
    switch (index_) {
        case TABLET_TOOL_TYPE_PEN: {
            tableToolType = BUTTON_TOOL_PEN;
            break;
        }
        case TABLET_TOOL_TYPE_ERASER: {
            tableToolType = BUTTON_TOOL_RUBBER;
            break;
        }
        case TABLET_TOOL_TYPE_BRUSH: {
            tableToolType = BUTTON_TOOL_BRUSH;
            break;
        }
        case TABLET_TOOL_TYPE_PENCIL: {
            tableToolType = BUTTON_TOOL_PENCIL;
            break;
        }
        case TABLET_TOOL_TYPE_AIRBRUSH: {
            tableToolType = BUTTON_TOOL_AIRBRUSH;
            break;
        }
        case TABLET_TOOL_TYPE_MOUSE: {
            tableToolType = BUTTON_TOOL_MOUSE;
            break;
        }
        case TABLET_TOOL_TYPE_LENS: {
            tableToolType = BUTTON_TOOL_LENS;
            break;
        }
        case TABLET_TOOL_TYPE_TOTEM: {
            tableToolType = BUTTON_TOOL_PEN;
            break;
        }
        default: {
            break;
        }
    }

    return tableToolType;
}

int32_t TouchEvent::GetOriginEventType() const
{
    return deviceEventType_;
}
} // namespace OHOS
