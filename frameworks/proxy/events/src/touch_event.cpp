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

#include "touch_event.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

namespace OHOS {
    namespace {
        using namespace OHOS::MMI;
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TouchEvent"};
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
    mDeviceEventType_ = deviceEventType;
    mAction_ = action;
    mIndex_ = index;
    mForcePrecision_ = forcePrecision;
    mMaxForce_ = maxForce;
    mTapCount_ = tapCount;
    mIsStandard_ = isStandard;
}


void TouchEvent::Initialize(TouchEvent& touchEvent)
{
    ManipulationEvent::Initialize(touchEvent);
    mDeviceEventType_ = touchEvent.GetOriginEventType();
    mAction_ = touchEvent.GetAction();
    mIndex_ = touchEvent.GetIndex();
    mForcePrecision_ = touchEvent.GetForcePrecision();
    mMaxForce_ = touchEvent.GetMaxForce();
    mTapCount_ = touchEvent.GetTapCount();
    mIsStandard_ = touchEvent.GetIsStandard();
}

void TouchEvent::Initialize(int32_t windowId, MultimodalEventPtr deviceEvent, int32_t deviceEventType, int32_t action,
                            int32_t index, float forcePrecision, float maxForce, float tapCount, int32_t startTime,
                            int32_t operationState, int32_t pointerCount, fingerInfos fingersInfos[], bool isStandard)
{
    CHK(deviceEvent, ERROR_NULL_POINTER);
    ManipulationEvent::Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                  deviceEvent->GetHighLevelEvent(), deviceEvent->GetUuid(),
                                  deviceEvent->GetEventType(), deviceEvent->GetOccurredTime(),
                                  deviceEvent->GetDeviceId(), deviceEvent->GetInputDeviceId(),
                                  deviceEvent->IsHighLevelInput(), deviceEvent->GetDeviceUdevTags());
    mDeviceEventType_ = deviceEventType;
    mAction_ = action;
    mIndex_ = index;
    mForcePrecision_ = forcePrecision;
    mMaxForce_ = maxForce;
    mTapCount_ = tapCount;
    mIsStandard_ = isStandard;
    this->setMultimodalEvent(deviceEvent);
}

void TouchEvent::setMultimodalEvent(MultimodalEventPtr deviceEvent)
{
    mDeviceEvent_ = deviceEvent;
}

int32_t TouchEvent::GetAction() const
{
    return mAction_;
}

int32_t TouchEvent::GetIndex() const
{
    return mIndex_;
}

float TouchEvent::GetForcePrecision() const
{
    return mForcePrecision_;
}

float TouchEvent::GetMaxForce() const
{
    return mMaxForce_;
}

float TouchEvent::GetTapCount() const
{
    return mTapCount_;
}

bool TouchEvent::GetIsStandard() const
{
    return mIsStandard_;
}

const MultimodalEvent *TouchEvent::GetMultimodalEvent() const
{
    return mDeviceEvent_;
}

int32_t TouchEvent::GetPointToolType(int32_t index) const
{
    int32_t tableToolType = 0;

    if (index < 0) {
        return 0;
    }

    switch (mIndex_) {
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
    return mDeviceEventType_;
}
}
