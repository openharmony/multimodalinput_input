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

#include "touch_event.h"

#include "mmi_log.h"
namespace OHOS {
void TouchEvent::Initialize(MultimodalProperty &multiProperty,
    ManipulationProperty &manipulationProperty, TouchProperty touchProperty)
{
    ManipulationEvent::Initialize(multiProperty, manipulationProperty);
    touchProperty_.action = touchProperty.action;
    touchProperty_.index = touchProperty.index;
    touchProperty_.forcePrecision = touchProperty.forcePrecision;
    touchProperty_.maxForce = touchProperty.maxForce;
    touchProperty_.tapCount = touchProperty.tapCount;
    touchProperty_.multimodalEvent = touchProperty.multimodalEvent;
}

bool TouchEvent::Marshalling(Parcel &parcel) const
{
    bool result = parcel.WriteInt32(manipulationProperty_.startTime);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(manipulationProperty_.operationState);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(manipulationProperty_.pointerCount);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(manipulationProperty_.pointerId);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(manipulationProperty_.mp.px_);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(manipulationProperty_.mp.py_);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(manipulationProperty_.mp.pz_);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(manipulationProperty_.touchArea);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(manipulationProperty_.touchPressure);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(touchProperty_.action);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(touchProperty_.index);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(touchProperty_.forcePrecision);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(touchProperty_.maxForce);
    if (!result) {
        return result;
    }
    result = parcel.WriteFloat(touchProperty_.tapCount);
    if (!result) {
        return result;
    }
    if (touchProperty_.multimodalEvent) {
        result = touchProperty_.multimodalEvent->Marshalling(parcel);
        if (!result) {
            return result;
        }
    }
    return result;
}

TouchEvent *TouchEvent::Unmarshalling(Parcel &parcel)
{
    TouchEvent *event = new (std::nothrow) TouchEvent();
    if (event == nullptr) {
        return nullptr;
    }
    return event;
}

int TouchEvent::GetAction()
{
    return touchProperty_.action;
}

int TouchEvent::GetPhase()
{
    int action = GetAction();
    switch (action) {
        case PRIMARY_POINT_DOWN:
            return PHASE_START;
        case POINT_MOVE:
            [[fallthrough]];
        case OTHER_POINT_UP:
        case OTHER_POINT_DOWN:
            return PHASE_MOVE;
        case PRIMARY_POINT_UP:
            return PHASE_COMPLETED;
        case CANCEL:
            return PHASE_CANCEL;
        default:
            MMI_LOGE("unknown phase action: %{public}d", action);
            return PHASE_NONE;
    }
}

int TouchEvent::GetIndex()
{
    return touchProperty_.index;
}

float TouchEvent::GetForcePrecision()
{
    return touchProperty_.forcePrecision;
}

float TouchEvent::GetMaxForce()
{
    return touchProperty_.maxForce;
}

float TouchEvent::GetTapCount()
{
    return touchProperty_.tapCount;
}
}