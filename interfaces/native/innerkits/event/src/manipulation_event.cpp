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

#include "manipulation_event.h"
#include "mmi_point.h"
namespace OHOS {
void ManipulationEvent::Initialize(MultimodalProperty &multiProperty,
    ManipulationProperty &manipulationProperty)
{
    MultimodalEvent::Initialize(multiProperty);
    manipulationProperty_.startTime = manipulationProperty.startTime;
    manipulationProperty_.operationState = manipulationProperty.operationState;
    manipulationProperty_.pointerCount = manipulationProperty.pointerCount;
    manipulationProperty_.pointerId = manipulationProperty.pointerId;
    manipulationProperty_.mp = manipulationProperty.mp;
    manipulationProperty_.touchArea = manipulationProperty.touchArea;
    manipulationProperty_.touchPressure = manipulationProperty.touchPressure;
    manipulationProperty_.offsetX = manipulationProperty.offsetX;
    manipulationProperty_.offsetY = manipulationProperty.offsetY;

}

int32_t ManipulationEvent::GetStartTime()
{
    return manipulationProperty_.startTime;
}

int ManipulationEvent::GetPhase()
{
    return manipulationProperty_.operationState;
}

MmiPoint ManipulationEvent::GetPointerPosition(int index)
{
    return MmiPoint(manipulationProperty_.mp.px_ - manipulationProperty_.offsetX,
        manipulationProperty_.mp.py_ - manipulationProperty_.offsetY);
}

void ManipulationEvent::SetScreenOffset(float offsetX, float offsetY)
{
    manipulationProperty_.offsetX = offsetX;
    manipulationProperty_.offsetY = offsetY;
}

MmiPoint ManipulationEvent::GetPointerScreenPosition(int index)
{
    return manipulationProperty_.mp;
}

int ManipulationEvent::GetPointerCount()
{
    return manipulationProperty_.pointerCount;
}

int ManipulationEvent::GetPointerId(int index)
{
    return manipulationProperty_.pointerId;
}

float ManipulationEvent::GetForce(int index)
{
    return manipulationProperty_.touchArea;
}

float ManipulationEvent::GetRadius(int index)
{
    return manipulationProperty_.touchPressure;
}

bool ManipulationEvent::Marshalling(Parcel &parcel) const
{
    return false;
}

ManipulationEvent *ManipulationEvent::Unmarshalling(Parcel &parcel)
{
    ManipulationEvent *event = new (std::nothrow) ManipulationEvent();
    if (event == nullptr) {
        return nullptr;
    }
    return event;
}
}
