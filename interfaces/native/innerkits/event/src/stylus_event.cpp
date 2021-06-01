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

#include "stylus_event.h"
namespace OHOS {
void StylusEvent::Initialize(MultimodalProperty &multimodalProperty,
    ManipulationProperty &manipulationProperty, StylusProperty stylusProperty)
{
    ManipulationEvent::Initialize(multimodalProperty, manipulationProperty);
    stylusProperty_.action = stylusProperty.action;
    stylusProperty_.buttons = stylusProperty.buttons;
}

bool StylusEvent::Marshalling(Parcel &parcel) const
{
    return false;
}

StylusEvent *StylusEvent::Unmarshalling(Parcel &parcel)
{
    StylusEvent *event = new (std::nothrow) StylusEvent();
    if (event == nullptr) {
        return nullptr;
    }
    return event;
}

int StylusEvent::GetAction()
{
    return stylusProperty_.action;
}

int StylusEvent::GetButtons()
{
    return stylusProperty_.buttons;
}
}  // namespace OHOS