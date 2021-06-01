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

#ifndef STYLUS_EVENT_H
#define STYLUS_EVENT_H

#include "manipulation_event.h"

namespace OHOS {
struct StylusProperty {
    int action;
    int buttons;
};

class StylusEvent : public ManipulationEvent {
public:
    void Initialize(MultimodalProperty &multiProperty,
        ManipulationProperty &manipulationProperty, StylusProperty stylusProperty);

    virtual ~StylusEvent() { }

    virtual int GetAction();

    virtual int GetButtons();

    bool Marshalling(Parcel &parcel) const override;
    static StylusEvent *Unmarshalling(Parcel &parcel);

    static constexpr int NONE = 0;

    static constexpr int BUTTON_PRESS = 1;

    static constexpr int BUTTON_RELEASE = 2;

    static constexpr int STYLUS_DOWN = 3;

    static constexpr int STYLUS_MOVE = 4;

    static constexpr int STYLUS_UP = 5;

    static constexpr int NONE_BUTTON = 0;

    static constexpr int FIRST_BUTTON = 1;
protected:
    StylusProperty stylusProperty_;
};
}  // namespace OHOS
#endif  // STYLUS_EVENT_H