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

#ifndef TOUCH_EVENT_H
#define TOUCH_EVENT_H

#include "manipulation_event.h"

namespace OHOS {
struct TouchProperty {
    int action;
    int index;
    float forcePrecision;
    float maxForce;
    float tapCount;

    std::shared_ptr<MultimodalEvent> multimodalEvent;
};

class TouchEvent : public ManipulationEvent {
public:
    void Initialize(MultimodalProperty &multimodalStruct,
        ManipulationProperty &manipulationProperty, TouchProperty touchProperty);

    void SetMultimodalEvent(std::shared_ptr<MultimodalEvent> multimodalEvent) {
        touchProperty_.multimodalEvent = multimodalEvent;
    }

    const std::shared_ptr<MultimodalEvent> GetMultimodalEvent() {
        return touchProperty_.multimodalEvent;
    }

    virtual int GetAction();

    virtual int GetIndex();

    virtual float GetForcePrecision();

    virtual float GetMaxForce();

    virtual float GetTapCount();

    int GetPhase() override;

    bool Marshalling(Parcel &parcel) const override;
    static TouchEvent *Unmarshalling(Parcel &parcel);

    static constexpr int NONE = 0;

    static constexpr int PRIMARY_POINT_DOWN = 1;

    static constexpr int PRIMARY_POINT_UP = 2;

    static constexpr int POINT_MOVE = 3;

    static constexpr int OTHER_POINT_DOWN = 4;

    static constexpr int OTHER_POINT_UP = 5;

    static constexpr int CANCEL = 6;

    static constexpr int HOVER_POINTER_ENTER = 7;

    static constexpr int HOVER_POINTER_MOVE = 8;

    static constexpr int HOVER_POINTER_EXIT = 9;

    static constexpr int OTHER = 10;
protected:
    TouchProperty touchProperty_;
};
}  // namespace OHOS
#endif  // TOUCH_EVENT_H