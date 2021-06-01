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

#ifndef MANIPULATION_EVENT_H
#define MANIPULATION_EVENT_H

#include "mmi_point.h"
#include "multimodal_event.h"

namespace OHOS {
struct ManipulationProperty {
    unsigned int startTime;
    int operationState;
    int pointerCount;
    int pointerId;
    MmiPoint mp;
    float touchArea;
    float touchPressure;
    float offsetX;
    float offsetY;
};

const int MAX_TOUCH_NUM = 10;

class ManipulationEvent : public MultimodalEvent {
public:
    void Initialize(MultimodalProperty &multiProperty, ManipulationProperty &ManipulationProperty);

    virtual int32_t GetStartTime();

    virtual int GetPhase();

    virtual MmiPoint GetPointerPosition(int index);

    virtual void SetScreenOffset(float offsetX, float offsetY);

    virtual MmiPoint GetPointerScreenPosition(int index);

    virtual int GetPointerCount();

    virtual int GetPointerId(int index);

    virtual float GetForce(int index);

    virtual float GetRadius(int index);
    bool Marshalling(Parcel &parcel) const override;
    static ManipulationEvent *Unmarshalling(Parcel &parcel);

    static constexpr int PHASE_NONE = 0;

    static constexpr int PHASE_START = 1;

    static constexpr int PHASE_MOVE = 2;

    static constexpr int PHASE_COMPLETED = 3;

    static constexpr int PHASE_CANCEL = 4;
protected:
    ManipulationProperty manipulationProperty_;
};
}  // namespace OHOS
#endif  // MANIPULATION_EVENT_H