/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GESTURE_HANDLER_H
#define GESTURE_HANDLER_H

#include <cmath>
#include <map>
#include <libinput.h>

#include "pointer_event.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class GestureHandler {
    DECLARE_DELAYED_SINGLETON(GestureHandler);

    struct Position {
        double x = 0.0;
        double y = 0.0;
    };
public:
    DISALLOW_COPY_AND_MOVE(GestureHandler);
    int32_t GestureIdentify(int32_t originType, int32_t seatSlot, double logicalX, double logicalY);
    double GetRotateAngle();
    void InitRotateGesture();
    bool GetRotateStatus();

private:
    int32_t HandleTouchPadDownEvent(int32_t seatSlot, double logicalX, double logicalY);
    int32_t HandleTouchPadMoveEvent(int32_t seatSlot, double logicalX, double logicalY);
    int32_t HandleTouchPadUpEvent(int32_t seatSlot);
    double CalculateAngle(std::map<int32_t, struct Position> fingerPosition);
    double AdjustRotateAngle(double currentAngle);

private:
    bool isReady_ { false };
    bool isStartRotate_ { false };
    std::map<int32_t, struct Position> fingerDownPosition_;
    std::map<int32_t, struct Position> fingerCurrentPosition_;
    double initialAngle_ { 0.0 };
    double lastAngle_ { 0.0 };
    double rotateAngle_ { 0.0 };
};

#define GESTURE_HANDLER ::OHOS::DelayedSingleton<GestureHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // GESTURE_HANDLER_H