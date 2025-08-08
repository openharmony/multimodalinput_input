/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PULL_THROW_SUBSCRIBER_HANDLER_H
#define PULL_THROW_SUBSCRIBER_HANDLER_H

#include <algorithm>
#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "singleton.h"

#include "long_press_event.h"
#include "pointer_event.h"
#include "uds_server.h"


namespace OHOS {
namespace MMI {

class PullThrowSubscriberHandler final {
    DECLARE_DELAYED_SINGLETON(PullThrowSubscriberHandler);
public:
    DISALLOW_COPY_AND_MOVE(PullThrowSubscriberHandler);

    struct FingerGesture {
        struct {
            int32_t id { 0 };
            int32_t x { 0 };
            int32_t y { 0 };
            int64_t downTime { 0 };
        } touches[2];
    };
    
    void HandleFingerGestureDownEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureMoveEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGesturePullMoveEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGesturePullUpEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureUpEvent(std::shared_ptr<PointerEvent> touchEvent);
    int SetHotZoneArea(double locationX, double locationY, double width, double height);

private:
    void StopFingerGesture(std::shared_ptr<PointerEvent> touchEvent);
    void StartFingerGesture();
    bool CheckFingerValidation(std::shared_ptr<PointerEvent> touchEvent) const;
    bool CheckProgressValid(std::shared_ptr<PointerEvent> touchEvent);
    bool CheckThrowAngleValid(double angle);
    bool CheckThrowDirection(double angle, int32_t posY);
    void UpdateFingerPoisition(std::shared_ptr<PointerEvent> touchEvent);
    void UpdatePositionHistory(double x, double y, double time);
    bool CheckSuddenStop() const;
 
private:
    FingerGesture fingerGesture_;
    std::shared_ptr<PointerEvent> touchEvent_ { nullptr };
    bool gestureInProgress_ = false;
    double triggerTime_ = 0.0; // trigger time milliseconds
    bool alreadyTouchDown_ = false;
    
    // Store historical positions and times
    struct PositionRecord {
        double x { 0.0 };
        double y { 0.0 };
        double time { 0.0 }; // milliseconds
    };
    std::vector<PositionRecord> positionHistory_; // Store the most recent location record
    static constexpr size_t MAX_HISTORY_SIZE = 10;
    static constexpr size_t MIN_HISTORY_SIZE = 3;
    
    static constexpr double THRES_SPEED = 0.6; // unit: pix
    static constexpr int64_t MIN_THRES_DIST = 50; // unit: pix
    static constexpr double MAX_DECELERATION = 0.0;
    static constexpr int32_t FIRST_TOUCH_FINGER = 0;
    
    static constexpr double ANGLE_DOWN_MIN {45.0};
    static constexpr double ANGLE_DOWN_MAX {135.0};
    static constexpr double ANGLE_UP_MIN {225.0};
    static constexpr double ANGLE_UP_MAX {315.0};
    static constexpr double FULL_CIRCLE_DEGREES {360.0};
    static constexpr double NUM_EPSILON {1e-3};
    static constexpr double SPIN_UP_AREA_Y = 600; // Y value close to the spin from up screen side
    static constexpr double SPIN_DOWN_AREA_Y = 2400; // Y value close to the spin from down screen side
    static constexpr double UP_SCREEN_AREA_Y = 1600;
    static constexpr double DOWN_SCREEN_AREA_Y = 1700;
    static constexpr double SPEED_SCALE = 2.0;
    const int64_t WINDOW_TIME_INTERVAL = 0.20e6; // sample window, unit: u sec
};
#define PULL_THROW_EVENT_HANDLER ::OHOS::DelayedSingleton<PullThrowSubscriberHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // PULL_THROW_SUBSCRIBER_HANDLER_H
