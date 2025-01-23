/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TOUCH_GESTURE_DETECTOR_H
#define TOUCH_GESTURE_DETECTOR_H

#include <map>
#include <unordered_set>
#include <vector>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
enum class GestureMode {
    ACTION_UNKNOWN,
    ACTION_SWIPE_DOWN,
    ACTION_SWIPE_UP,
    ACTION_SWIPE_LEFT,
    ACTION_SWIPE_RIGHT,
    ACTION_PINCH_CLOSED,
    ACTION_PINCH_OPENED,
    ACTION_GESTURE_END
};

struct Point {
    Point() {}
    Point(float px, float py) : x(px), y(py) {}
    Point(float px, float py, int64_t pt)
        : x(px), y(py), time(pt) {}
    float x { 0.0f };
    float y { 0.0f };
    int64_t time { 0 };
};

class TouchGestureDetector final {
public:
    class GestureListener {
    public:
        GestureListener() = default;
        virtual ~GestureListener() = default;
        virtual bool OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode) = 0;
        virtual void OnGestureTrend(std::shared_ptr<PointerEvent> event) = 0;
    };

    TouchGestureDetector(TouchGestureType type, std::shared_ptr<GestureListener> listener)
        : gestureType_(type), listener_(listener) {}
    bool OnTouchEvent(std::shared_ptr<PointerEvent> event);
    void AddGestureFingers(int32_t fingers);
    void RemoveGestureFingers(int32_t fingers);
    void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent);

    static bool IsPhysicalPointer(std::shared_ptr<PointerEvent> event);

private:
    enum class SlideState {
        DIRECTION_UNKNOW,
        DIRECTION_DOWN,
        DIRECTION_UP,
        DIRECTION_LEFT,
        DIRECTION_RIGHT
    };

    void ReleaseData();
    bool IsMatchGesture(int32_t count) const;
    bool IsMatchGesture(GestureMode action, int32_t count) const;
    void HandleDownEvent(std::shared_ptr<PointerEvent> event);
    void HandleMoveEvent(std::shared_ptr<PointerEvent> event);
    void HandleUpEvent(std::shared_ptr<PointerEvent> event);
    bool NotifyGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode);
    bool WhetherDiscardTouchEvent(std::shared_ptr<PointerEvent> event);

    Point CalcClusterCenter(const std::map<int32_t, Point> &points) const;
    Point CalcGravityCenter(std::map<int32_t, Point> &map);
    double CalcTwoPointsDistance(const Point &p1, const Point &p2) const;
    void CalcAndStoreDistance();
    int32_t CalcMultiFingerMovement(std::map<int32_t, Point> &map);
    void HandlePinchMoveEvent(std::shared_ptr<PointerEvent> event);
    bool InOppositeDirections(const std::unordered_set<SlideState> &directions) const;
    bool InDiverseDirections(const std::unordered_set<SlideState> &directions) const;
    GestureMode JudgeOperationMode(std::map<int32_t, Point> &movePoint);
    bool AntiJitter(std::shared_ptr<PointerEvent> event, GestureMode mode);
    std::vector<std::pair<int32_t, Point>> SortPoints(std::map<int32_t, Point> &points);

    bool HandleFingerDown();
    int64_t GetMaxDownInterval();
    float GetMaxFingerSpacing();
    GestureMode ChangeToGestureMode(SlideState state);
    SlideState GetSlidingDirection(double angle);
    void HandleSwipeMoveEvent(std::shared_ptr<PointerEvent> event);
    bool IsFingerMove(const Point &downPt, const Point &movePt) const;
    double GetAngle(float startX, float startY, float endX, float endY);
    SlideState ClacFingerMoveDirection(std::shared_ptr<PointerEvent> event);
    void CheckGestureTrend(std::shared_ptr<PointerEvent> event) const;
    bool IsLastTouchUp(std::shared_ptr<PointerEvent> event) const;
    void OnGestureSendEvent(std::shared_ptr<PointerEvent> event) const;

private:
    std::set<int32_t> fingers_;
    TouchGestureType gestureType_ { TOUCH_GESTURE_TYPE_NONE };
    bool isRecognized_ { false };
    bool gestureEnable_ { false };
    bool isFingerReady_ { false };
    bool haveGestureWinEmerged_ { false };
    int32_t gestureDisplayId_ { INT32_MAX };
    int32_t continuousCloseCount_ { 0 };
    int32_t continuousOpenCount_ { 0 };
    int32_t gestureTimer_ { -1 };
    std::map<int32_t, Point> downPoint_;
    std::map<int32_t, Point> movePoint_;
    std::map<int32_t, double> lastDistance_;
    std::shared_ptr<GestureListener> listener_ { nullptr };
    std::shared_ptr<PointerEvent> lastTouchEvent_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_DETECTOR_H