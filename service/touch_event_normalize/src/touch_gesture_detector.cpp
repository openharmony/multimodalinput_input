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

#include "touch_gesture_detector.h"
#include <numeric>

#include "input_event_handler.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureDetector"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t MAX_PHYSCAL_POINTER_NUM { 10 };
constexpr int32_t ANGLE_PI { 180 };

constexpr double ANGLE_RIGHT_DOWN { -45.0 };
constexpr double ANGLE_RIGHT_UP { 45.0 };
constexpr double ANGLE_LEFT_DOWN { -135.0 };
constexpr double ANGLE_LEFT_UP { 135.0 };

// gesture threshold values
constexpr float MAXIMUM_POINTER_SPACING { 2000 };
constexpr int64_t MAXIMUM_POINTER_INTERVAL { 100000 };
constexpr int64_t MAXIMUM_PRESS_DELAY { 15 }; // ms
constexpr double MAXIMUM_SINGLE_SLIDE_DISTANCE { 3.0 };
constexpr double MINIMUM_GRAVITY_OFFSET { 0.5 };
constexpr int32_t MAXIMUM_CONTINUOUS_COUNTS { 2 };
constexpr int32_t MINIMUM_FINGER_COUNT_OFFSET { 1 };
constexpr size_t SINGLE_TOUCH { 1 };
constexpr size_t SINGLE_DIRECTION { 1 };
} // namespace

bool TouchGestureDetector::OnTouchEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPF(event);
    if (WhetherDiscardTouchEvent(event)) {
        return false;
    }
    int32_t action = event->GetPointerAction();
    switch (action) {
        case PointerEvent::POINTER_ACTION_DOWN: {
            HandleDownEvent(event);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            HandleMoveEvent(event);
            break;
        }
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            HandleUpEvent(event);
            break;
        }
        default: {
            MMI_HILOGD("action:%{public}s is invalid", event->DumpPointerAction());
            break;
        }
    }
    return isRecognized_;
}

void TouchGestureDetector::HandleDownEvent(std::shared_ptr<PointerEvent> event)
{
    CALL_INFO_TRACE;
    if (isRecognized_) {
        if (haveGestureWinEmerged_) {
            return;
        }
        MMI_HILOGI("Touch-down while touch gesture is pending");
        isRecognized_ = false;

        if (lastTouchEvent_ != nullptr) {
            auto now = GetSysClockTime();
            lastTouchEvent_->SetActionTime(now);
            NotifyGestureEvent(lastTouchEvent_, GestureMode::ACTION_GESTURE_END);
        }
    }
    int32_t pointerId = event->GetPointerId();
    PointerEvent::PointerItem item {};

    if (!event->GetPointerItem(pointerId, item)) {
        MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
        return;
    }
    auto [_, isNew] = downPoint_.insert_or_assign(
        pointerId, Point { item.GetDisplayX(), item.GetDisplayY(), item.GetDownTime() });
    if (!isNew) {
        MMI_HILOGE("Insert value failed, duplicated pointerId:%{public}d", pointerId);
    }
    if (gestureTimer_ >= 0) {
        TimerMgr->RemoveTimer(gestureTimer_);
        gestureTimer_ = -1;
    }
    if (gestureType_ == TOUCH_GESTURE_TYPE_SWIPE) {
        isFingerReady_ = HandleFingerDown();
    } else if (gestureType_ == TOUCH_GESTURE_TYPE_PINCH) {
        CalcAndStoreDistance();
        movePoint_ = downPoint_;
    }
    MMI_HILOGI("The gestureType:%{public}d, touches:%{public}s, isFingerReady:%{public}d, pointerId:%{public}d",
        gestureType_, DumpTouches().c_str(), isFingerReady_, pointerId);
}

void TouchGestureDetector::HandleMoveEvent(std::shared_ptr<PointerEvent> event)
{
    if (isRecognized_ || (gestureTimer_ >= 0)) {
        return;
    }
    if (!GestureMonitorHandler::CheckMonitorValid(gestureType_, static_cast<int32_t>(downPoint_.size()))) {
        return;
    }
    if (!IsMatchGesture(event->GetPointerCount()) && !IsMatchGesture(ALL_FINGER_COUNT)) {
        return;
    }
    if (gestureType_ == TOUCH_GESTURE_TYPE_SWIPE) {
        HandleSwipeMoveEvent(event);
    } else if (gestureType_ == TOUCH_GESTURE_TYPE_PINCH) {
        HandlePinchMoveEvent(event);
    }
    if (isRecognized_) {
        lastTouchEvent_ = std::make_shared<PointerEvent>(*event);
        if (listener_ != nullptr) {
            listener_->OnGestureTrend(event);
        }
    }
}

void TouchGestureDetector::HandleSwipeMoveEvent(std::shared_ptr<PointerEvent> event)
{
    if (!isFingerReady_) {
        return;
    }
    auto state = ClacFingerMoveDirection(event);
    if (state == SlideState::DIRECTION_UNKNOW) {
        return;
    }
    GestureMode type = ChangeToGestureMode(state);
    if (type == GestureMode::ACTION_UNKNOWN) {
        return;
    }
    gestureTimer_ = TimerMgr->AddTimer(MAXIMUM_PRESS_DELAY, REPEAT_ONCE,
        [this, pointerEvent = std::make_shared<PointerEvent>(*event), type]() {
            gestureTimer_ = -1;
            isRecognized_ = true;
            lastTouchEvent_ = pointerEvent;
            NotifyGestureEvent(pointerEvent, type);
#ifdef TOUCH_GESTURE_MONITOR_ENABLED
            MMI_HILOGW("Touch-swipe identified, cancel all touches");
            if (listener_ != nullptr) {
                listener_->OnGestureTrend(pointerEvent);
            }
#else
            MMI_HILOGI("Touch-swipe identified, will not cancel touches");
#endif // TOUCH_GESTURE_MONITOR_ENABLED
        });
    if (gestureTimer_ < 0) {
        MMI_HILOGE("TimerMgr::AddTimer fail");
    }
}

void TouchGestureDetector::HandlePinchMoveEvent(std::shared_ptr<PointerEvent> event)
{
    std::map<int32_t, Point> movePoints;
    std::unordered_set<SlideState> directions;

    for (const auto &[pointerId, downPt] : downPoint_) {
        PointerEvent::PointerItem item {};
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
            return;
        }
        Point movePt { item.GetDisplayX(), item.GetDisplayY(), item.GetDownTime() };

        if (IsFingerMove(downPt, movePt)) {
            double angle = GetAngle(downPt.x, downPt.y, movePt.x, movePt.y);
            auto direction = GetSlidingDirection(angle);
            directions.insert(direction);
        }
        auto [_, isNew] = movePoints.insert_or_assign(pointerId, movePt);
        if (!isNew) {
            MMI_HILOGE("Insert value failed, duplicated pointerId:%{public}d", pointerId);
        }
    }
    if (!InDiverseDirections(directions)) {
        return;
    }
    if (CalcMultiFingerMovement(movePoints) >=
        static_cast<int32_t>(downPoint_.size() - MINIMUM_FINGER_COUNT_OFFSET)) {
        movePoint_ = movePoints;
        GestureMode type = JudgeOperationMode(movePoints);
        isRecognized_ = AntiJitter(event, type);
    }
}

bool TouchGestureDetector::InOppositeDirections(const std::unordered_set<SlideState> &directions) const
{
    bool up = directions.find(SlideState::DIRECTION_DOWN) != directions.cend();
    bool down = directions.find(SlideState::DIRECTION_UP) != directions.cend();
    bool left = directions.find(SlideState::DIRECTION_LEFT) != directions.cend();
    bool right = directions.find(SlideState::DIRECTION_RIGHT) != directions.cend();
    return (up && down) || (up && left) || (up && right) || (down && left) || (down && right) || (left && right);
}

bool TouchGestureDetector::InDiverseDirections(const std::unordered_set<SlideState> &directions) const
{
    return (directions.size() > SINGLE_DIRECTION);
}

void TouchGestureDetector::HandleUpEvent(std::shared_ptr<PointerEvent> event)
{
    CALL_INFO_TRACE;
    downPoint_.erase(event->GetPointerId());
    movePoint_.erase(event->GetPointerId());
    MMI_HILOGI("The gestureType:%{public}d, touches:%{public}s, isFingerReady:%{public}d, pointerId:%{public}d",
        gestureType_, DumpTouches().c_str(), isFingerReady_, event->GetPointerId());
    if (gestureTimer_ >= 0) {
        TimerMgr->RemoveTimer(gestureTimer_);
        gestureTimer_ = -1;
    }
    if (isRecognized_) {
        PointerEvent::PointerItem pointerItem {};

        if ((lastTouchEvent_ != nullptr) &&
            lastTouchEvent_->GetPointerItem(event->GetPointerId(), pointerItem) &&
            event->GetPointerItem(event->GetPointerId(), pointerItem)) {
            lastTouchEvent_->UpdatePointerItem(event->GetPointerId(), pointerItem);
        }
        if (!haveGestureWinEmerged_) {
            MMI_HILOGI("Touch-up while touch gesture is pending");
            if (lastTouchEvent_ != nullptr) {
                auto now = GetSysClockTime();
                lastTouchEvent_->SetActionTime(now);
                NotifyGestureEvent(lastTouchEvent_, GestureMode::ACTION_GESTURE_END);
            }
        }
    }
    if (IsLastTouchUp(event)) {
        if (isRecognized_ && (lastTouchEvent_ != nullptr)) {
            auto now = GetSysClockTime();
            lastTouchEvent_->SetActionTime(now);
            NotifyGestureEvent(lastTouchEvent_, GestureMode::ACTION_GESTURE_END);
        }
        ReleaseData();
    }
}

bool TouchGestureDetector::IsPhysicalPointer(std::shared_ptr<PointerEvent> event)
{
    CHKPF(event);
    if (event->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        return false;
    }
    const int32_t pointerId = event->GetPointerId();
    return ((pointerId >= 0) && (pointerId < MAX_PHYSCAL_POINTER_NUM));
}

void TouchGestureDetector::ReleaseData()
{
    CALL_INFO_TRACE;
    if (gestureTimer_ >= 0) {
        TimerMgr->RemoveTimer(gestureTimer_);
        gestureTimer_ = -1;
    }
    isRecognized_ = false;
    isFingerReady_ = false;
    haveGestureWinEmerged_ = false;
    lastTouchEvent_ = nullptr;
    continuousCloseCount_ = 0;
    continuousOpenCount_ = 0;
    lastDistance_.clear();
    downPoint_.clear();
    movePoint_.clear();
}

bool TouchGestureDetector::WhetherDiscardTouchEvent(std::shared_ptr<PointerEvent> event)
{
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return true;
    }
    if (!gestureEnable_) {
        return true;
    }
    if (!IsPhysicalPointer(event)) {
        return true;
    }
    int32_t displayId = event->GetTargetDisplayId();
    if (gestureDisplayId_ != INT32_MAX && gestureDisplayId_ != displayId) {
        MMI_HILOGE("touch event from two different display, discards touch event");
        return true;
    }
    int32_t action = event->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_UP) {
        gestureDisplayId_ = INT32_MAX;
        return false;
    }
    if (action == PointerEvent::POINTER_ACTION_DOWN) {
        gestureDisplayId_ = displayId;
    }
    return false;
}

bool TouchGestureDetector::HandleFingerDown()
{
    if (!GestureMonitorHandler::CheckMonitorValid(gestureType_, static_cast<int32_t>(downPoint_.size()))) {
        return false;
    }
    float maxDistance = GetMaxFingerSpacing();
    if (maxDistance > MAXIMUM_POINTER_SPACING) {
        MMI_HILOGE("Too much finger spacing");
        return false;
    }
    int64_t interval = GetMaxDownInterval();
    if (interval > MAXIMUM_POINTER_INTERVAL) {
        MMI_HILOGE("The pointers down time interval is too long");
        return false;
    }
    return true;
}

int64_t TouchGestureDetector::GetMaxDownInterval() const
{
    int64_t earliestTime = std::numeric_limits<int64_t>::max();
    int64_t latestTime = std::numeric_limits<int64_t>::min();

    for (const auto &point : downPoint_) {
        int64_t touchTime = point.second.time;
        if (touchTime > latestTime) {
            latestTime = touchTime;
        }
        if (touchTime < earliestTime) {
            earliestTime = touchTime;
        }
    }
    MMI_HILOGI("Down interval:%{public}" PRId64, (latestTime - earliestTime));
    return latestTime - earliestTime;
}

float TouchGestureDetector::GetMaxFingerSpacing() const
{
    float maxSpacing = 0.0f;

    for (auto iter = downPoint_.cbegin(); iter != downPoint_.cend(); ++iter) {
        auto innerIter = iter;
        float pX = iter->second.x;
        float pY = iter->second.y;

        for (++innerIter; innerIter != downPoint_.cend(); ++innerIter) {
            float nX = innerIter->second.x;
            float nY = innerIter->second.y;
            maxSpacing = std::max<float>(maxSpacing, std::hypot(pX - nX, pY - nY));
        }
    }
    MMI_HILOGI("Down max spacing:%{public}.2f", maxSpacing);
    return maxSpacing;
}

double TouchGestureDetector::GetAngle(float startX, float startY, float endX, float endY) const
{
    return std::atan2((endY - startY), (endX - startX)) * (ANGLE_PI / M_PI);
}

bool TouchGestureDetector::IsFingerMove(const Point &downPt, const Point &movePt) const
{
    return (CalcTwoPointsDistance(downPt, movePt) > MAXIMUM_SINGLE_SLIDE_DISTANCE);
}

TouchGestureDetector::SlideState TouchGestureDetector::GetSlidingDirection(double angle)
{
    if (angle >= ANGLE_RIGHT_DOWN && angle < ANGLE_RIGHT_UP) {
        return TouchGestureDetector::SlideState::DIRECTION_RIGHT;
    } else if (angle >= ANGLE_RIGHT_UP && angle < ANGLE_LEFT_UP) {
        return TouchGestureDetector::SlideState::DIRECTION_DOWN;
    } else if (angle >= ANGLE_LEFT_DOWN && angle < ANGLE_RIGHT_DOWN) {
        return TouchGestureDetector::SlideState::DIRECTION_UP;
    } else {
        return TouchGestureDetector::SlideState::DIRECTION_LEFT;
    }
}

GestureMode TouchGestureDetector::ChangeToGestureMode(TouchGestureDetector::SlideState state)
{
    switch (state) {
        case TouchGestureDetector::SlideState::DIRECTION_UP: {
            return GestureMode::ACTION_SWIPE_UP;
        }
        case TouchGestureDetector::SlideState::DIRECTION_DOWN: {
            return GestureMode::ACTION_SWIPE_DOWN;
        }
        case TouchGestureDetector::SlideState::DIRECTION_LEFT: {
            return GestureMode::ACTION_SWIPE_LEFT;
        }
        case TouchGestureDetector::SlideState::DIRECTION_RIGHT: {
            return GestureMode::ACTION_SWIPE_RIGHT;
        }
        default: {
            MMI_HILOGW("unknow state:%{public}d", state);
            return GestureMode::ACTION_UNKNOWN;
        }
    }
}

TouchGestureDetector::SlideState TouchGestureDetector::ClacFingerMoveDirection(std::shared_ptr<PointerEvent> event)
{
    if (event->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
        return SlideState::DIRECTION_UNKNOW;
    }
    if (downPoint_.size() < THREE_FINGER_COUNT) {
        return SlideState::DIRECTION_UNKNOW;
    }
    size_t recognizedCount { 0 };
    std::unordered_set<SlideState> directions;

    for (const auto &[pointerId, downPt] : downPoint_) {
        PointerEvent::PointerItem item {};
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
            return SlideState::DIRECTION_UNKNOW;
        }
        Point movePt { item.GetDisplayX(), item.GetDisplayY() };

        if (!IsFingerMove(downPt, movePt)) {
            continue;
        }
        double angle = GetAngle(downPt.x, downPt.y, movePt.x, movePt.y);
        auto direction = GetSlidingDirection(angle);
        if (direction != SlideState::DIRECTION_UNKNOW) {
            directions.insert(direction);
            ++recognizedCount;
        }
        MMI_HILOGI("The pointerId:%{public}d,angle:%{public}.2f,direction:%{public}d", pointerId, angle, direction);
    }
    if ((recognizedCount < downPoint_.size()) || InDiverseDirections(directions)) {
        return SlideState::DIRECTION_UNKNOW;
    }
    return *(directions.begin());
}

double TouchGestureDetector::CalcTwoPointsDistance(const Point &p1, const Point &p2) const
{
    return std::hypot(p1.x - p2.x, p1.y - p2.y);
}

std::vector<std::pair<int32_t, Point>> TouchGestureDetector::SortPoints(std::map<int32_t, Point> &points)
{
    if (points.empty()) {
        MMI_HILOGW("Points are empty");
        return {};
    }
    std::vector<std::pair<int32_t, Point>> sequence(points.begin(), points.end());
    std::sort(sequence.begin(), sequence.end(),
        [](std::pair<int32_t, Point> right, std::pair<int32_t, Point> left) {
        return right.second.x < left.second.x;
    });
    auto iter = std::max_element(sequence.begin(), sequence.end(),
        [](std::pair<int32_t, Point> right, std::pair<int32_t, Point> left) {
        return right.second.y < left.second.y;
    });
    std::pair<int32_t, Point> temp = *iter;
    sequence.erase(iter);
    sequence.push_back(temp);
    return sequence;
}

Point TouchGestureDetector::CalcClusterCenter(const std::map<int32_t, Point> &points) const
{
    if (points.empty()) {
        return Point {};
    }
    Point acc = std::accumulate(points.cbegin(), points.cend(), Point{},
        [](const auto &init, const auto &item) {
            return Point { init.x + item.second.x, init.y + item.second.y };
        });
    return Point { acc.x / points.size(), acc.y / points.size() };
}

Point TouchGestureDetector::CalcGravityCenter(std::map<int32_t, Point> &points)
{
    double xSum = 0.0;
    double ySum = 0.0;
    double area = 0.0;
    const int32_t arrCount = 2;
    int32_t count = static_cast<int32_t>(points.size());
    if (count < FOUR_FINGER_COUNT || count > MAX_FINGERS_COUNT) {
        return Point(static_cast<float>(xSum), static_cast<float>(ySum));
    }
    double **vertices = new (std::nothrow) double *[count];
    if (vertices == nullptr) {
        return Point(static_cast<float>(xSum), static_cast<float>(ySum));
    }
    int32_t i = 0;
    std::vector<std::pair<int32_t, Point>> sequence = SortPoints(points);
    if (sequence.empty()) {
        MMI_HILOGW("Points sorting failed");
        goto end;
    }
    for (const auto &pointData : sequence) {
        vertices[i] = new (std::nothrow) double[arrCount];
        if (vertices[i] == nullptr) {
            goto end;
        }
        Point value = pointData.second;
        vertices[i][0] = value.x;
        vertices[i][1] = value.y;
        ++i;
    }
    for (int32_t j = 0; j < count; ++j) {
        double *current = vertices[j];
        double *next = vertices[(j + 1) % count];
        double crossProduct = current[0] * next[1] - next[0] * current[1];
        area += crossProduct;
        xSum += (current[0] + next[0]) * crossProduct;
        ySum += (current[1] + next[1]) * crossProduct;
    }
    area /= arrCount;
    xSum /= count * area;
    ySum /= count * area;
end:
    for (int32_t n = 0; n < count; ++n) {
        if (vertices[n] != nullptr) {
            delete[] vertices[n];
        }
    }
    delete[] vertices;
    return Point(static_cast<float>(xSum), static_cast<float>(ySum));
}

void TouchGestureDetector::CalcAndStoreDistance()
{
    if (!GestureMonitorHandler::CheckMonitorValid(gestureType_, static_cast<int32_t>(downPoint_.size()))) {
        return;
    }
    lastDistance_.clear();
    int64_t interval = GetMaxDownInterval();
    if (interval > MAXIMUM_POINTER_INTERVAL) {
        MMI_HILOGE("The pointers down time interval is too long");
        return;
    }
    Point center = CalcClusterCenter(downPoint_);

    for (const auto &[pointerId, downPt] : downPoint_) {
        double distance = CalcTwoPointsDistance(center, downPt);
        lastDistance_.emplace(pointerId, distance);
    }
}

int32_t TouchGestureDetector::CalcMultiFingerMovement(std::map<int32_t, Point> &points)
{
    int32_t movementCount = 0;
    for (const auto &[id, point] : movePoint_) {
        auto movePoints = points.find(id);
        if (movePoints == points.end()) {
            continue;
        }
        if (CalcTwoPointsDistance(point, movePoints->second) >= MAXIMUM_SINGLE_SLIDE_DISTANCE) {
            ++movementCount;
        }
    }
    return movementCount;
}

GestureMode TouchGestureDetector::JudgeOperationMode(std::map<int32_t, Point> &movePoints)
{
    Point center = CalcClusterCenter(movePoints);
    std::map<int32_t, double> tempDistance;
    int32_t closeCount = 0;
    int32_t openCount = 0;

    for (const auto &[pointerId, _] : downPoint_) {
        auto movePointIter = movePoints.find(pointerId);
        if (movePointIter == movePoints.end()) {
            return GestureMode::ACTION_UNKNOWN;
        }
        double currentDistance = CalcTwoPointsDistance(center, movePointIter->second);
        auto distanceIter = lastDistance_.find(pointerId);
        if (distanceIter == lastDistance_.end()) {
            return GestureMode::ACTION_UNKNOWN;
        }
        double lastDistance = distanceIter->second;
        if (currentDistance < lastDistance &&
            lastDistance - currentDistance >= MINIMUM_GRAVITY_OFFSET) {
            ++closeCount;
        } else if (currentDistance > lastDistance &&
            currentDistance - lastDistance >= MINIMUM_GRAVITY_OFFSET) {
            ++openCount;
        }
        tempDistance.emplace(pointerId, currentDistance);
        MMI_HILOGI("The pointerId:%{public}d,lastDistance:%{public}.2f,"
            "currentDistance:%{public}.2f,closeCount:%{public}d,openCount:%{public}d",
            pointerId, lastDistance, currentDistance, closeCount, openCount);
    }

    lastDistance_.swap(tempDistance);
    GestureMode type = GestureMode::ACTION_UNKNOWN;

    if (closeCount >= static_cast<int32_t>(downPoint_.size() - MINIMUM_FINGER_COUNT_OFFSET)) {
        type = GestureMode::ACTION_PINCH_CLOSED;
    } else if (openCount >= static_cast<int32_t>(downPoint_.size() - MINIMUM_FINGER_COUNT_OFFSET)) {
        type = GestureMode::ACTION_PINCH_OPENED;
    }
    return type;
}

bool TouchGestureDetector::AntiJitter(std::shared_ptr<PointerEvent> event, GestureMode mode)
{
    if (mode == GestureMode::ACTION_PINCH_CLOSED) {
        ++continuousCloseCount_;
        if (continuousCloseCount_ >= MAXIMUM_CONTINUOUS_COUNTS) {
            return NotifyGestureEvent(event, mode);
        }
        continuousOpenCount_ = 0;
    } else if (mode == GestureMode::ACTION_PINCH_OPENED) {
        ++continuousOpenCount_;
        if (continuousOpenCount_ >= MAXIMUM_CONTINUOUS_COUNTS) {
            return NotifyGestureEvent(event, mode);
        }
        continuousCloseCount_ = 0;
    } else {
        continuousCloseCount_ = 0;
        continuousOpenCount_ = 0;
    }
    return false;
}

void TouchGestureDetector::AddGestureFingers(int32_t fingers)
{
    auto iter = fingers_.insert(fingers);
    if (!iter.second) {
        MMI_HILOGE("Insert finger failed, finger:%{public}d", fingers);
        return;
    }
    if (!fingers_.empty()) {
        gestureEnable_ = true;
        MMI_HILOGI("Start detection of touch-gesture(%{public}u)", gestureType_);
    }
}

void TouchGestureDetector::RemoveGestureFingers(int32_t fingers)
{
    auto iter = fingers_.find(fingers);
    if (iter != fingers_.end()) {
        fingers_.erase(iter);
    }
    if (fingers_.empty()) {
        MMI_HILOGI("Stop detection of touch-gesture(%{public}u)", gestureType_);
        gestureEnable_ = false;
        ReleaseData();
    }
}

void TouchGestureDetector::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    if ((gestureType_ == TOUCH_GESTURE_TYPE_PINCH) && isRecognized_ && !haveGestureWinEmerged_) {
        MMI_HILOGI("Gesture window of UNI-CUBIC emerges, redirect touches");
        haveGestureWinEmerged_ = true;
        OnGestureSendEvent(lastTouchEvent);
    }
}

bool TouchGestureDetector::IsMatchGesture(int32_t count) const
{
    return fingers_.find(count) != fingers_.end();
}

bool TouchGestureDetector::IsMatchGesture(GestureMode mode, int32_t count) const
{
    if (!IsMatchGesture(count) && !IsMatchGesture(ALL_FINGER_COUNT)) {
        return false;
    }
    switch (mode) {
        case GestureMode::ACTION_SWIPE_DOWN:
        case GestureMode::ACTION_SWIPE_UP:
        case GestureMode::ACTION_SWIPE_LEFT:
        case GestureMode::ACTION_SWIPE_RIGHT:
            return gestureType_ == TOUCH_GESTURE_TYPE_SWIPE;
        case GestureMode::ACTION_PINCH_OPENED:
        case GestureMode::ACTION_PINCH_CLOSED:
            return gestureType_ == TOUCH_GESTURE_TYPE_PINCH;
        case GestureMode::ACTION_GESTURE_END:
            return true;
        default:{
            MMI_HILOGW("Unknown mode:%{public}d", mode);
            return false;
        }
    }
}

bool TouchGestureDetector::NotifyGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode)
{
    CHKPF(event);
    CHKPF(listener_);
    if (!IsMatchGesture(mode, event->GetPointerCount())) {
        return false;
    }
    if (mode == GestureMode::ACTION_UNKNOWN) {
        MMI_HILOGE("Wrong gesture");
        return false;
    }
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        MMI_HILOGW("Handles only touchscreen events");
        return false;
    }
    if (!listener_->OnGestureEvent(event, mode)) {
        MMI_HILOGE("Failed to notify the gesture(%{public}d) event", mode);
        return false;
    }
    MMI_HILOGI("Gesture(%{public}d) identified successfully", mode);
    return true;
}

void TouchGestureDetector::CheckGestureTrend(std::shared_ptr<PointerEvent> event) const
{
    CHKPV(listener_);
    int32_t nMovements { 0 };

    for (const auto &[pointerId, downPt] : downPoint_) {
        PointerEvent::PointerItem item {};

        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGW("No touch(%{public}d) record", pointerId);
            return;
        }
        Point movePt { item.GetDisplayX(), item.GetDisplayY() };

        if (IsFingerMove(downPt, movePt)) {
            ++nMovements;
        }
    }
    if (nMovements >= THREE_FINGER_COUNT) {
        listener_->OnGestureTrend(event);
    }
}

bool TouchGestureDetector::IsLastTouchUp(std::shared_ptr<PointerEvent> event) const
{
    return ((event->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) &&
            (event->GetPointerIds().size() == SINGLE_TOUCH));
}

void TouchGestureDetector::OnGestureSendEvent(std::shared_ptr<PointerEvent> event) const
{
    CALL_INFO_TRACE;
    CHKPV(event);
    event->SetTargetWindowId(-1);
    auto pointerEvent = std::make_shared<PointerEvent>(*event);
    pointerEvent->RemoveAllPointerItems();
    auto items = event->GetAllPointerItems();
    for (auto &item : items) {
        if (!item.IsPressed()) {
            continue;
        }
        int32_t pointerId = item.GetPointerId();
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
        auto now = GetSysClockTime();
        pointerEvent->SetActionTime(now);
        pointerEvent->UpdateId();
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);

        item.SetTargetWindowId(-1);
        event->UpdatePointerItem(pointerId, item);
        pointerEvent->AddPointerItem(item);

        MMI_HILOGI("Redirect touch on transparent window of UNI-CUBIC, No:%{public}d, PI:%{public}d",
            pointerEvent->GetId(), pointerEvent->GetPointerId());
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPV(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleTouchEvent(pointerEvent);
    }
}

std::string TouchGestureDetector::DumpTouches() const
{
    std::ostringstream output;
    output << "[" << downPoint_.size() << "]";

    for (const auto &[id, downPt] : downPoint_) {
        output << "(" << id << "," << downPt.time << "," << downPt.x
               << "," << downPt.y << ")";
    }
    return std::move(output).str();
}
} // namespace MMI
} // namespace OHOS