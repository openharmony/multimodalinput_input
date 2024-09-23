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

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <unordered_set>

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureDetector"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ANGLE_PI = 180;

constexpr double ANGLE_RIGHT_DOWN = -45.0;
constexpr double ANGLE_RIGHT_UP = 45.0;
constexpr double ANGLE_LEFT_DOWN = -135.0;
constexpr double ANGLE_LEFT_UP = 135.0;

// gesture threshold values
constexpr int32_t MAXIMUM_SAME_DIRECTION_OFFSET = 1;
constexpr float MAXIMUM_POINTER_SPACING = 2000;
constexpr int64_t MAXIMUM_POINTER_INTERVAL = 100000;
constexpr double MAXIMUM_SINGLE_SLIDE_DISTANCE = 5;
constexpr double MINIMUM_GRAVITY_OFFSET = 0.5;
constexpr int32_t MAXIMUM_CONTINUOUS_COUNTS = 2;
constexpr int32_t MINIMUM_FINGER_COUNT_OFFSET = 1;
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
        case PointerEvent::POINTER_ACTION_UP: {
            HandleUpEvent(event);
            break;
        }
        default: {
            MMI_HILOGW("action:%{public}s is invalid", event->DumpPointerAction());
            break;
        }
    }
    return isRecognized_;
}

void TouchGestureDetector::HandleDownEvent(std::shared_ptr<PointerEvent> event)
{
    CALL_INFO_TRACE;
    CHKPV(event);
    int32_t pointerId = event->GetPointerId();
    if (isRecognized_) {
        MMI_HILOGW("The gestures begin, point down:%{public}d", pointerId);
        return;
    }
    PointerEvent::PointerItem item;
    if (!event->GetPointerItem(pointerId, item)) {
        MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
        return;
    }
    int32_t x = item.GetDisplayX();
    int32_t y = item.GetDisplayY();
    int64_t time = item.GetDownTime();
    auto iter = downPoint_.insert(std::make_pair(pointerId, Point(x, y, time)));
    if (!iter.second) {
        MMI_HILOGE("Insert value failed, duplicated pointerId:%{public}d", pointerId);
    }
    if (gestureType_ == TOUCH_GESTURE_TYPE_SWIPE) {
        isFingerReady_ = HandleFingerDown();
    } else if (gestureType_ == TOUCH_GESTURE_TYPE_PINCH) {
        CalcAndStoreDistance(downPoint_);
    }
    MMI_HILOGI("gestureType:%{public}d, finger count:%{public}zu, isFingerReady:%{public}s, "
        "pointerId:%{public}d, x:%{private}d, y:%{private}d",
        gestureType_, downPoint_.size(), isFingerReady_ ? "true" : "false", pointerId, x, y);
    movePoint_ = downPoint_;
}

void TouchGestureDetector::HandleMoveEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (isRecognized_) {
        return;
    }
    if (downPoint_.size() < THREE_FINGER_COUNT) {
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
}

void TouchGestureDetector::HandleSwipeMoveEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (!isFingerReady_) {
        return;
    }
    auto state = ClacFingerMoveDirection(event);
    if (state == TouchGestureDetector::SlideState::DIRECTION_UNKNOW) {
        return;
    }
    GestureMode type = ChangeToGestureMode(state);
    if (NotifyGestureEvent(event, type)) {
        isRecognized_ = true;
    }
}

void TouchGestureDetector::HandlePinchMoveEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (downPoint_.size() < FOUR_FINGER_COUNT || lastDistance_.empty()) {
        return;
    }
    std::map<int32_t, Point> movePoints;
    for (const auto &[pointerId, _] : downPoint_) {
        PointerEvent::PointerItem item;
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
            return;
        }
        int32_t x = item.GetDisplayX();
        int32_t y = item.GetDisplayY();
        int64_t time = item.GetDownTime();
        auto iter = movePoints.insert(std::make_pair(pointerId, Point(x, y, time)));
        if (!iter.second) {
            MMI_HILOGE("Insert value failed, duplicated pointerId:%{public}d", pointerId);
        }
    }
    if (CalcMultiFingerMovement(movePoints) >
        static_cast<int32_t>(downPoint_.size() - MINIMUM_FINGER_COUNT_OFFSET)) {
        movePoint_ = movePoints;
        GestureMode type = JudgeOperationMode(movePoints);
        isRecognized_ = AntiJitter(event, type);
    }
}

void TouchGestureDetector::HandleUpEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    int32_t pointerId = event->GetPointerId();
    auto iter = downPoint_.find(pointerId);
    if (iter == downPoint_.end()) {
        MMI_HILOGW("Invalid pointer: %{public}d", pointerId);
        return;
    }
    downPoint_.erase(iter);
    MMI_HILOGI("gestureType:%{public}d, finger count:%{public}zu, isFingerReady:%{public}s, pointerId:%{public}d",
        gestureType_, downPoint_.size(), isFingerReady_ ? "true" : "false", pointerId);
    if (downPoint_.empty()) {
        ReleaseData();
    }
}

void TouchGestureDetector::ReleaseData()
{
    CALL_INFO_TRACE;
    isRecognized_ = false;
    isFingerReady_ = false;
    haveLastDistance_ = false;
    continuousCloseCount_ = 0;
    continuousOpenCount_ = 0;
    lastDistance_.clear();
    downPoint_.clear();
    movePoint_.clear();
}

bool TouchGestureDetector::WhetherDiscardTouchEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPF(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return true;
    }
    if (!gestureEnable_) {
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
    if (downPoint_.size() < THREE_FINGER_COUNT) {
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

int64_t TouchGestureDetector::GetMaxDownInterval()
{
    int64_t earliestTime = INT64_MAX;
    int64_t latestTime = INT64_MIN;
    if (downPoint_.size() < THREE_FINGER_COUNT) {
        MMI_HILOGE("downPoint_ size(%{public}zu)", downPoint_.size());
        return latestTime - earliestTime;
    }

    for (const auto &point : downPoint_) {
        int64_t touchTime = point.second.time;
        if (touchTime > latestTime) {
            latestTime = touchTime;
        }
        if (touchTime < earliestTime) {
            earliestTime = touchTime;
        }
    }
    MMI_HILOGI("Down interval: %{public}" PRId64, (latestTime - earliestTime));
    return latestTime - earliestTime;
}

float TouchGestureDetector::GetMaxFingerSpacing()
{
    if (downPoint_.size() < THREE_FINGER_COUNT) {
        return 0.0f;
    }
    float maxSpacing = 0.0f;
    for (size_t i = 0; i < downPoint_.size(); ++i) {
        for (size_t j = i + 1; j < downPoint_.size(); ++j) {
            float pX = downPoint_[i].x;
            float pY = downPoint_[i].y;
            float nX = downPoint_[j].x;
            float nY = downPoint_[j].y;
            maxSpacing = std::max(maxSpacing, (float)hypot(pX - nX, pY - nY));
        }
    }
    MMI_HILOGI("Down max spacing: %{public}.2f", maxSpacing);
    return maxSpacing;
}

double TouchGestureDetector::GetAngle(float startX, float startY, float endX, float endY)
{
    return atan2((endY - startY), (endX - startX)) * (ANGLE_PI / M_PI);
}

bool TouchGestureDetector::IsFingerMove(float startX, float startY, float endX, float endY)
{
    return std::fabs(endX + endY - startX - startY) > FLT_EPSILON;
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
    auto state = TouchGestureDetector::SlideState::DIRECTION_UNKNOW;
    CHKPR(event, state);
    if (event->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
        return state;
    }
    if (downPoint_.size() < THREE_FINGER_COUNT) {
        return state;
    }
    int32_t recognizedCount = 0;
    std::unordered_set<TouchGestureDetector::SlideState> directions;
    for (const auto &dPoint : downPoint_) {
        int32_t pointerId = dPoint.first;
        Point point = dPoint.second;

        PointerEvent::PointerItem item;
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item:%{public}d fail", pointerId);
            return state;
        }
        int32_t x = item.GetDisplayX();
        int32_t y = item.GetDisplayY();
        double angle = GetAngle(point.x, point.y, x, y);
        bool isMove = IsFingerMove(point.x, point.y, x, y);
        MMI_HILOGI("pointerId:%{public}d,dx:%{private}.2f,dy:%{private}.2f,x:%{private}d,"
            "y:%{private}d,isMove:%{public}s", pointerId, point.x, point.y, x, y, isMove ? "true" : "false");
        if (fabs(angle) < FLT_EPSILON && !isMove) {
            continue;
        }
        auto direction = GetSlidingDirection(angle);
        if (direction != state) {
            directions.insert(direction);
            ++recognizedCount;
        }
        MMI_HILOGI("pointerId:%{public}d,angle:%{public}.2f,direction:%{public}d", pointerId, angle, direction);
    }
    if (recognizedCount < downPoint_.size() || directions.size() > MAXIMUM_SAME_DIRECTION_OFFSET) {
        return state;
    }
    return *(directions.begin());
}

double TouchGestureDetector::CalcTwoPointsDistance(const Point &p1, const Point &p2)
{
    return sqrt(fabs((p1.x - p2.x) * (p1.x - p2.x) + (p1.y - p2.y) * (p1.y - p2.y)));
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

void TouchGestureDetector::CalcAndStoreDistance(std::map<int32_t, Point> &points)
{
    if (downPoint_.size() < FOUR_FINGER_COUNT) {
        return;
    }
    int64_t interval = GetMaxDownInterval();
    if (interval > MAXIMUM_POINTER_INTERVAL) {
        haveLastDistance_ = false;
        MMI_HILOGE("The pointers down time interval is too long");
        return;
    }
    Point center = CalcGravityCenter(points);
    if (!lastDistance_.empty()) {
        lastDistance_.clear();
    }
    for (const auto &point : points) {
        int32_t pointerId = point.first;
        double distance = CalcTwoPointsDistance(center, point.second);
        lastDistance_.emplace(pointerId, distance);
    }
    haveLastDistance_ = true;
}

int32_t TouchGestureDetector::CalcMultiFingerMovement(std::map<int32_t, Point> &points)
{
    int32_t movementCount = 0;
    for (const auto &[id, point] : movePoint_) {
        auto movePoints = points.find(id);
        if (movePoints == points.end()) {
            return 0;
        }
        if (CalcTwoPointsDistance(point, movePoints->second) >= MAXIMUM_SINGLE_SLIDE_DISTANCE) {
            ++movementCount;
        }
    }
    return movementCount;
}

GestureMode TouchGestureDetector::JudgeOperationMode(std::map<int32_t, Point> &movePoints)
{
    GestureMode type = GestureMode::ACTION_UNKNOWN;
    if (downPoint_.size() < FOUR_FINGER_COUNT || !haveLastDistance_) {
        return type;
    }
    Point center = CalcGravityCenter(movePoints);
    std::map<int32_t, double> tempDistance;
    int32_t closeCount = 0;
    int32_t openCount = 0;
    for (const auto &[pointerId, _] : downPoint_) {
        auto movePointIter = movePoints.find(pointerId);
        if (movePointIter == movePoints.end()) {
            return type;
        }
        double currentDistance = CalcTwoPointsDistance(center, movePointIter->second);
        auto distanceIter = lastDistance_.find(pointerId);
        if (distanceIter == lastDistance_.end()) {
            return type;
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
        MMI_HILOGI("pointerId:%{public}d,lastDistance:%{public}.2f,"
            "currentDistance:%{public}.2f,closeCount:%{public}d,openCount:%{public}d",
            pointerId, lastDistance, currentDistance, closeCount, openCount);
    }

    if (!lastDistance_.empty()) {
        lastDistance_.clear();
        lastDistance_ = tempDistance;
    }
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
    }
}

void TouchGestureDetector::RemoveGestureFingers(int32_t fingers)
{
    auto iter = fingers_.find(fingers);
    if (iter != fingers_.end()) {
        fingers_.erase(iter);
    }
    if (fingers_.empty()) {
        gestureEnable_ = false;
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
} // namespace MMI
} // namespace OHOS