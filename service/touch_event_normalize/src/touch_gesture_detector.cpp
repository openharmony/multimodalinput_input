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
constexpr int32_t FOUR_FINGER_COUNT = 4;
constexpr int32_t THREE_FINGER_COUNT = 3;
constexpr int32_t ANGLE_PI = 180;

constexpr double ANGLE_RIGHT_DOWN = -45.0;
constexpr double ANGLE_RIGHT_UP = 45.0;
constexpr double ANGLE_LEFT_DOWN = -135.0;
constexpr double ANGLE_LEFT_UP = 135.0;

// gesture threshold values
constexpr int32_t MAXIMUM_SAME_DIRECTION_OFFSET = 1;
constexpr float MAXIMUM_POINTER_SPACING = 800;
constexpr int64_t MAXIMUM_POINTER_INTERVAL = 100000;
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
    if (getureType_ == SwipeAdapterType) {
        isFingerReady_ = HandleFingerDown();
    }
    MMI_HILOGI("getureType:%{public}d, finger count:%{public}zu, isFingerReady:%{public}s, "
        "pointerId:%{public}d, x:%{private}d, y:%{private}d",
        getureType_, downPoint_.size(), isFingerReady_ ? "true" : "false", pointerId, x, y);
}

void TouchGestureDetector::HandleMoveEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (isRecognized_) {
        return;
    }
    if (getureType_ == SwipeAdapterType) {
        HandleSwipeMoveEvent(event);
    }
}

void TouchGestureDetector::HandleSwipeMoveEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (downPoint_.size() < THREE_FINGER_COUNT || !isFingerReady_) {
        return;
    }
    auto state = ClacFingerMoveDirection(event);
    if (state == TouchGestureDetector::SlideState::DIRECTION_UNKNOW) {
        return;
    }
    GetureType type = ChangeToGetureType(state);
    if (NotifyGestureEvent(event, type)) {
        isRecognized_ = true;
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
    if (downPoint_.empty()) {
        ReleaseData();
    }
}

void TouchGestureDetector::ReleaseData()
{
    CALL_INFO_TRACE;
    isRecognized_ = false;
    isFingerReady_ = false;
    downPoint_.clear();
}

bool TouchGestureDetector::WhetherDiscardTouchEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPF(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return true;
    }
    if (!gestureEnable_) {
        MMI_HILOGE("enable is false, discards touch event");
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
    int32_t fingersCount = downPoint_.size();
    if (fingersCount < THREE_FINGER_COUNT) {
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

GetureType TouchGestureDetector::ChangeToGetureType(TouchGestureDetector::SlideState state)
{
    switch (state) {
        case TouchGestureDetector::SlideState::DIRECTION_UP: {
            return GetureType::ACTION_SWIPE_UP;
        }
        case TouchGestureDetector::SlideState::DIRECTION_DOWN: {
            return GetureType::ACTION_SWIPE_DOWN;
        }
        case TouchGestureDetector::SlideState::DIRECTION_LEFT: {
            return GetureType::ACTION_SWIPE_LEFT;
        }
        case TouchGestureDetector::SlideState::DIRECTION_RIGHT: {
            return GetureType::ACTION_SWIPE_RIGHT;
        }
        default: {
            MMI_HILOGW("unknow state, state:%{public}d", state);
            return GetureType::ACTION_UNKNOW;
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
        MMI_HILOGI("pointerId: %{public}d, point.x:%{private}.2f, point.y:%{private}.2f, x:%{private}d,"
            "y:%{private}d, isMove:%{public}s", pointerId, point.x, point.y, x, y, isMove ? "true" : "false");
        if (fabs(angle) < FLT_EPSILON && !isMove) {
            continue;
        }
        auto direction = GetSlidingDirection(angle);
        if (direction != state) {
            directions.insert(direction);
            ++recognizedCount;
        }
        MMI_HILOGI("pointerId: %{public}d, angle: %{public}.2f, direction: %{public}d", pointerId, angle, direction);
    }
    if (recognizedCount < THREE_FINGER_COUNT || directions.size() > MAXIMUM_SAME_DIRECTION_OFFSET) {
        return state;
    }
    return *(directions.begin());
}

bool TouchGestureDetector::NotifyGestureEvent(std::shared_ptr<PointerEvent> event, GetureType mode)
{
    CHKPF(event);
    CHKPF(listener_);
    if (mode == GetureType::ACTION_UNKNOW) {
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
    return true;
}
} // namespace MMI
} // namespace OHOS