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

#include "pull_throw_subscriber_handler.h"

#include <parameters.h>

#include "app_mgr_client.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "key_command_handler.h"
#include "key_command_handler_util.h"
#include "net_packet.h"
#include "proto.h"
#include "running_process_info.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PullThrowSubscriberHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ONE_FINGER { 1 };
constexpr int32_t TWO_FINGER { 2 };
constexpr int32_t DEFAULT_USER_ID { 100 };
constexpr int32_t PX_BASE { 160 };
constexpr int32_t MS_TO_US { 1000 };

}

PullThrowSubscriberHandler::PullThrowSubscriberHandler() {}

PullThrowSubscriberHandler::~PullThrowSubscriberHandler() {}

void PullThrowSubscriberHandler::HandleFingerGestureDownEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!CheckFingerValidation(touchEvent)) {
        return;
    }
    UpdateFingerPoisition(touchEvent);
    MMI_HILOGI("PullThrow Check On Finger Down Event");
    alreadyTouchDown_ = true;
    StartFingerGesture();
}

void PullThrowSubscriberHandler::HandleFingerGestureMoveEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!CheckProgressValid(touchEvent)) {
        return;
    }
}

void PullThrowSubscriberHandler::HandleFingerGesturePullMoveEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (!CheckProgressValid(touchEvent)) {
        return;
    }
    if (gestureInProgress_ && alreadyTouchDown_) {
        triggerTime_ = touchEvent->GetActionTime();
        alreadyTouchDown_ = false;
        UpdateFingerPoisition(touchEvent);
    }
    if (gestureInProgress_ && (touchEvent->GetActionTime() - triggerTime_ > WINDOW_TIME_INTERVAL)) {
        triggerTime_ = touchEvent->GetActionTime();
        UpdateFingerPoisition(touchEvent);
    }
}


void PullThrowSubscriberHandler::HandleFingerGesturePullUpEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    MMI_HILOGI("PullThrow On PullUp Event");
    if (!CheckProgressValid(touchEvent)) {
        return;
    }
    // Update the last position point for calculating acceleration
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    UpdatePositionHistory(item.GetDisplayX(), item.GetDisplayY(), touchEvent->GetActionTime());
    if (gestureInProgress_) {
        MMI_HILOGI("PullThrow On gestureInProgress");
        double endTime = touchEvent->GetActionTime();
        // Calcultating distance
        double dx = item.GetDisplayX() - fingerGesture_.touches[FIRST_TOUCH_FINGER].x;
        double dy = item.GetDisplayY() - fingerGesture_.touches[FIRST_TOUCH_FINGER].y;
        double distance = std::sqrt(dx * dx + dy * dy);
        double deltaTime = (endTime - triggerTime_) / 1e3;
        if (deltaTime <= 0) {
            deltaTime = 1.0 / 1e3;
        }
        double speed = distance / deltaTime;
        // provide a speed scale to improve success rate in spin area
        if (item.GetDisplayY() > SPIN_UP_AREA_Y && item.GetDisplayY() < SPIN_DOWN_AREA_Y) {
            speed = speed * SPEED_SCALE;
        }
        double throwAngle = atan2(dy, dx) * 180 / M_PI;
        MMI_HILOGI("Throw speed: %{public}f, angle: %{public}f, dist: %{public}f", speed, throwAngle, distance);
        // check sudden stop
        bool hasSuddenStop = CheckSuddenStop();
        if (hasSuddenStop) {
            MMI_HILOGI("PullThrow detected sudden stop");
            StopFingerGesture(touchEvent);
            return;
        }
        // check pull throw condition: speed, distance, direction
        if (speed > THRES_SPEED && distance > MIN_THRES_DIST && CheckThrowDirection(throwAngle, item.GetDisplayY())) {
            touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_THROW);
            touchEvent->SetThrowAngle(throwAngle);
            touchEvent->SetThrowSpeed(speed);
            MMI_HILOGI("PullThrow SUCCESS match gesture result");
        } else {
            MMI_HILOGI("PullThrow NO match gesture result");
        }
    }
    StopFingerGesture(touchEvent);
}

void PullThrowSubscriberHandler::HandleFingerGestureUpEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    MMI_HILOGI("PullThrow Stop On Gesture Up Event");
    StopFingerGesture(touchEvent);
}

void PullThrowSubscriberHandler::UpdateFingerPoisition(std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    fingerGesture_.touches[FIRST_TOUCH_FINGER].id = id;
    fingerGesture_.touches[FIRST_TOUCH_FINGER].x = item.GetDisplayX();
    fingerGesture_.touches[FIRST_TOUCH_FINGER].y = item.GetDisplayY();
    
    UpdatePositionHistory(item.GetDisplayX(), item.GetDisplayY(), touchEvent->GetActionTime());
}

bool PullThrowSubscriberHandler::CheckFingerValidation(std::shared_ptr<PointerEvent> touchEvent) const
{
    auto fingerCount = touchEvent->GetPointerIds().size();
    if (fingerCount != static_cast<size_t>(ONE_FINGER)) {
        MMI_HILOGD("PullThrow check cancel: The number of finger count is not 1");
        return false;
    }
    return true;
}

bool PullThrowSubscriberHandler::CheckProgressValid(std::shared_ptr<PointerEvent> touchEvent)
{
    if (touchEvent->HasFlag(InputEvent::EVENT_FLAG_DISABLE_PULL_THROW)) {
        StopFingerGesture(touchEvent);
        return false;
    }
    if (gestureInProgress_ && !CheckFingerValidation(touchEvent)) {
        StopFingerGesture(touchEvent);
        return false;
    }
    return true;
}

bool PullThrowSubscriberHandler::CheckThrowDirection(double angle, int32_t posY)
{
    angle = (angle < NUM_EPSILON) ? angle + FULL_CIRCLE_DEGREES : angle;
    if (posY < UP_SCREEN_AREA_Y && angle >= ANGLE_DOWN_MIN && angle < ANGLE_DOWN_MAX) {
        return true;
    }
    if (posY > DOWN_SCREEN_AREA_Y && angle >= ANGLE_UP_MIN && angle < ANGLE_UP_MAX) {
        return true;
    }
    return false;
}

bool PullThrowSubscriberHandler::CheckThrowAngleValid(double angle)
{
    angle = (angle < NUM_EPSILON) ? angle + FULL_CIRCLE_DEGREES : angle;
    if (angle >= ANGLE_DOWN_MIN && angle < ANGLE_DOWN_MAX) {
        return true;
    }
    if (angle >= ANGLE_UP_MIN && angle < ANGLE_UP_MAX) {
        return true;
    }
    return false;
}

void PullThrowSubscriberHandler::StartFingerGesture()
{
    CALL_DEBUG_ENTER;
    gestureInProgress_ = true;
    positionHistory_.clear();
}

void PullThrowSubscriberHandler::StopFingerGesture(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    gestureInProgress_ = false;
    alreadyTouchDown_ = false;
    triggerTime_ = touchEvent->GetActionTime();
    positionHistory_.clear();
}

void PullThrowSubscriberHandler::UpdatePositionHistory(double x, double y, double time)
{
    PositionRecord record;
    record.x = x;
    record.y = y;
    record.time = time;
    
    positionHistory_.push_back(record);
    if (positionHistory_.size() > MAX_HISTORY_SIZE) {
        positionHistory_.erase(positionHistory_.begin());
    }
}

bool PullThrowSubscriberHandler::CheckSuddenStop() const
{
    if (positionHistory_.size() < MIN_HISTORY_SIZE) {
        MMI_HILOGI("PullThrow position history size less than 3");
        return false;
    }
    
    // 计算最近两段的速度
    const auto& newest = positionHistory_.back();
    const auto& middle = positionHistory_[positionHistory_.size() - 2];
    const auto& oldest = positionHistory_[positionHistory_.size() - 3];
    
    // 计算位移和时间差
    double dx1 = middle.x - oldest.x;
    double dy1 = middle.y - oldest.y;
    double dt1 = (middle.time - oldest.time) / 1e3;
    
    double dx2 = newest.x - middle.x;
    double dy2 = newest.y - middle.y;
    double dt2 = (newest.time - middle.time) / 1e3;
    
    // 防止除以零
    if (dt1 <= 0) dt1 = NUM_EPSILON;
    if (dt2 <= 0) dt2 = NUM_EPSILON;
    
    // 计算速度（矢量长度）
    double speed1 = std::sqrt(dx1 * dx1 + dy1 * dy1) / dt1;
    double speed2 = std::sqrt(dx2 * dx2 + dy2 * dy2) / dt2;
    
    // 计算加速度（速度变化率）
    double timeSpace = (dt1 + dt2) / 2;
    if (timeSpace <= 0) timeSpace = NUM_EPSILON;
    double acceleration = (speed2 - speed1) / timeSpace;
    
    // 如果加速度为负且绝对值大于阈值，说明有急停动作
    return (acceleration < MAX_DECELERATION);
}

} // namespace MMI
} // namespace OHOS
