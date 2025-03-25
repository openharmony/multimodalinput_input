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
    if (CheckFingerValidation(touchEvent)) {
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
    if (CheckProgressValid(touchEvent)) {
        return;
    }
}

void PullThrowSubscriberHandler::HandleFingerGesturePullMoveEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (CheckProgressValid(touchEvent)) {
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
    if (CheckProgressValid(touchEvent)) {
        return;
    }
    if (gestureInProgress_) {
        MMI_HILOGI("PullThrow On gestureInProgress");
        double endTime = touchEvent->GetActionTime();
        // 计算距离
        int32_t id = touchEvent->GetPointerId();
        PointerEvent::PointerItem item;
        touchEvent->GetPointerItem(id, item);
        double dx = item.GetDisplayX() - fingerGesture_.touches[FIRST_TOUCH_FINGER].x;
        double dy = item.GetDisplayY() - fingerGesture_.touches[FIRST_TOUCH_FINGER].y;
        double distance = std::sqrt(dx * dx + dy * dy);
        // 计算时间差，转换为秒
        double deltaTime = (endTime - triggerTime_) / 1e3; // 如果时间戳是毫秒
        if (deltaTime <= 0) {
            deltaTime = 1.0 / 1e3; // 设置最小时间差，防止除以0
        }
        // 计算速度
        double speed = distance / deltaTime;
        double throwAngle = atan2(dy, dx) * 180 / M_PI;
        MMI_HILOGI("Throw speed: %{public}lf, angle: %{public}lf, dist: %{public}lf", speed, throwAngle, distance);
        // 检查速度距离是否大于阈值
        if (speed > THRES_SPEED && distance > MIN_THRES_DIST) {
            // 判断方向
            touchEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_THROW);
            touchEvent->SetThrowAngle(atan2(dy, dx) * 180 / M_PI); // 180:弧度转化为角度
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
}

bool PullThrowSubscriberHandler::CheckFingerValidation(std::shared_ptr<PointerEvent> touchEvent) const
{
    auto fingerCount = touchEvent->GetPointerIds().size();
    if (fingerCount != static_cast<size_t>(ONE_FINGER)) {
        MMI_HILOGD("PullThrow check cancel: The number of finger count is not 1");
        return true;
    }
    return false;
}

bool PullThrowSubscriberHandler::CheckProgressValid(std::shared_ptr<PointerEvent> touchEvent)
{
    if (gestureInProgress_ && CheckFingerValidation(touchEvent)) {
        StopFingerGesture(touchEvent);
        return true;
    }
    return false;
}

void PullThrowSubscriberHandler::StartFingerGesture()
{
    CALL_DEBUG_ENTER;
    gestureInProgress_ = true;
}

void PullThrowSubscriberHandler::StopFingerGesture(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    gestureInProgress_ = false;
    alreadyTouchDown_ = false;
    triggerTime_ = touchEvent->GetActionTime();
}
} // namespace MMI
} // namespace OHOS
