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

#include "touch_gesture_adapter.h"

#include "input_event_handler.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureAdapter"

namespace OHOS {
namespace MMI {
TouchGestureAdapter::TouchGestureAdapter(TouchGestureType type, std::shared_ptr<TouchGestureAdapter> next)
    : gestureType_(type), nextAdapter_(next)
{}

void TouchGestureAdapter::SetGestureCondition(bool flag, TouchGestureType type, int32_t fingers)
{
    if ((gestureDetector_ != nullptr) && ((type & gestureType_) == gestureType_)) {
        if (flag) {
            gestureDetector_->AddGestureFingers(fingers);
        } else {
            gestureDetector_->RemoveGestureFingers(fingers);
        }
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->SetGestureCondition(flag, type, fingers);
    }
}

void TouchGestureAdapter::process(std::shared_ptr<PointerEvent> event)
{
    LogTouchEvent(event);
    OnTouchEvent(event);
    if (ShouldDeliverToNext() && nextAdapter_ != nullptr) {
        nextAdapter_->process(event);
    }
}

void TouchGestureAdapter::HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent)
{
    if (gestureDetector_ != nullptr) {
        gestureDetector_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->HandleGestureWindowEmerged(windowId, lastTouchEvent);
    }
}

void TouchGestureAdapter::Init()
{
    if (gestureDetector_ == nullptr) {
        gestureDetector_ = std::make_shared<TouchGestureDetector>(gestureType_, shared_from_this());
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->Init();
    }
}

void TouchGestureAdapter::LogTouchEvent(std::shared_ptr<PointerEvent> event) const
{
    CHKPV(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return;
    }
    switch (event->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_DOWN:
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            break;
        }
        default: {
            return;
        }
    }
    auto pointers = event->GetPointerIds();
    std::ostringstream sTouches;
    sTouches << "(";

    if (auto iter = pointers.cbegin(); iter != pointers.cend()) {
        sTouches << *iter;
        for (++iter; iter != pointers.cend(); ++iter) {
            sTouches << "," << *iter;
        }
    }
    sTouches << ")";
    MMI_HILOGI("GestureType:%{public}u,No:%{public}d,PA:%{public}s,PI:%{public}d,Touches:%{public}s",
        gestureType_, event->GetId(), event->DumpPointerAction(), event->GetPointerId(),
        std::move(sTouches).str().c_str());
}

std::shared_ptr<TouchGestureAdapter> TouchGestureAdapter::GetGestureFactory()
{
    std::shared_ptr<TouchGestureAdapter> pinch =
        std::make_shared<TouchGestureAdapter>(TOUCH_GESTURE_TYPE_PINCH, nullptr);
    std::shared_ptr<TouchGestureAdapter> swipe =
        std::make_shared<TouchGestureAdapter>(TOUCH_GESTURE_TYPE_SWIPE, pinch);
    swipe->Init();
    return swipe;
}

void TouchGestureAdapter::OnTouchEvent(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    CHKPV(gestureDetector_);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return;
    }
    shouldDeliverToNext_ = true;

    if (gestureType_ == TOUCH_GESTURE_TYPE_SWIPE) {
        OnSwipeGesture(event);
    } else if (gestureType_ == TOUCH_GESTURE_TYPE_PINCH) {
        OnPinchGesture(event);
    }
    if (gestureStarted_ && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        shouldDeliverToNext_ = false;
    }
}

void TouchGestureAdapter::OnSwipeGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if ((state_ == GestureState::PINCH) && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::SWIPE : GestureState::IDLE;
}

void TouchGestureAdapter::OnPinchGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if ((state_ == GestureState::SWIPE) && (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE)) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::PINCH : GestureState::IDLE;
}

bool TouchGestureAdapter::OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode)
{
#ifdef OHOS_BUILD_ENABLE_MONITOR
    auto pointEvent = std::make_shared<PointerEvent>(*event);
    pointEvent->UpdateId();
    pointEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_TOUCH_GESTURE);
    switch (mode) {
        case GestureMode::ACTION_SWIPE_DOWN:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_DOWN);
            break;
        case GestureMode::ACTION_SWIPE_UP:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_UP);
            break;
        case GestureMode::ACTION_SWIPE_LEFT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_LEFT);
            break;
        case GestureMode::ACTION_SWIPE_RIGHT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_RIGHT);
            break;
        case GestureMode::ACTION_PINCH_CLOSED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_CLOSEED);
            break;
        case GestureMode::ACTION_PINCH_OPENED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_OPENED);
            break;
        case GestureMode::ACTION_GESTURE_END:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_GESTURE_END);
            break;
        default:
            MMI_HILOGW("unknow mode:%{public}d", mode);
            return false;
    }
    auto monitor = InputHandler->GetMonitorHandler();
    CHKPF(monitor);
    monitor->HandlePointerEvent(pointEvent);
#endif // OHOS_BUILD_ENABLE_MONITOR
    return true;
}

void TouchGestureAdapter::OnGestureTrend(std::shared_ptr<PointerEvent> event)
{
    WIN_MGR->CancelAllTouches(event);
}
} // namespace MMI
} // namespace OHOS