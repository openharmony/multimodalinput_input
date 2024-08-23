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
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureAdapter"

namespace OHOS {
namespace MMI {
TouchGestureAdapter::TouchGestureAdapter(AdapterType type, std::shared_ptr<TouchGestureAdapter> next)
    : getureType_(type), nextAdapter_(next)
{}

void TouchGestureAdapter::SetGestureEnable(bool isEnable)
{
    if (gestureDetector_ != nullptr) {
        gestureDetector_->SetGestureEnable(isEnable);
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->SetGestureEnable(isEnable);
    }
}

void TouchGestureAdapter::process(std::shared_ptr<PointerEvent> event)
{
    OnTouchEvent(event);
    if (ShouldDeliverToNext() && nextAdapter_ != nullptr) {
        nextAdapter_->process(event);
    }
}

void TouchGestureAdapter::Init()
{
    if (gestureDetector_ == nullptr) {
        gestureDetector_ = std::make_shared<TouchGestureDetector>(getureType_, shared_from_this());
    }
    if (nextAdapter_ != nullptr) {
        nextAdapter_->Init();
    }
}

std::shared_ptr<TouchGestureAdapter> TouchGestureAdapter::GetGestureFactory()
{
    std::shared_ptr<TouchGestureAdapter> pinch =
        std::make_shared<TouchGestureAdapter>(PinchAdapterType, nullptr);
    std::shared_ptr<TouchGestureAdapter> swipe =
        std::make_shared<TouchGestureAdapter>(SwipeAdapterType, pinch);
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
    int32_t action = event->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_DOWN ||
        action == PointerEvent::POINTER_ACTION_UP) {
        hasCancel_ = false;
    }
    shouldDeliverToNext_ = true;
    if (!gestureStarted_ && action == PointerEvent::POINTER_ACTION_UP) {
        gestureDetector_->OnTouchEvent(event);
        return;
    }
    if (getureType_ == SwipeAdapterType) {
        OnSwipeGesture(event);
    } else if (getureType_ == PinchAdapterType) {
        OnPinchGesture(event);
    }

    if (!hasCancel_ && state_ != GestureState::IDLE &&
        action != PointerEvent::POINTER_ACTION_UP) {
        hasCancel_ = true;
        OnGestureSuccessful(event);
    }
    if (gestureStarted_ && action == PointerEvent::POINTER_ACTION_MOVE) {
        shouldDeliverToNext_ = false;
    }
}

void TouchGestureAdapter::OnGestureSuccessful(std::shared_ptr<PointerEvent> event)
{
    CALL_INFO_TRACE;
    CHKPV(event);
    auto items = event->GetAllPointerItems();
    for (const auto &item : items) {
        if (!item.IsPressed()) {
            continue;
        }
        int32_t pointerId = item.GetPointerId();
        auto pointerEvent = std::make_shared<PointerEvent>(*event);
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        pointerEvent->SetActionTime(GetSysClockTime());
        pointerEvent->UpdateId();
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
        auto eventDispatchHandler = InputHandler->GetEventDispatchHandler();
        CHKPV(eventDispatchHandler);
        eventDispatchHandler->HandlePointerEvent(pointerEvent);
    }
}

void TouchGestureAdapter::OnSwipeGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if (state_ == GestureState::PINCH) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::SWIPE : GestureState::IDLE;
}

void TouchGestureAdapter::OnPinchGesture(std::shared_ptr<PointerEvent> event)
{
    CHKPV(gestureDetector_);
    if (state_ == GestureState::SWIPE) {
        return;
    }
    gestureStarted_ = gestureDetector_->OnTouchEvent(event);
    state_ = gestureStarted_ ? GestureState::PINCH : GestureState::IDLE;
}

bool TouchGestureAdapter::OnGestureEvent(std::shared_ptr<PointerEvent> event, GetureType mode)
{
#ifdef OHOS_BUILD_ENABLE_MONITOR
    auto pointEvent = std::make_shared<PointerEvent>(*event);
    pointEvent->SetHandlerEventType(HANDLE_EVENT_TYPE_TOUCH_GESTURE);
    switch (mode) {
        case GetureType::ACTION_SWIPE_DOWN:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_DOWN);
            break;
        case GetureType::ACTION_SWIPE_UP:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_UP);
            break;
        case GetureType::ACTION_SWIPE_LEFT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_LEFT);
            break;
        case GetureType::ACTION_SWIPE_RIGHT:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_SWIPE_RIGHT);
            break;
        case GetureType::ACTION_PINCH_CLOSED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_CLOSEED);
            break;
        case GetureType::ACTION_PINCH_OPENED:
            pointEvent->SetPointerAction(PointerEvent::TOUCH_ACTION_PINCH_OPENED);
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
} // namespace MMI
} // namespace OHOS