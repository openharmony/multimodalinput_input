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

#include "pointer_event.h"

#include "gesture_monitor_handler.h"

namespace OHOS {
namespace MMI {
GestureMonitorHandler::GestureMonitorHandler(const GestureMonitorHandler &other)
    : fingers_(other.fingers_), gestureType_(other.gestureType_), touchGestureInfo_(other.touchGestureInfo_)
{}

GestureMonitorHandler& GestureMonitorHandler::operator=(const GestureMonitorHandler &other)
{
    gestureType_ = other.gestureType_;
    fingers_ = other.fingers_;
    touchGestureInfo_ = other.touchGestureInfo_;
    return *this;
}

bool GestureMonitorHandler::CheckMonitorValid(TouchGestureType type, int32_t fingers)
{
    if (type == TOUCH_GESTURE_TYPE_NONE ||
        (TOUCH_GESTURE_TYPE_ALL & type) != type) {
        return false;
    }
    TouchGestureType ret = TOUCH_GESTURE_TYPE_NONE;
    if (fingers == ALL_FINGER_COUNT) {
        return true;
    }
    if (((type & TOUCH_GESTURE_TYPE_SWIPE) == TOUCH_GESTURE_TYPE_SWIPE) &&
        (THREE_FINGER_COUNT <= fingers && fingers <= MAX_FINGERS_COUNT)) {
        ret = TOUCH_GESTURE_TYPE_SWIPE;
    } else if (((type & TOUCH_GESTURE_TYPE_PINCH) == TOUCH_GESTURE_TYPE_PINCH) &&
        (FOUR_FINGER_COUNT <= fingers && fingers <= MAX_FINGERS_COUNT)) {
        ret = TOUCH_GESTURE_TYPE_PINCH;
    }
    if (ret != TOUCH_GESTURE_TYPE_NONE) {
        if ((type = type ^ ret) != TOUCH_GESTURE_TYPE_NONE) {
            return CheckMonitorValid(type, fingers);
        }
    } else {
        return false;
    }
    return true;
}

bool GestureMonitorHandler::IsTouchGestureEvent(int32_t pointerAction)
{
    switch (pointerAction) {
        case PointerEvent::TOUCH_ACTION_SWIPE_DOWN:
        case PointerEvent::TOUCH_ACTION_SWIPE_UP:
        case PointerEvent::TOUCH_ACTION_SWIPE_RIGHT:
        case PointerEvent::TOUCH_ACTION_SWIPE_LEFT:
        case PointerEvent::TOUCH_ACTION_PINCH_OPENED:
        case PointerEvent::TOUCH_ACTION_PINCH_CLOSEED:
        case PointerEvent::TOUCH_ACTION_GESTURE_END: {
            return true;
        }
        default: {
            return false;
        }
    }
}

bool GestureMonitorHandler::IsMatchGesture(int32_t action, int32_t count) const
{
    TouchGestureType type = TOUCH_GESTURE_TYPE_NONE;
    switch (action) {
        case PointerEvent::TOUCH_ACTION_SWIPE_DOWN:
        case PointerEvent::TOUCH_ACTION_SWIPE_UP:
        case PointerEvent::TOUCH_ACTION_SWIPE_RIGHT:
        case PointerEvent::TOUCH_ACTION_SWIPE_LEFT:
            type = TOUCH_GESTURE_TYPE_SWIPE;
            break;
        case PointerEvent::TOUCH_ACTION_PINCH_OPENED:
        case PointerEvent::TOUCH_ACTION_PINCH_CLOSEED:
            type = TOUCH_GESTURE_TYPE_PINCH;
            break;
        case PointerEvent::TOUCH_ACTION_GESTURE_END:
            return true;
        default:
            return false;
    }
    auto iter = touchGestureInfo_.find(type);
    if (iter == touchGestureInfo_.end()) {
        iter = touchGestureInfo_.find(TOUCH_GESTURE_TYPE_ALL);
        if (iter == touchGestureInfo_.end()) {
            return false;
        }
    }
    const std::set<int32_t> &info = iter->second;
    return ((gestureType_ & type) == type) &&
        (info.find(count) != info.end() || info.find(ALL_FINGER_COUNT) != info.end());
}

void GestureMonitorHandler::AddGestureMonitor(TouchGestureType type, int32_t fingers)
{
    if (type == TOUCH_GESTURE_TYPE_NONE) {
        return;
    }
    fingers_ = fingers;
    gestureType_ = gestureType_ | type;
    auto iter = touchGestureInfo_.find(type);
    if (iter == touchGestureInfo_.end()) {
        touchGestureInfo_.insert({type, { fingers }});
        return;
    }
    iter->second.insert(fingers);
}

bool GestureMonitorHandler::RemoveGestureMonitor(TouchGestureType type, int32_t fingers)
{
    auto iter = touchGestureInfo_.find(type);
    if (iter == touchGestureInfo_.end()) {
        return false;
    }
    std::set<int32_t> &info = iter->second;
    auto it = info.find(fingers);
    if (it == info.end()) {
        return false;
    }
    info.erase(it);
    if (info.empty()) {
        if (touchGestureInfo_.find(TOUCH_GESTURE_TYPE_ALL) == touchGestureInfo_.end()) {
            gestureType_ = gestureType_ ^ type;
        }
        touchGestureInfo_.erase(iter);
    }
    return touchGestureInfo_.empty();
}
} // namespace MMI
} // namespace OHOS