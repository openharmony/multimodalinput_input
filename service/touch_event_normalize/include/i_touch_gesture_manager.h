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

#ifndef I_TOUCH_GESTURE_MANAGER_H
#define I_TOUCH_GESTURE_MANAGER_H

#include <memory>
#include <string>
#include <vector>

#include "input_handler_type.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class ITouchGestureManager {
public:
    ITouchGestureManager() = default;
    ITouchGestureManager(const ITouchGestureManager &other) = default;
    ITouchGestureManager(ITouchGestureManager &&other) = default;
    virtual ~ITouchGestureManager() = default;

    ITouchGestureManager& operator=(const ITouchGestureManager &other) = default;
    ITouchGestureManager& operator=(ITouchGestureManager &&other) = default;

    virtual bool DoesSupportGesture(TouchGestureType gestureType, int32_t nFingers) const = 0;
    virtual bool AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers) = 0;
    virtual void RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers) = 0;
    virtual bool HasHandler() const = 0;
    virtual void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent) = 0;
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) = 0;
    virtual void OnSessionLost(int32_t session) = 0;

protected:
    struct Handler {
        int32_t session_ { -1 };
        TouchGestureType gesture_ { TOUCH_GESTURE_TYPE_NONE };
        int32_t nFingers_ {};

        bool operator<(const Handler &other) const
        {
            if (session_ != other.session_) {
                return (session_ < other.session_);
            }
            if (gesture_ != other.gesture_) {
                return (gesture_ < other.gesture_);
            }
            return (nFingers_ < other.nFingers_);
        }
    };
};
} // namespace MMI
} // namespace OHOS
#endif // I_TOUCH_GESTURE_MANAGER_H
