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

#ifndef TOUCH_GESTURE_MANAGER_H
#define TOUCH_GESTURE_MANAGER_H

#include <memory>

#include <nocopyable.h>

#include "delegate_interface.h"
#include "touch_gesture_adapter.h"

namespace OHOS {
namespace MMI {
class TouchGestureManager final {
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

public:
    TouchGestureManager(std::shared_ptr<DelegateInterface> delegate);
    ~TouchGestureManager();
    DISALLOW_COPY_AND_MOVE(TouchGestureManager);

    void AddHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers);
    void RemoveHandler(int32_t session, TouchGestureType gestureType, int32_t nFingers);
    void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent);

private:
    void StartRecognization(TouchGestureType gestureType, int32_t nFingers);
    void StopRecognization(TouchGestureType gestureType, int32_t nFingers);
    void RemoveAllHandlers();
    void SetupSessionObserver();
    void OnSessionLost(int32_t session);

    std::weak_ptr<DelegateInterface> delegate_;
    std::shared_ptr<TouchGestureAdapter> touchGesture_;
    std::set<Handler> handlers_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_MANAGER_H