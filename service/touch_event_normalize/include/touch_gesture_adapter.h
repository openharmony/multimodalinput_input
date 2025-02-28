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

#ifndef TOUCH_GESTURE_ADAPTER_H
#define TOUCH_GESTURE_ADAPTER_H

#include "touch_gesture_detector.h"

namespace OHOS {
namespace MMI {
class TouchGestureAdapter final :
    public TouchGestureDetector::GestureListener,
    public std::enable_shared_from_this<TouchGestureAdapter> {
public:
    TouchGestureAdapter(TouchGestureType type, std::shared_ptr<TouchGestureAdapter> next);
    static std::shared_ptr<TouchGestureAdapter> GetGestureFactory();
    void process(std::shared_ptr<PointerEvent> event);
    void SetGestureCondition(bool flag, TouchGestureType type, int32_t fingers);
    void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent);

private:
    enum class GestureState {
        IDLE,
        SWIPE,
        PINCH,
    };

    struct TouchItem {
        bool cancelled_ { false };
    };

    inline bool ShouldDeliverToNext() const
    {
        return shouldDeliverToNext_;
    }
    void Init();
    void OnTouchEvent(std::shared_ptr<PointerEvent> event);
    void OnSwipeGesture(std::shared_ptr<PointerEvent> event);
    void OnPinchGesture(std::shared_ptr<PointerEvent> event);
    bool OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode) override;
    void OnGestureTrend(std::shared_ptr<PointerEvent> event) override;

private:
    bool gestureStarted_ { false };
    bool shouldDeliverToNext_ { true };
    TouchGestureType gestureType_ { TOUCH_GESTURE_TYPE_NONE };
    inline static GestureState state_ { GestureState::IDLE };
    std::shared_ptr<TouchGestureDetector> gestureDetector_ { nullptr };
    std::shared_ptr<TouchGestureAdapter> nextAdapter_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_ADAPTER_H