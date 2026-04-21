/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TOUCH_CONTROLLER_IMPL_H
#define TOUCH_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {

class TouchControllerImpl {
public:
    TouchControllerImpl();
    ~TouchControllerImpl();

    int32_t TouchDown(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY);
    int32_t TouchMove(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY);
    int32_t TouchUp(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY);

private:
    struct TouchContactState {
        int32_t displayId = -1;
        int32_t displayX = 0;
        int32_t displayY = 0;
        int64_t downTime = 0;
    };

    struct PointerEventContext {
        int32_t action = PointerEvent::POINTER_ACTION_UNKNOWN;
        int32_t touchId = -1;
        int32_t displayId = -1;
        int64_t actionTime = 0;
        bool currentPressed = false;
    };

    bool IsTouchIdValid(int32_t touchId) const;
    std::shared_ptr<PointerEvent> CreatePointerEvent(const PointerEventContext &context,
        const std::map<int32_t, TouchContactState> &contacts);
    void AddPointerItems(const std::shared_ptr<PointerEvent> &pointerEvent, const PointerEventContext &context,
        const std::map<int32_t, TouchContactState> &contacts) const;
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> &event);
    std::shared_ptr<PointerEvent> BuildTouchDownEvent(int32_t touchId, int32_t displayId, int32_t displayX,
        int32_t displayY, int64_t actionTime);
    std::shared_ptr<PointerEvent> BuildTouchMoveEvent(int32_t touchId, int32_t displayId, int32_t displayX,
        int32_t displayY, int64_t actionTime);
    std::shared_ptr<PointerEvent> BuildTouchUpEvent(int32_t touchId, int32_t displayId, int32_t displayX,
        int32_t displayY, int64_t actionTime);
    void CommitTouchDownState(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY,
        int64_t downTime);
    void CommitTouchMoveState(int32_t touchId, int32_t displayId, int32_t displayX, int32_t displayY);
    void ClearTouchState(int32_t touchId);

    std::map<int32_t, TouchContactState> activePoints_;
    int32_t activeDisplayId_ { -1 };
    mutable std::mutex injectMutex_;
    mutable std::mutex activePointsMutex_;
};

} // namespace MMI
} // namespace OHOS

#endif // TOUCH_CONTROLLER_IMPL_H
