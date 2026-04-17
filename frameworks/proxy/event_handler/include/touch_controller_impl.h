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

    bool IsTouchIdValid(int32_t touchId) const;
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action, int32_t touchId, int32_t displayId,
        int64_t actionTime, const std::map<int32_t, TouchContactState> &contacts, bool currentPressed);
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> &event);

    std::map<int32_t, TouchContactState> activePoints_;
    int32_t activeDisplayId_ { -1 };
    mutable std::mutex sendMutex_;
    mutable std::mutex mutex_;
};

} // namespace MMI
} // namespace OHOS

#endif // TOUCH_CONTROLLER_IMPL_H
