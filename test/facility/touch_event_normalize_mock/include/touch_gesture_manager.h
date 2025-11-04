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

#ifndef MMI_TOUCH_GESTURE_MANAGER_MOCK_H
#define MMI_TOUCH_GESTURE_MANAGER_MOCK_H

#include "gmock/gmock.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class ITouchGestureManager {
public:
    ITouchGestureManager() = default;
    virtual ~ITouchGestureManager() = default;

    virtual void HandleGestureWindowEmerged(int32_t, std::shared_ptr<PointerEvent>) = 0;
};

class TouchGestureManager final : public ITouchGestureManager {
public:
    TouchGestureManager() = default;
    ~TouchGestureManager() override = default;
    DISALLOW_COPY_AND_MOVE(TouchGestureManager);

    MOCK_METHOD(void, HandleGestureWindowEmerged, (int32_t, std::shared_ptr<PointerEvent>));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_TOUCH_GESTURE_MANAGER_MOCK_H
