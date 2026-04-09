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

#ifndef MOUSE_CONTROLLER_IMPL_H
#define MOUSE_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {

class MouseControllerImpl {
public:
    MouseControllerImpl();
    ~MouseControllerImpl();

    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);
    int32_t PressButton(int32_t button);
    int32_t ReleaseButton(int32_t button);
    int32_t BeginAxis(int32_t axis, int32_t value);
    int32_t UpdateAxis(int32_t axis, int32_t value);
    int32_t EndAxis(int32_t axis);

private:
    PointerEvent::PointerItem CreatePointerItem();
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);
    bool ValidateCoordinates(int32_t& x, int32_t& y, int32_t displayId);

    std::map<int32_t, bool> buttonStates_;
    std::map<int32_t, int64_t> buttonDownTimes_;

    struct {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;

    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;

    mutable std::mutex mutex_;
};

} // namespace MMI
} // namespace OHOS

#endif // MOUSE_CONTROLLER_IMPL_H
