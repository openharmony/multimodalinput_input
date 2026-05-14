/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOUSE_REDISPATCH_STORE_H
#define MOUSE_REDISPATCH_STORE_H

#include <map>
#include <memory>
#include <optional>
#include <set>

#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class MouseRedispatchStore final {
public:
    struct Guard {
        Guard(const std::shared_ptr<PointerEvent>& event);
        ~Guard();
    };

    bool IsActive() const { return active_; }
    float GetZOrder() const { return zOrder_; }

    void CacheLastEvent(const std::shared_ptr<PointerEvent>& event);
    std::shared_ptr<PointerEvent> GetLastEvent() const;

    void SetAxisBeginWindow(const std::optional<WindowInfo>& window);
    std::optional<WindowInfo> GetAxisBeginWindow() const;
    void EraseAxisBeginWindow(float zOrder);
    const std::map<float, std::optional<WindowInfo>>& GetAxisBeginWindowMap() const;

    void SetWindowActive(int32_t windowId);
    bool IsWindowActive(int32_t windowId) const;
    void DeactivateWindow(int32_t windowId);

    bool Abandon(const std::shared_ptr<PointerEvent>& pointerEvent);

    void ClearDeviceEvents(int32_t deviceId);
    void Reset();

private:
    bool active_ { false };
    float zOrder_ { 0.0f };

    std::shared_ptr<PointerEvent> lastEvent_ { nullptr };
    std::map<float, std::optional<WindowInfo>> axisBeginWindowMap_;
    std::set<int32_t> activeWindows_;
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_REDISPATCH_STORE_H
