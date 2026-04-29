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

#ifndef TOUCH_REDISPATCH_STORE_H
#define TOUCH_REDISPATCH_STORE_H

#include <map>
#include <memory>
#include <set>
#include <utility>

#include "pointer_dispatch_event_cache.h"
#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
struct RedispatchFingerInfo {
    int32_t windowId { -1 };
    std::shared_ptr<PointerEvent> event;
    bool active { true };
};

struct WindowPartInfo {
    int32_t displayId { -1 };
    int32_t windowId { -1 };
    uint32_t flags { 0 };
};

struct WindowInfoEX {
    WindowInfo window;
    bool flag { false };
};

struct LastTouch {
    int32_t deviceId_ { -1 };
    int32_t pointerId_ { -1 };

    bool operator<(const LastTouch &other) const
    {
        if (deviceId_ != other.deviceId_) {
            return (deviceId_ < other.deviceId_);
        }
        return (pointerId_ < other.pointerId_);
    }

    bool operator==(const LastTouch &other) const
    {
        return (deviceId_ == other.deviceId_ && pointerId_ == other.pointerId_);
    }
};

struct LastTouchInfo {
    int32_t lastTouchLogicX { -1 };
    int32_t lastTouchLogicY { -1 };
    WindowInfo lastTouchWindowInfo;
};

class TouchRedispatchStore final {
public:
    struct Guard {
        Guard(const std::shared_ptr<PointerEvent>& event);
        ~Guard();
    };

    bool IsActive() const { return active_; }
    float GetZOrder() const { return zOrder_; }

    void SetFingerActive(float zOrder, int32_t deviceId, int32_t pointerId,
                         const std::shared_ptr<PointerEvent>& event);
    bool IsFingerActive(float zOrder, int32_t deviceId, int32_t pointerId) const;
    void DeactivateFinger(float zOrder, int32_t deviceId, int32_t pointerId);
    std::shared_ptr<PointerEvent> GetFingerEvent(float zOrder, int32_t deviceId, int32_t pointerId) const;
    int32_t GetFingerWindowId(float zOrder, int32_t deviceId, int32_t pointerId) const;

    const std::map<float, std::map<std::pair<int32_t, int32_t>, RedispatchFingerInfo>>& GetFingerMap() const;

    std::map<int32_t, std::map<int32_t, std::set<int32_t>>>& GetTargetTouchWinIds();
    std::map<int32_t, WindowPartInfo>& GetFirstTouchInfos();
    WindowInfo& GetLockWindowInfo();

    std::shared_ptr<PointerEvent>& GetLastTouchEventOnBackGesture();
    std::map<int32_t, std::shared_ptr<PointerEvent>>& GetLastPointerEventForWindowChangeMap();
    std::shared_ptr<PointerEvent>& GetLastPointerEventForGesture();
    PointerDispatchEventCache& GetDispatchEventCache();
    std::map<LastTouch, LastTouchInfo>& GetLastTouchInfos();
    std::map<int32_t, std::vector<std::shared_ptr<WindowInfo>>>& GetCancelEventList();
    std::map<int32_t, std::map<int32_t, WindowInfoEX>>& GetTouchItemDownInfos();

    bool Abandon(const std::shared_ptr<PointerEvent>& pointerEvent);

    void Reset();

private:
    bool active_ { false };
    float zOrder_ { 0.0f };

    std::map<float, std::map<std::pair<int32_t, int32_t>, RedispatchFingerInfo>> redispatchFingers_;

    std::map<float, std::map<int32_t, std::map<int32_t, std::set<int32_t>>>> targetTouchWinIds_;
    std::map<float, std::map<int32_t, WindowPartInfo>> firstTouchInfos_;
    std::map<float, WindowInfo> lockWindowInfo_;

    std::map<float, std::shared_ptr<PointerEvent>> lastTouchEventOnBackGesture_;
    std::map<float, std::map<int32_t, std::shared_ptr<PointerEvent>>> lastPointerEventForWindowChangeMap_;
    std::map<float, std::shared_ptr<PointerEvent>> lastPointerEventForGesture_;
    std::map<float, PointerDispatchEventCache> dispatchEventCache_;
    std::map<float, std::map<LastTouch, LastTouchInfo>> lastTouchInfos_;
    std::map<float, std::map<int32_t, std::vector<std::shared_ptr<WindowInfo>>>> cancelEventList_;
    std::map<float, std::map<int32_t, std::map<int32_t, WindowInfoEX>>> touchItemDownInfos_;
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_REDISPATCH_STORE_H
