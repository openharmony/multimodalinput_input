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

#include "mouse_redispatch_store.h"

#include "input_windows_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseRedispatchStore"

namespace OHOS {
namespace MMI {
MouseRedispatchStore::Guard::Guard(const std::shared_ptr<PointerEvent>& event)
{
    auto& store = WIN_MGR->GetMouseRedispatchStore();
    store.active_ = true;
    store.zOrder_ = event->GetZOrder();
}

MouseRedispatchStore::Guard::~Guard()
{
    auto& store = WIN_MGR->GetMouseRedispatchStore();
    store.active_ = false;
    store.zOrder_ = 0.0f;
}

void MouseRedispatchStore::CacheLastEvent(const std::shared_ptr<PointerEvent>& event)
{
    lastEvent_ = event;
}

std::shared_ptr<PointerEvent> MouseRedispatchStore::GetLastEvent() const
{
    return lastEvent_;
}

void MouseRedispatchStore::SetAxisBeginWindow(const std::optional<WindowInfo>& window)
{
    axisBeginWindowMap_[zOrder_] = window;
}

std::optional<WindowInfo> MouseRedispatchStore::GetAxisBeginWindow() const
{
    auto iter = axisBeginWindowMap_.find(zOrder_);
    if (iter != axisBeginWindowMap_.end()) {
        return iter->second;
    }
    return std::nullopt;
}

void MouseRedispatchStore::EraseAxisBeginWindow(float zOrder)
{
    axisBeginWindowMap_.erase(zOrder);
}

const std::map<float, std::optional<WindowInfo>>& MouseRedispatchStore::GetAxisBeginWindowMap() const
{
    return axisBeginWindowMap_;
}

void MouseRedispatchStore::SetWindowActive(int32_t windowId)
{
    activeWindows_.insert(windowId);
}

bool MouseRedispatchStore::IsWindowActive(int32_t windowId) const
{
    return activeWindows_.count(windowId) > 0;
}

void MouseRedispatchStore::DeactivateWindow(int32_t windowId)
{
    activeWindows_.erase(windowId);
}

bool MouseRedispatchStore::Abandon(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPF(pointerEvent);
    int32_t windowId = pointerEvent->GetTargetWindowId();
    if (!IsWindowActive(windowId)) {
        MMI_HILOGD("Abandon mouse redispatch, windowId:%{public}d not active", windowId);
        return true;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END) {
        DeactivateWindow(windowId);
    }
    return false;
}

void MouseRedispatchStore::ClearDeviceEvents(int32_t deviceId)
{
    if (lastEvent_ != nullptr && lastEvent_->GetDeviceId() == deviceId) {
        lastEvent_ = nullptr;
    }
}

void MouseRedispatchStore::Reset()
{
    lastEvent_ = nullptr;
    axisBeginWindowMap_.clear();
    activeWindows_.clear();
}
} // namespace MMI
} // namespace OHOS
