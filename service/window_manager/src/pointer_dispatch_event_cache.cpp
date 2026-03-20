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

#include "pointer_dispatch_event_cache.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDispatchEventCache"

namespace OHOS {
namespace MMI {
void PointerDispatchEventCache::Update(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    if (pointerEvent == nullptr) {
        MMI_HILOGW("PointerEvent is nullptr");
        return;
    }
    if (IsStylusEvent(pointerEvent)) {
        lastStylusEvent_ = pointerEvent;
        return;
    }
    lastTouchEvent_ = pointerEvent;
}

std::shared_ptr<PointerEvent> PointerDispatchEventCache::GetForDispatch(int32_t pointerAction) const
{
    if (pointerAction == PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW ||
        pointerAction == PointerEvent::POINTER_ACTION_LEVITATE_OUT_WINDOW) {
        return lastStylusEvent_;
    }
    return lastTouchEvent_;
}

std::shared_ptr<PointerEvent> PointerDispatchEventCache::GetTouchEvent() const
{
    return lastTouchEvent_;
}

void PointerDispatchEventCache::ClearDeviceEvents(int32_t deviceId)
{
    if (lastTouchEvent_ != nullptr && lastTouchEvent_->GetDeviceId() == deviceId) {
        lastTouchEvent_ = nullptr;
    }
    if (lastStylusEvent_ != nullptr && lastStylusEvent_->GetDeviceId() == deviceId) {
        lastStylusEvent_ = nullptr;
    }
}

void PointerDispatchEventCache::ClearTouch()
{
    lastTouchEvent_ = nullptr;
}

void PointerDispatchEventCache::Reset()
{
    lastTouchEvent_ = nullptr;
    lastStylusEvent_ = nullptr;
}

bool PointerDispatchEventCache::IsStylusEvent(const std::shared_ptr<PointerEvent>& pointerEvent) const
{
    if (pointerEvent == nullptr) {
        MMI_HILOGW("PointerEvent is nullptr");
        return false;
    }
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = pointerEvent->GetPointerId();
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", pointerId);
        return false;
    }
    auto toolType = pointerItem.GetToolType();
    return toolType == PointerEvent::TOOL_TYPE_PEN || toolType == PointerEvent::TOOL_TYPE_PENCIL;
}
} // namespace MMI
} // namespace OHOS
