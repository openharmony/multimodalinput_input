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

#include "touch_redispatch_store.h"

#include "input_windows_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchRedispatchStore"

namespace OHOS {
namespace MMI {
TouchRedispatchStore::Guard::Guard(const std::shared_ptr<PointerEvent>& event)
{
    auto& store = WIN_MGR->GetTouchRedispatchStore();
    store.active_ = true;
    store.zOrder_ = event->GetZOrder();
}

TouchRedispatchStore::Guard::~Guard()
{
    auto& store = WIN_MGR->GetTouchRedispatchStore();
    store.active_ = false;
    store.zOrder_ = 0.0f;
}

void TouchRedispatchStore::SetFingerActive(float zOrder, int32_t deviceId, int32_t pointerId,
    const std::shared_ptr<PointerEvent>& event)
{
    RedispatchFingerInfo info;
    if (event != nullptr) {
        info.windowId = event->GetTargetWindowId();
    }
    info.event = event;
    info.active = true;
    redispatchFingers_[zOrder][{deviceId, pointerId}] = info;
}

bool TouchRedispatchStore::IsFingerActive(float zOrder, int32_t deviceId, int32_t pointerId) const
{
    auto outerIter = redispatchFingers_.find(zOrder);
    if (outerIter == redispatchFingers_.end()) {
        return false;
    }
    auto innerIter = outerIter->second.find({deviceId, pointerId});
    if (innerIter != outerIter->second.end()) {
        return innerIter->second.active;
    }
    return false;
}

void TouchRedispatchStore::DeactivateFinger(float zOrder, int32_t deviceId, int32_t pointerId)
{
    auto outerIter = redispatchFingers_.find(zOrder);
    if (outerIter == redispatchFingers_.end()) {
        return;
    }
    outerIter->second.erase({deviceId, pointerId});
    if (outerIter->second.empty()) {
        redispatchFingers_.erase(outerIter);
    }
}

std::shared_ptr<PointerEvent> TouchRedispatchStore::GetFingerEvent(float zOrder, int32_t deviceId,
    int32_t pointerId) const
{
    auto outerIter = redispatchFingers_.find(zOrder);
    if (outerIter == redispatchFingers_.end()) {
        return nullptr;
    }
    auto innerIter = outerIter->second.find({deviceId, pointerId});
    if (innerIter != outerIter->second.end()) {
        return innerIter->second.event;
    }
    return nullptr;
}

int32_t TouchRedispatchStore::GetFingerWindowId(float zOrder, int32_t deviceId, int32_t pointerId) const
{
    auto outerIter = redispatchFingers_.find(zOrder);
    if (outerIter == redispatchFingers_.end()) {
        return -1;
    }
    auto innerIter = outerIter->second.find({deviceId, pointerId});
    if (innerIter != outerIter->second.end()) {
        return innerIter->second.windowId;
    }
    return -1;
}

const TouchRedispatchStore::FingerMap& TouchRedispatchStore::GetFingerMap() const
{
    return redispatchFingers_;
}

std::map<int32_t, std::map<int32_t, std::set<int32_t>>>& TouchRedispatchStore::GetTargetTouchWinIds()
{
    return targetTouchWinIds_[zOrder_];
}

std::map<int32_t, WindowPartInfo>& TouchRedispatchStore::GetFirstTouchInfos()
{
    return firstTouchInfos_[zOrder_];
}

WindowInfo& TouchRedispatchStore::GetLockWindowInfo()
{
    return lockWindowInfo_[zOrder_];
}

std::shared_ptr<PointerEvent>& TouchRedispatchStore::GetLastTouchEventOnBackGesture()
{
    return lastTouchEventOnBackGesture_[zOrder_];
}

std::map<int32_t, std::shared_ptr<PointerEvent>>& TouchRedispatchStore::GetLastPointerEventForWindowChangeMap()
{
    return lastPointerEventForWindowChangeMap_[zOrder_];
}

std::shared_ptr<PointerEvent>& TouchRedispatchStore::GetLastPointerEventForGesture()
{
    return lastPointerEventForGesture_[zOrder_];
}

PointerDispatchEventCache& TouchRedispatchStore::GetDispatchEventCache()
{
    return dispatchEventCache_[zOrder_];
}

std::map<LastTouch, LastTouchInfo>& TouchRedispatchStore::GetLastTouchInfos()
{
    return lastTouchInfos_[zOrder_];
}

std::map<int32_t, std::vector<std::shared_ptr<WindowInfo>>>& TouchRedispatchStore::GetCancelEventList()
{
    return cancelEventList_[zOrder_];
}

std::map<int32_t, std::map<int32_t, WindowInfoEX>>& TouchRedispatchStore::GetTouchItemDownInfos()
{
    return touchItemDownInfos_[zOrder_];
}

bool TouchRedispatchStore::Abandon(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPF(pointerEvent);
    int32_t deviceId = pointerEvent->GetDeviceId();
    int32_t pointerId = pointerEvent->GetPointerId();
    float zOrder = pointerEvent->GetZOrder();
    PointerEvent::PointerItem pointerItem;
    int32_t toolType = PointerEvent::TOOL_TYPE_FINGER;
    if (pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        toolType = pointerItem.GetToolType();
    }
    int32_t action = pointerEvent->GetPointerAction();
    if (toolType == PointerEvent::TOOL_TYPE_PEN &&
        action == PointerEvent::POINTER_ACTION_PROXIMITY_IN) {
        SetFingerActive(zOrder, deviceId, pointerId, pointerEvent);
        MMI_HILOGD("Auto-activate pen on PROXIMITY_IN, z:%{public}f d:%{public}d p:%{public}d",
            zOrder, deviceId, pointerId);
        return false;
    }
    if (!IsFingerActive(zOrder, deviceId, pointerId)) {
        MMI_HILOGD("Abandon touch redispatch, not active, z:%{public}f d:%{public}d p:%{public}d",
            zOrder, deviceId, pointerId);
        return true;
    }
    if (toolType == PointerEvent::TOOL_TYPE_PEN) {
        if (action == PointerEvent::POINTER_ACTION_PROXIMITY_OUT) {
            DeactivateFinger(zOrder, deviceId, pointerId);
            MMI_HILOGD("Deactivate pen on PROXIMITY_OUT, d:%{public}d p:%{public}d",
                deviceId, pointerId);
        }
    } else {
        if (action == PointerEvent::POINTER_ACTION_UP ||
            action == PointerEvent::POINTER_ACTION_CANCEL ||
            action == PointerEvent::POINTER_ACTION_HOVER_CANCEL ||
            action == PointerEvent::POINTER_ACTION_HOVER_EXIT) {
            DeactivateFinger(zOrder, deviceId, pointerId);
            MMI_HILOGD("Deactivate finger on action:%{public}d, d:%{public}d p:%{public}d",
                action, deviceId, pointerId);
        }
    }
    return false;
}

void TouchRedispatchStore::Reset()
{
    redispatchFingers_.clear();
    targetTouchWinIds_.clear();
    firstTouchInfos_.clear();
    lockWindowInfo_.clear();
    lastTouchEventOnBackGesture_.clear();
    lastPointerEventForWindowChangeMap_.clear();
    lastPointerEventForGesture_.clear();
    dispatchEventCache_.clear();
    lastTouchInfos_.clear();
    cancelEventList_.clear();
    touchItemDownInfos_.clear();
}
} // namespace MMI
} // namespace OHOS
