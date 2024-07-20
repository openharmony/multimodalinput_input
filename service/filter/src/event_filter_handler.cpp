/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_handler.h"

#include "error_multimodal.h"
#include "input_device_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventFilterHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    if (HandleKeyEventFilter(keyEvent)) {
        MMI_HILOGD("Key event is filtered");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventFilterHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (HandlePointerEventFilter(pointerEvent)) {
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventFilterHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (HandlePointerEventFilter(pointerEvent)) {
        MMI_HILOGD("Touch event is filtered");
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventFilterHandler::AddInputEventFilter(sptr<IEventFilter> filter,
    int32_t filterId, int32_t priority, uint32_t deviceTags, int32_t clientPid)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lockFilter_);
    CHKPR(filter, ERROR_NULL_POINTER);
    MMI_HILOGI("Add filter, filterId:%{public}d, priority:%{public}d, clientPid:%{public}d, filters_ size:%{public}zu",
        filterId, priority, clientPid, filters_.size());
    std::weak_ptr<EventFilterHandler> weakPtr = shared_from_this();
    auto deathCallback = [weakPtr, filterId, clientPid](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr != nullptr) {
            auto ret = sharedPtr->RemoveInputEventFilter(filterId, clientPid);
            if (ret != RET_OK) {
                MMI_HILOGW("Remove filter on dead return:%{public}d, filterId:%{public}d, clientPid:%{public}d",
                    ret, filterId, clientPid);
            } else {
                MMI_HILOGW("Remove filter on dead success, filterId:%{public}d, clientPid:%{public}d",
                    filterId, clientPid);
            }
        }
    };
    sptr<IRemoteObject::DeathRecipient> deathRecipient = new (std::nothrow) EventFilterDeathRecipient(deathCallback);
    CHKPR(deathRecipient, RET_ERR);
    filter->AsObject()->AddDeathRecipient(deathRecipient);
    FilterInfo info { .filter = filter, .deathRecipient = deathRecipient, .filterId = filterId,
        .priority = priority, .deviceTags = deviceTags, .clientPid = clientPid };
    auto it = filters_.cbegin();
    for (; it != filters_.cend(); ++it) {
        if (info.priority < it->priority) {
            break;
        }
    }
    auto it2 = filters_.emplace(it, std::move(info));
    if (it2 == filters_.end()) {
        MMI_HILOGE("Fail to add filter");
        return ERROR_FILTER_ADD_FAIL;
    }
    return RET_OK;
}

int32_t EventFilterHandler::RemoveInputEventFilter(int32_t filterId, int32_t clientPid)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lockFilter_);
    if (filters_.empty()) {
        MMI_HILOGD("Filter is empty");
        return RET_OK;
    }
    for (auto it = filters_.begin(); it != filters_.end();) {
        if (filterId == -1) {
            if (it->clientPid == clientPid) {
                auto id = it->filterId;
                filters_.erase(it++);
                MMI_HILOGI("Filter remove success, filterId:%{public}d, clientPid:%{public}d", id, clientPid);
                continue;
            }
            ++it;
            continue;
        }
        if (it->IsSameClient(filterId, clientPid)) {
            filters_.erase(it++);
            MMI_HILOGI("Filter remove success, filterId:%{public}d, clientPid:%{public}d", filterId, clientPid);
            return RET_OK;
        }
        ++it;
    }
    if (filterId == -1) {
        return RET_OK;
    }
    MMI_HILOGI("Filter not found, filterId:%{public}d, clientPid:%{public}d", filterId, clientPid);
    return RET_OK;
}

void EventFilterHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lockFilter_);
    dprintf(fd, "Filter information:\n");
    dprintf(fd, "Filters: count=%d\n", filters_.size());
    for (const auto &item : filters_) {
        dprintf(fd, "priority:%d | filterId:%d | Pid:%d\n", item.priority, item.filterId, item.clientPid);
    }
}

bool EventFilterHandler::HandleKeyEventFilter(std::shared_ptr<KeyEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    std::lock_guard<std::mutex> guard(lockFilter_);
    if (filters_.empty()) {
        return false;
    }
    std::vector<KeyEvent::KeyItem> keyItems = event->GetKeyItems();
    if (keyItems.empty()) {
        MMI_HILOGE("keyItems is empty");
        return false;
    }
    std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(keyItems.front().GetDeviceId());
    CHKPF(inputDevice);
    for (auto &i: filters_) {
        if (!inputDevice->HasCapability(i.deviceTags)) {
            continue;
        }
        if (i.filter->HandleKeyEvent(event)) {
            MMI_HILOGD("Call HandleKeyEventFilter return true");
            return true;
        }
    }
    return false;
}

bool EventFilterHandler::HandlePointerEventFilter(std::shared_ptr<PointerEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    std::lock_guard<std::mutex> guard(lockFilter_);
    if (filters_.empty()) {
        return false;
    }
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = event->GetPointerId();
    if (!event->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", pointerId);
        return false;
    }
    std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(pointerItem.GetDeviceId());
    CHKPF(inputDevice);
    for (auto &i: filters_) {
        if (!inputDevice->HasCapability(i.deviceTags)) {
            continue;
        }
        if (i.filter->HandlePointerEvent(event)) {
            MMI_HILOGD("Call HandlePointerEvent return true");
            return true;
        }
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
