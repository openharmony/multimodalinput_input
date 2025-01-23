/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "long_press_event_subscribe_manager.h"

#include <cinttypes>

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LongPressEventSubscribeManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
constexpr int32_t MAX_FINGER_COUNT { 2 };
constexpr int32_t MAX_DURATION { 3000 };
} // namespace
int32_t LongPressEventSubscribeManager::subscribeManagerId_ = 0;

LongPressEventSubscribeManager::LongPressEventSubscribeManager() {}
LongPressEventSubscribeManager::~LongPressEventSubscribeManager() {}

LongPressEventSubscribeManager::SubscribeLongPressEventInfo::SubscribeLongPressEventInfo(
    const LongPressRequest &longPressRequest,
    std::function<void(LongPressEvent)> callback)
    : longPressRequest_(longPressRequest), callback_(callback)
{
}

int32_t LongPressEventSubscribeManager::SubscribeLongPressEvent(
    const LongPressRequest &longPressRequest,
    std::function<void(LongPressEvent)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(callback, ERROR_NULL_POINTER);
    if (longPressRequest.fingerCount <= 0 || longPressRequest.fingerCount > MAX_FINGER_COUNT ||
        longPressRequest.duration <= 0 || longPressRequest.duration > MAX_DURATION) {
        MMI_HILOGE("FingerCount or duration is invalid");
        return RET_ERR;
    }
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return EVENT_REG_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    if (LongPressEventSubscribeManager::subscribeManagerId_ >= INT_MAX) {
        MMI_HILOGE("The subscribeId has reached the upper limit, cannot continue the subscription");
        return INVALID_SUBSCRIBE_ID;
    }
    int32_t subscribeId = LongPressEventSubscribeManager::subscribeManagerId_;
    ++LongPressEventSubscribeManager::subscribeManagerId_;
    subscribeInfos_.emplace(std::make_pair(subscribeId, SubscribeLongPressEventInfo(longPressRequest, callback)));
    int32_t ret = MMIEventHdl.SubscribeLongPressEvent(subscribeId, longPressRequest);
    if (ret != RET_OK) {
        subscribeInfos_.erase(subscribeId);
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("The subscribeId:%{public}d, fingerCount:%{public}d, duration:%{public}d", subscribeId,
        longPressRequest.fingerCount, longPressRequest.duration);
    return subscribeId;
}

int32_t LongPressEventSubscribeManager::UnsubscribeLongPressEvent(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribe id is less than 0");
        return RET_ERR;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("The subscribeInfos is empty");
        return RET_ERR;
    }

    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        if (MMIEventHdl.UnsubscribeLongPressEvent(subscribeId) != RET_OK) {
            MMI_HILOGE("Leave, unsubscribe long press event failed");
            return RET_ERR;
        }
        subscribeInfos_.erase(it);
        return RET_OK;
    }
    MMI_HILOGE("Failed to unsubscribe long press event, subscribeId:%{public}d", subscribeId);
    return RET_ERR;
}

int32_t LongPressEventSubscribeManager::OnSubscribeLongPressEventCallback(const LongPressEvent &longPressEvent,
    int32_t subscribeId)
{
    CHK_PID_AND_TID();
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribe id is less than 0");
        return RET_ERR;
    }
    std::function<void(LongPressEvent)> callback = nullptr;
    std::lock_guard<std::mutex> guard(mtx_);
    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        SubscribeLongPressEventInfo &subscribeInfo = it->second;
        callback = subscribeInfo.GetCallback();
    }
    CHKPR(callback, ERROR_NULL_POINTER);
    callback(longPressEvent);
    MMI_HILOGD("LongPressEvent fingerCount:%{public}d, duration:%{public}d, pid:%{public}d, displayId:%{public}d, "
        "displayX:%{public}d, displayY:%{public}d, result:%{public}d, windowId:%{public}d, pointerId:%{public}d, "
        "bundleName:%{public}s, subscribeId:%{public}d, downTime:%{public} " PRId64 "",
        longPressEvent.fingerCount, longPressEvent.duration, longPressEvent.pid,
        longPressEvent.displayId, longPressEvent.displayX, longPressEvent.displayY,
        longPressEvent.result, longPressEvent.windowId, longPressEvent.pointerId, longPressEvent.bundleName.c_str(),
        subscribeId, longPressEvent.downTime);
    return RET_OK;
}

void LongPressEventSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGD("Leave, subscribeInfos_ is empty");
        return;
    }
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        SubscribeLongPressEventInfo &subscribeInfo = it->second;
        LongPressRequest longPressRequest = subscribeInfo.GetLongPressRequest();
        int32_t ret = MMIEventHdl.SubscribeLongPressEvent(it->first, longPressRequest);
        if (ret != RET_OK) {
            MMI_HILOGE("Subscribe long pres event failed, ret:%{public}d", ret);
        }
    }
}
} // namespace MMI
} // namespace OHOS
