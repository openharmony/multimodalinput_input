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

#include "tablet_event_input_subscribe_manager.h"
#include <cinttypes>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletEventInputSubscribeManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
} // namespace
int32_t TabletEventInputSubscribeManager::subscribeManagerId_ = 0;

TabletEventInputSubscribeManager::TabletEventInputSubscribeManager() {}
TabletEventInputSubscribeManager::~TabletEventInputSubscribeManager() {}

int32_t TabletEventInputSubscribeManager::SubscribeTabletProximity(
    std::function<void(std::shared_ptr<PointerEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHKPR(callback, ERROR_NULL_POINTER);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return EVENT_REG_FAIL;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    if (TabletEventInputSubscribeManager::subscribeManagerId_ >= INT_MAX) {
        MMI_HILOGE("The subscribeId has reached the upper limit, cannot continue the subscription");
        return INVALID_SUBSCRIBE_ID;
    }
    int32_t subscribeId = TabletEventInputSubscribeManager::subscribeManagerId_;
    ++TabletEventInputSubscribeManager::subscribeManagerId_;
    subscribeInfos_.emplace(std::make_pair(subscribeId, SubscribeTabletEventInfo(callback)));
    int32_t ret = MMIEventHdl.SubscribeTabletProximity(subscribeId);
    if (ret != RET_OK) {
        MMI_HILOGE("Subscribing Tablet event failed, ret:%{public}d", ret);
        subscribeInfos_.erase(subscribeId);
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("The subscribeId:%{public}d", subscribeId);
    return subscribeId;
}

int32_t TabletEventInputSubscribeManager::UnsubscribetabletProximity(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribe id is less than 0");
        return RET_ERR;
    }
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("The subscribeInfos is empty");
        return RET_ERR;
    }
    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        if (MMIEventHdl.UnsubscribetabletProximity(subscribeId) != RET_OK) {
            MMI_HILOGE("Leave, unsubscribe switch event failed");
            return RET_ERR;
        }
        subscribeInfos_.erase(it);
        return RET_OK;
    }
    return RET_ERR;
}

int32_t TabletEventInputSubscribeManager::OnSubscribeTabletProximityCallback(std::shared_ptr<PointerEvent> event,
    int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_HILOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }
    std::function<void(std::shared_ptr<PointerEvent>)> callback = nullptr;
    std::lock_guard<std::mutex> guard(mtx_);
    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        SubscribeTabletEventInfo &subscribeInfo = it->second;
        callback = subscribeInfo.GetCallback();
    }
    CHKPR(callback, ERROR_NULL_POINTER);
    callback(event);
    MMI_HILOGI("Tablet event id:%{public}d", subscribeId);
    return RET_OK;
}

void TabletEventInputSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGD("Leave, subscribeInfos_ is empty");
        return;
    }
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        SubscribeTabletEventInfo &subscribeInfo = it->second;
        int32_t ret = MMIEventHdl.SubscribeTabletProximity(it->first);
        if (ret != RET_OK) {
            MMI_HILOGE("Subscribe switch event failed, ret:%{public}d", ret);
        }
    }
}
} // namespace MMI
} // namespace OHOS