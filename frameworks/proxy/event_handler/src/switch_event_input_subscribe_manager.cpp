/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "switch_event_input_subscribe_manager.h"

#include <cinttypes>

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SwitchEventInputSubscribeManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID = -1;
} // namespace
int32_t SwitchEventInputSubscribeManager::subscribeManagerId_ = 0;

SwitchEventInputSubscribeManager::SwitchEventInputSubscribeManager() {}
SwitchEventInputSubscribeManager::~SwitchEventInputSubscribeManager() {}

SwitchEventInputSubscribeManager::SubscribeSwitchEventInfo::SubscribeSwitchEventInfo(
    int32_t switchType,
    std::function<void(std::shared_ptr<SwitchEvent>)> callback)
    : switchType_(switchType), callback_(callback)
{
}

int32_t SwitchEventInputSubscribeManager::SubscribeSwitchEvent(
    int32_t switchType,
    std::function<void(std::shared_ptr<SwitchEvent>)> callback)
{
    CALL_INFO_TRACE;
    CHKPR(callback, INVALID_SUBSCRIBE_ID);
    if (switchType < SwitchEvent::SwitchType::DEFAULT) {
        MMI_HILOGE("switch type error");
        return RET_ERR;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    if (SwitchEventInputSubscribeManager::subscribeManagerId_ >= INT_MAX) {
        MMI_HILOGE("The subscribeId has reached the upper limit, cannot continue the subscription");
        return INVALID_SUBSCRIBE_ID;
    }
    int32_t subscribeId = SwitchEventInputSubscribeManager::subscribeManagerId_;
    ++SwitchEventInputSubscribeManager::subscribeManagerId_;
    subscribeInfos_.emplace(std::make_pair(subscribeId, SubscribeSwitchEventInfo(switchType, callback)));
    int32_t ret = MMIEventHdl.SubscribeSwitchEvent(subscribeId, switchType);
    if (ret != RET_OK) {
        MMI_HILOGE("Subscribing switch event failed, ret:%{public}d", ret);
        subscribeInfos_.erase(subscribeId);
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("subscribeId:%{public}d,switchType:%{public}d", subscribeId, switchType);

    return subscribeId;
}

int32_t SwitchEventInputSubscribeManager::UnsubscribeSwitchEvent(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("The subscribe id is less than 0");
        return RET_ERR;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("The subscribeInfos is empty");
        return RET_ERR;
    }

    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        if (MMIEventHdl.UnsubscribeSwitchEvent(subscribeId) != RET_OK) {
            MMI_HILOGE("Leave, unsubscribe switch event failed");
            return RET_ERR;
        }
        subscribeInfos_.erase(it);
        return RET_OK;
    }

    return RET_ERR;
}

int32_t SwitchEventInputSubscribeManager::OnSubscribeSwitchEventCallback(std::shared_ptr<SwitchEvent> event,
    int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_HILOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }
    std::function<void(std::shared_ptr<SwitchEvent>)> callback = nullptr;
    std::lock_guard<std::mutex> guard(mtx_);
    auto it = subscribeInfos_.find(subscribeId);
    if (it != subscribeInfos_.end()) {
        SubscribeSwitchEventInfo &subscribeInfo = it->second;
        callback = subscribeInfo.GetCallback();
    }
    CHKPR(callback, ERROR_NULL_POINTER);
    callback(event);
    MMI_HILOGI("Switch event id:%{public}d switchValue:%{public}d", subscribeId, event->GetSwitchValue());
    return RET_OK;
}

void SwitchEventInputSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    if (subscribeInfos_.empty()) {
        MMI_HILOGD("Leave, subscribeInfos_ is empty");
        return;
    }
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        SubscribeSwitchEventInfo &subscribeInfo = it->second;
        int32_t ret = MMIEventHdl.SubscribeSwitchEvent(subscribeInfo.GetSwitchType(), it->first);
        if (ret != RET_OK) {
            MMI_HILOGE("Subscribe switch event failed, ret:%{public}d", ret);
        }
    }
}
} // namespace MMI
} // namespace OHOS