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

#include "key_event_input_subscribe_manager.h"

#include <cinttypes>

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "bytrace_adapter.h"
#include "mmi_event_handler.h"
#include "multimodal_event_handler.h"
#include "standardized_event_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyEventInputSubscribeManager" };
constexpr int32_t INVALID_SUBSCRIBE_ID = -1;
} // namespace
int32_t KeyEventInputSubscribeManager::subscribeIdManager_ = 0;

KeyEventInputSubscribeManager::SubscribeKeyEventInfo::SubscribeKeyEventInfo(
    std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
    : keyOption_(keyOption), callback_(callback), eventHandler_(eventHandler)
{
    if (KeyEventInputSubscribeManager::subscribeIdManager_ >= INT_MAX) {
        subscribeId_ = -1;
        MMI_LOGE("subscribeId has reached the upper limit, cannot continue the subscription");
        return;
    }
    subscribeId_ = KeyEventInputSubscribeManager::subscribeIdManager_;
    ++KeyEventInputSubscribeManager::subscribeIdManager_;
}

int32_t KeyEventInputSubscribeManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_LOG_ENTER;
    CHKPR(keyOption, INVALID_SUBSCRIBE_ID);
    CHKPR(callback, INVALID_SUBSCRIBE_ID);
    if (!MMIEventHdl.StartClient()) {
        MMI_LOGE("client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    for (auto preKey : keyOption->GetPreKeys()) {
        MMI_LOGD("keyOption->prekey:%{public}d", preKey);
    }
    auto eventHandler = AppExecFwk::EventHandler::Current();
    if (eventHandler == nullptr) {
        eventHandler = MEventHandler->GetSharedPtr();
    }
    
    std::lock_guard<std::mutex> guard(mtx_);
    SubscribeKeyEventInfo subscribeInfo(keyOption, callback, eventHandler);
    MMI_LOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
        subscribeInfo.GetSubscribeId(), keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());
    EventManager.SubscribeKeyEvent(subscribeInfo);
    subscribeInfos_.push_back(subscribeInfo);
    return subscribeInfo.GetSubscribeId();
}

int32_t KeyEventInputSubscribeManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    CALL_LOG_ENTER;
    if (subscribeId < 0) {
        MMI_LOGE("the subscribe id is less than 0");
        return RET_ERR;
    }
    if (!MMIEventHdl.StartClient()) {
        MMI_LOGE("client init failed");
        return INVALID_SUBSCRIBE_ID;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_LOGE("the subscribeInfos is empty");
        return RET_ERR;
    }
    
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        if (it->GetSubscribeId() == subscribeId) {
            if (EventManager.UnSubscribeKeyEvent(subscribeId) != RET_OK) {
                MMI_LOGE("Leave, unsubscribe key event failed");
                return RET_ERR;
            }
            subscribeInfos_.erase(it);
            return RET_OK;
        }
    }
    return RET_ERR;
}

int32_t KeyEventInputSubscribeManager::OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event, int32_t subscribeId)
{
    CALL_LOG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_LOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }

    int32_t pid = GetPid();
    uint64_t tid = GetThisThreadId();
    MMI_LOGI("pid:%{public}d threadId:%{public}" PRIu64, pid, tid);
    BytraceAdapter::StartBytrace(event, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_SUBSCRIBE_EVENT);

    auto callMsgHandler = [this, event, subscribeId] () {
        int32_t pid = GetPid();
        uint64_t tid = GetThisThreadId();
        MMI_LOGI("callMsgHandler pid:%{public}d threadId:%{public}" PRIu64, pid, tid);
        
        std::lock_guard<std::mutex> guard(mtx_);
        auto obj = GetSubscribeKeyEvent(subscribeId);
        if (!obj) {
            MMI_LOGE("subscribe key event not found. id:%{public}d", subscribeId);
            return;
        }
        obj->GetCallback()(event);
        MMI_LOGD("callMsgHandler key event callback id:%{public}d keyCode:%{public}d pid:%{public}d "
            "threadId:%{public}" PRIu64, subscribeId, event->GetKeyCode(), pid, tid);
    };

    std::lock_guard<std::mutex> guard(mtx_);
    auto obj = GetSubscribeKeyEvent(subscribeId);
    if (obj == nullptr) {
        MMI_LOGE("subscribe key event not found. id:%{public}d", subscribeId);
        return RET_ERR;
    }
    auto eventHandler = obj->GetEventHandler();
    if (eventHandler == nullptr) {
        MMI_LOGE("Event handler ptr = nullptr");
        return RET_ERR;
    }
    bool ret = eventHandler->PostHighPriorityTask(callMsgHandler);
    if (!ret) {
        MMI_LOGE("post task failed");
        return RET_ERR;
    }
    return RET_OK;
}

void KeyEventInputSubscribeManager::OnConnected()
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_LOGE("Leave, subscribeInfos_ is empty");
        return;
    }
    for (const auto& subscriberInfo : subscribeInfos_) {
        if (EventManager.SubscribeKeyEvent(subscriberInfo) != RET_OK) {
            MMI_LOGE("subscribe key event failed");
        }
    }
}

const KeyEventInputSubscribeManager::SubscribeKeyEventInfo*
KeyEventInputSubscribeManager::GetSubscribeKeyEvent(int32_t id)
{
    if (id < 0) {
        MMI_LOGE("invalid input param id:%{public}d", id);
        return nullptr;
    }
    for (const auto& subscriber : subscribeInfos_) {
        if (subscriber.GetSubscribeId() == id) {
            return &subscriber;
        }
    }
    return nullptr;
}
} // namespace MMI
} // namespace OHOS