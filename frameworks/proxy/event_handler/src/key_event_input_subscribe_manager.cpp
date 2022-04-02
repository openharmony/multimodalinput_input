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
#include "input_manager_impl.h"
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
    EventHandlerPtr eventHandler)
    : keyOption_(keyOption), callback_(callback), eventHandler_(eventHandler)
{
    if (KeyEventInputSubscribeManager::subscribeIdManager_ >= INT_MAX) {
        subscribeId_ = -1;
        MMI_HILOGE("subscribeId has reached the upper limit, cannot continue the subscription");
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
    
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGE("client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    for (auto preKey : keyOption->GetPreKeys()) {
        MMI_HILOGD("keyOption->prekey:%{public}d", preKey);
    }
    auto eventHandler = InputMgrImpl->GetCurrentEventHandler();
    CHKPR(eventHandler, INVALID_SUBSCRIBE_ID);
    SubscribeKeyEventInfo subscribeInfo(keyOption, callback, eventHandler);
    MMI_HILOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
        subscribeInfo.GetSubscribeId(), keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());
    if (EventManager.SubscribeKeyEvent(subscribeInfo) != RET_OK) {
        MMI_HILOGE("Leave, subscribe key event failed");
        return INVALID_SUBSCRIBE_ID;
    }
    subscribeInfos_.push_back(subscribeInfo);
    return subscribeInfo.GetSubscribeId();
}

int32_t KeyEventInputSubscribeManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    CALL_LOG_ENTER;
    if (subscribeId < 0) {
        MMI_HILOGE("the subscribe id is less than 0");
        return RET_ERR;
    }
    
    std::lock_guard<std::mutex> guard(mtx_);
    if (!MMIEventHdl.StartClient()) {
        MMI_HILOGE("client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("the subscribeInfos is empty");
        return RET_ERR;
    }
    
    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        if (it->GetSubscribeId() == subscribeId) {
            if (EventManager.UnSubscribeKeyEvent(subscribeId) != RET_OK) {
                MMI_HILOGE("Leave, unsubscribe key event failed");
                return RET_ERR;
            }
            subscribeInfos_.erase(it);
            return RET_OK;
        }
    }
    return RET_ERR;
}

bool KeyEventInputSubscribeManager::PostTask(int32_t subscribeId, const AppExecFwk::EventHandler::Callback &callback)
{
    auto obj = GetSubscribeKeyEvent(subscribeId);
    CHKPF(obj);
    auto eventHandler = obj->GetEventHandler();
    CHKPF(eventHandler);
    return MMIEventHandler::PostTask(eventHandler, callback);
}

void KeyEventInputSubscribeManager::OnSubscribeKeyEventCallbackTask(std::shared_ptr<KeyEvent> event,
    int32_t subscribeId)
{
    CHK_PIDANDTID();
    std::lock_guard<std::mutex> guard(mtx_);
    auto obj = GetSubscribeKeyEvent(subscribeId);
    CHKPV(obj);
    obj->GetCallback()(event);
    MMI_HILOGD("key event callback id:%{public}d keyCode:%{public}d", subscribeId, event->GetKeyCode());
}

int32_t KeyEventInputSubscribeManager::OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event,
    int32_t subscribeId)
{
    CHK_PIDANDTID();
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_HILOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }
    
    std::lock_guard<std::mutex> guard(mtx_);
    BytraceAdapter::StartBytrace(event, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    if (!PostTask(subscribeId, std::bind(&KeyEventInputSubscribeManager::OnSubscribeKeyEventCallbackTask,
        this, event, subscribeId))) {
        MMI_HILOGE("post task failed");
        return RET_ERR;
    }
    MMI_HILOGD("key event id:%{public}d keyCode:%{public}d", subscribeId, event->GetKeyCode());
    return RET_OK;
}

void KeyEventInputSubscribeManager::OnConnected()
{
    CALL_LOG_ENTER;
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("Leave, subscribeInfos_ is empty");
        return;
    }
    for (const auto& subscriberInfo : subscribeInfos_) {
        if (EventManager.SubscribeKeyEvent(subscriberInfo) != RET_OK) {
            MMI_HILOGE("subscribe key event failed");
        }
    }
}

const KeyEventInputSubscribeManager::SubscribeKeyEventInfo* KeyEventInputSubscribeManager::GetSubscribeKeyEvent(
    int32_t id)
{
    if (id < 0) {
        MMI_HILOGE("invalid input param id:%{public}d", id);
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