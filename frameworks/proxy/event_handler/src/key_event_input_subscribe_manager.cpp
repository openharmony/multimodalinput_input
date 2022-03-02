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
#include "bytrace.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_standardized_event_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyEventInputSubscribeManager" };
constexpr int32_t INVALID_SUBSCRIBE_ID = -1;
}
int32_t KeyEventInputSubscribeManager::subscribeIdManager_ = 0;

KeyEventInputSubscribeManager::SubscribeKeyEventInfo::SubscribeKeyEventInfo(
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption,
    std::function<void(std::shared_ptr<OHOS::MMI::KeyEvent>)> callback)
    : keyOption_(keyOption), callback_(callback)
{
    if (KeyEventInputSubscribeManager::subscribeIdManager_ >= INT_MAX) {
        subscribeId_ = -1;
        MMI_LOGE("subscribeId has reached the upper limit, cannot continue the subscription");
        return;
    }
    subscribeId_ = KeyEventInputSubscribeManager::subscribeIdManager_;
    ++KeyEventInputSubscribeManager::subscribeIdManager_;
}

int32_t KeyEventInputSubscribeManager::SubscribeKeyEvent(std::shared_ptr<OHOS::MMI::KeyOption> keyOption,
    std::function<void(std::shared_ptr<OHOS::MMI::KeyEvent>)> callback)
{
    MMI_LOGD("Enter");
    CHKPR(keyOption, INVALID_SUBSCRIBE_ID);
    CHKPR(callback, INVALID_SUBSCRIBE_ID);
    for (auto preKey : keyOption->GetPreKeys()) {
        MMI_LOGD("keyOption->prekey:%{public}d", preKey);
    }
    SubscribeKeyEventInfo subscribeInfo(keyOption, callback);
    MMI_LOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
        subscribeInfo.GetSubscribeId(), keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());
    if (EventManager.SubscribeKeyEvent(subscribeInfo) != RET_OK) {
        MMI_LOGE("Leave, subscribe key event failed");
        return INVALID_SUBSCRIBE_ID;
    }
    subscribeInfos_.push_back(subscribeInfo);
    MMI_LOGD("Leave");
    return subscribeInfo.GetSubscribeId();
}

int32_t KeyEventInputSubscribeManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    MMI_LOGD("Enter");
    if (subscribeId < 0) {
        MMI_LOGE("the subscribe id is less than 0");
        return RET_ERR;
    }
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
            MMI_LOGD("Leave");
            return RET_OK;
        }
    }
    MMI_LOGE("Leave");
    return RET_ERR;
}

int32_t KeyEventInputSubscribeManager::OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event, int32_t subscribeId)
{
    MMI_LOGD("Enter");
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_LOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }
    int32_t keyId = event->GetId();
    const std::string keyEventString = "keyEventSubscribe";
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyEventString, keyId);
    for (const auto& subscriber : subscribeInfos_) {
        if (subscriber.GetSubscribeId() == subscribeId) {
            subscriber.GetCallback()(event);
            MMI_LOGD("Leave, client executes subscribe callback function success");
            return RET_OK;
        }
    }
    MMI_LOGE("Leave");
    return RET_ERR;
}
} // namespace MMI
} // namespace OHOS