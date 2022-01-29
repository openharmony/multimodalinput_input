/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyEventInputSubscribeManager" };
}
int32_t KeyEventInputSubscribeManager::subscribeIdManager_ = 0;
bool KeyEventInputSubscribeManager::CheckRepeatSubscribeKeyEevent(std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    for (auto subscribeInfoIter = subscribeKeyEventInfoList_.begin();
        subscribeInfoIter != subscribeKeyEventInfoList_.end(); ++subscribeInfoIter) {
        std::shared_ptr<OHOS::MMI::KeyOption> subscribeKeyOption = subscribeInfoIter->GetKeyOption();
        std::vector<int32_t> subscribePreKeys = subscribeKeyOption->GetPreKeys();
        std::vector<int32_t> preKeys = keyOption->GetPreKeys();
        if (subscribePreKeys.size() != preKeys.size()) {
            continue;
        }
        MMI_LOGD("subscribeKeyOption final key:%{public}d, keyOption final key:%{public}d",
            subscribeKeyOption->GetFinalKey(), keyOption->GetFinalKey());
        if (subscribeKeyOption->GetFinalKey() != keyOption->GetFinalKey()) {
            continue;
        }

        int32_t preKeyCount = 0; 
        bool isNotFind = false;
        for (auto preKeyIter = preKeys.begin(); preKeyIter != preKeys.end(); ++preKeyIter) {
            if (*preKeyIter < 0) {
                continue;
            }
            if (std::find(subscribePreKeys.begin(), subscribePreKeys.end(), *preKeyIter) == subscribePreKeys.end()) {
                isNotFind = true;
                break;
            }
            ++preKeyCount;
        }
        if (isNotFind) {
            continue;
        }
        int32_t subPreKeyCount = 0;
        for (auto subPreKeyIter = subscribePreKeys.begin(); subPreKeyIter != subscribePreKeys.end(); ++subPreKeyIter) {
            if (*subPreKeyIter < 0) {
                continue;
            }
            ++subPreKeyCount;
        }
        if (preKeyCount == subPreKeyCount && subscribeKeyOption->IsFinalKeyDown() == keyOption->IsFinalKeyDown()) {
            return true;
        }
    }
    return false;
}

int32_t KeyEventInputSubscribeManager::SubscribeKeyEvent(std::shared_ptr<OHOS::MMI::KeyOption> keyOption,
    std::function<void(std::shared_ptr<OHOS::MMI::KeyEvent>)> callback)
{
    MMI_LOGD("client subscribe key event");
    if (callback == nullptr) {
        MMI_LOGD("the [Callback] is nullptr");
        return -1;
    }
    if (keyOption == nullptr) {
        MMI_LOGD("the [KeyOption] is nullptr.");
        return -1;
    }
    if (CheckRepeatSubscribeKeyEevent(keyOption)) {
        MMI_LOGD("repeat subscribe key event");
        return -1;
    }
    for (auto preKey : keyOption->GetPreKeys()) {
        MMI_LOGD("KeyOption->prekey=%{public}d", preKey);
    }
    SubscribeKeyEventInfo subscribeInfo(keyOption, callback);
    MMI_LOGD("SubscribeId=%{public}d,KeyOption->finalKey=%{public}d,"
        "KeyOption->isFinalKeyDown=%{public}d,KeyOption->finalKeyDownDuriation=%{public}d",
        subscribeInfo.GetSubscribeId(), keyOption->GetFinalKey(), ((keyOption->IsFinalKeyDown() == true) ? 1 : 0),
        keyOption->GetFinalKeyDownDuration());
    int32_t keySubscibeId = subscribeInfo.GetSubscribeId();
    std::string keySubscribeIdstring = "SubscribeKeyEvent client subscribeKeyId: " + std::to_string(keySubscibeId);
    MMI_LOGT(" SubscribeKeyEvent client trace subscribeKeyId = %{public}d", keySubscibeId);
    int32_t eventKey = 1;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keySubscribeIdstring, eventKey);
    if (RET_OK == MMIEventHdl.SubscribeKeyEvent(subscribeInfo)) {
        subscribeKeyEventInfoList_.push_back(subscribeInfo);
        return subscribeInfo.GetSubscribeId();
    }
    return -1;
}

int32_t KeyEventInputSubscribeManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    MMI_LOGD("client unsubscribe key event");
    if (subscribeId < 0) {
        MMI_LOGD("the subscribe id is less than 0.");
        return RET_ERR;
    }
    int32_t size = subscribeKeyEventInfoList_.size();
    if (size == 0) {
        MMI_LOGD("the [SubscribeKeyEventInfoList] is empty");
        return RET_ERR;
    }
    auto it = subscribeKeyEventInfoList_.begin();
    for (; it != subscribeKeyEventInfoList_.end(); ++it) {
        if (it->GetSubscribeId() == subscribeId) {
            if (RET_OK == MMIEventHdl.UnSubscribeKeyEvent(subscribeId)) {
                subscribeKeyEventInfoList_.erase(it);
                return RET_OK;
            }
        }
    }
    if (it == subscribeKeyEventInfoList_.end()) {
        MMI_LOGD("cannot find subscribe key event info by subscribe id.");
    }
    return RET_ERR;
}

int32_t KeyEventInputSubscribeManager::OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event, int32_t subscribeId)
{
    MMI_LOGD("client on subscribe key event callback");
    if (subscribeId < 0) {
        MMI_LOGD("the subscribe id is less than 0.");
        return RET_ERR;
    }
    auto subscribeInfoListIter = subscribeKeyEventInfoList_.begin();
    for (; subscribeInfoListIter != subscribeKeyEventInfoList_.end(); ++subscribeInfoListIter) {
        if (subscribeId == subscribeInfoListIter->GetSubscribeId()) {
            subscribeInfoListIter->GetCallback()(event);
            MMI_LOGD("client executes subscribe callback function success");
            return RET_OK;
        }
    }
    if (subscribeInfoListIter == subscribeKeyEventInfoList_.end()) {
        MMI_LOGD("client cannot find subscribe key event callback");
    }
    return RET_ERR;
}
} // namespace MMI
} // namespace OHOS