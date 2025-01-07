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

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventInputSubscribeManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_SUBSCRIBE_ID { -1 };
constexpr size_t PRE_KEYS_NUM { 4 };
} // namespace
int32_t KeyEventInputSubscribeManager::subscribeIdManager_ = 0;

KeyEventInputSubscribeManager::KeyEventInputSubscribeManager() {}
KeyEventInputSubscribeManager::~KeyEventInputSubscribeManager() {}

KeyEventInputSubscribeManager::SubscribeKeyEventInfo::SubscribeKeyEventInfo(
    std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
    : keyOption_(keyOption), callback_(callback)
{
    if (KeyEventInputSubscribeManager::subscribeIdManager_ >= std::numeric_limits<int32_t>::max()) {
        subscribeId_ = -1;
        MMI_HILOGE("The subscribeId has reached the upper limit, cannot continue the subscription");
        return;
    }
    subscribeId_ = KeyEventInputSubscribeManager::subscribeIdManager_;
    ++KeyEventInputSubscribeManager::subscribeIdManager_;
}

static bool operator<(const KeyOption &first, const KeyOption &second)
{
    if (first.GetFinalKey() != second.GetFinalKey()) {
        return (first.GetFinalKey() < second.GetFinalKey());
    }
    const std::set<int32_t> sPrekeys { first.GetPreKeys() };
    const std::set<int32_t> tPrekeys { second.GetPreKeys() };
    std::set<int32_t>::const_iterator sIter = sPrekeys.cbegin();
    std::set<int32_t>::const_iterator tIter = tPrekeys.cbegin();
    for (; sIter != sPrekeys.cend() && tIter != tPrekeys.cend(); ++sIter, ++tIter) {
        if (*sIter != *tIter) {
            return (*sIter < *tIter);
        }
    }
    if (sIter != sPrekeys.cend() || tIter != tPrekeys.cend()) {
        return (tIter != tPrekeys.cend());
    }
    if (first.IsFinalKeyDown()) {
        if (!second.IsFinalKeyDown()) {
            return false;
        }
    } else {
        if (second.IsFinalKeyDown()) {
            return true;
        }
    }
    return (first.GetFinalKeyDownDuration() < second.GetFinalKeyDownDuration());
}

KeyEventInputSubscribeManager::SubscribeKeyEventInfo::SubscribeKeyEventInfo(const SubscribeKeyEventInfo &other)
    : keyOption_(other.keyOption_), callback_(other.callback_), subscribeId_(other.subscribeId_)
{}

KeyEventInputSubscribeManager::SubscribeKeyEventInfo& KeyEventInputSubscribeManager::SubscribeKeyEventInfo::operator=(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &other)
{
    if (this != &other) {
        keyOption_ = other.keyOption_;
        callback_ = other.callback_;
        subscribeId_ = other.subscribeId_;
    }
    return *this;
}

bool KeyEventInputSubscribeManager::SubscribeKeyEventInfo::operator<(const SubscribeKeyEventInfo &other) const
{
    if (keyOption_ == nullptr) {
        return (other.keyOption_ != nullptr);
    } else if (other.keyOption_ == nullptr) {
        return false;
    }
    return (*keyOption_ < *other.keyOption_);
}

int32_t KeyEventInputSubscribeManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyOption, INVALID_SUBSCRIBE_ID);
    CHKPR(callback, INVALID_SUBSCRIBE_ID);
    std::set<int32_t> preKeys = keyOption->GetPreKeys();
    if (preKeys.size() > PRE_KEYS_NUM) {
        MMI_HILOGE("PreKeys number invalid");
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("PRE:[%{private}s],FINAL:%{private}d,KA:%{public}s,HT:%{public}d",
        DumpSet(preKeys).c_str(), keyOption->GetFinalKey(),
        (keyOption->IsFinalKeyDown() ? "down" : "up"), keyOption->GetFinalKeyDownDuration());

    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    auto [tIter, isOk] = subscribeInfos_.emplace(keyOption, callback);
    if (!isOk) {
        MMI_HILOGW("Subscription is duplicated");
        return tIter->GetSubscribeId();
    }
    int32_t ret = MMIEventHdl.SubscribeKeyEvent(*tIter);
    if (ret != RET_OK) {
        MMI_HILOGE("Subscribing key event failed");
        subscribeInfos_.erase(tIter);
        return ret;
    }
    MMI_HILOGI("The subscribeId:%{public}d, preKeys:[%{private}s], finalKey:%{private}d,"
        "keyOption->isFinalKeyDown:%{public}s, keyOption->finalKeyDownDuration:%{public}d",
        tIter->GetSubscribeId(), DumpSet(preKeys).c_str(), keyOption->GetFinalKey(),
        keyOption->IsFinalKeyDown() ? "true" : "false", keyOption->GetFinalKeyDownDuration());
    return tIter->GetSubscribeId();
}

int32_t KeyEventInputSubscribeManager::UnsubscribeKeyEvent(int32_t subscribeId)
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
        MMI_HILOGE("The subscribe Infos is empty");
        return RET_ERR;
    }

    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        if (it->GetSubscribeId() == subscribeId) {
            if (MMIEventHdl.UnsubscribeKeyEvent(subscribeId) != RET_OK) {
                MMI_HILOGE("Leave, unsubscribe key event failed");
                return RET_ERR;
            }
            subscribeInfos_.erase(it);
            return RET_OK;
        }
    }
    return RET_ERR;
}

int32_t KeyEventInputSubscribeManager::SubscribeHotkey(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyOption, INVALID_SUBSCRIBE_ID);
    CHKPR(callback, INVALID_SUBSCRIBE_ID);
    std::set<int32_t> preKeys = keyOption->GetPreKeys();
    if (preKeys.size() > PRE_KEYS_NUM) {
        MMI_HILOGE("PreKeys number invalid");
        return INVALID_SUBSCRIBE_ID;
    }
    MMI_HILOGI("PRE:[%{private}s],FINAL:%{private}d,KA:%{public}s,HT:%{public}d",
        DumpSet(preKeys).c_str(), keyOption->GetFinalKey(),
        (keyOption->IsFinalKeyDown() ? "down" : "up"), keyOption->GetFinalKeyDownDuration());

    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    auto [tIter, isOk] = subscribeInfos_.emplace(keyOption, callback);
    if (!isOk) {
        MMI_HILOGW("Subscription is duplicated");
        return tIter->GetSubscribeId();
    }
    int32_t ret = MMIEventHdl.SubscribeHotkey(*tIter);
    if (ret != RET_OK) {
        MMI_HILOGE("SubscribeHotkey fail, error:%{public}d", ret);
        subscribeInfos_.erase(tIter);
        return ret;
    }

    MMI_HILOGI("The subscribeId:%{public}d, preKeys:%{private}s, finalKey:%{private}d,"
        "keyOption->isFinalKeyDown:%{public}s, keyOption->finalKeyDownDuration:%{public}d",
        tIter->GetSubscribeId(), DumpSet(preKeys).c_str(), keyOption->GetFinalKey(),
        keyOption->IsFinalKeyDown() ? "true" : "false", keyOption->GetFinalKeyDownDuration());
    return tIter->GetSubscribeId();
}

int32_t KeyEventInputSubscribeManager::UnsubscribeHotkey(int32_t subscribeId)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("Subscribe id is less than 0");
        return RET_ERR;
    }

    if (!MMIEventHdl.InitClient()) {
        MMI_HILOGE("Client init failed");
        return INVALID_SUBSCRIBE_ID;
    }

    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGE("Subscribe Infos is empty");
        return RET_ERR;
    }

    for (auto it = subscribeInfos_.begin(); it != subscribeInfos_.end(); ++it) {
        if (it->GetSubscribeId() == subscribeId) {
            if (MMIEventHdl.UnsubscribeHotkey(subscribeId) != RET_OK) {
                MMI_HILOGE("UnsubscribeHotkey fail");
                return RET_ERR;
            }
            subscribeInfos_.erase(it);
            return RET_OK;
        }
    }
    return RET_ERR;
}

int32_t KeyEventInputSubscribeManager::OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event,
    int32_t subscribeId)
{
    CHK_PID_AND_TID();
    CHKPR(event, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_HILOGE("Leave, the subscribe id is less than 0");
        return RET_ERR;
    }

    BytraceAdapter::StartBytrace(event, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
    std::shared_ptr<const KeyEventInputSubscribeManager::SubscribeKeyEventInfo> info =
        GetSubscribeKeyEvent(subscribeId);
    CHKPR(info, ERROR_NULL_POINTER);
    auto callback = info->GetCallback();
    if (!callback) {
        MMI_HILOGE("Callback is null");
        return RET_ERR;
    }
    callback(event);
    MMI_HILOGD("Key event id:%{public}d, keyCode:%{private}d", subscribeId, event->GetKeyCode());
    return RET_OK;
}

void KeyEventInputSubscribeManager::OnConnected()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscribeInfos_.empty()) {
        MMI_HILOGD("Leave, subscribeInfos_ is empty");
        return;
    }
    for (const auto& subscriberInfo : subscribeInfos_) {
        if (MMIEventHdl.SubscribeKeyEvent(subscriberInfo) != RET_OK) {
            MMI_HILOGE("Subscribe key event failed");
        }
    }
}

std::shared_ptr<const KeyEventInputSubscribeManager::SubscribeKeyEventInfo>
KeyEventInputSubscribeManager::GetSubscribeKeyEvent(int32_t id)
{
    if (id < 0) {
        MMI_HILOGE("Invalid input param id:%{public}d", id);
        return nullptr;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &subscriber : subscribeInfos_) {
        if (subscriber.GetSubscribeId() == id) {
            return std::make_shared<const SubscribeKeyEventInfo>(subscriber);
        }
    }
    return nullptr;
}
} // namespace MMI
} // namespace OHOS
