/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "key_event_subscriber.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "net_packet.h"
#include "proto.h"
#include "input_event_handler.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "KeyEventSubscriber"};
constexpr uint8_t MAX_PRE_KEY_COUNT = 4;
}

int32_t KeyEventSubscriber::SubscribeKeyEvent(
        SessionPtr sess, int32_t subscribeId, std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    MMI_LOGT("Enter");
    CHKR(subscribeId >= 0, PARAM_INPUT_INVALID, RET_ERR);
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(keyOption, ERROR_NULL_POINTER);
    int32_t preKeySize = keyOption->GetPreKeys().size();
    if (preKeySize > MAX_PRE_KEY_COUNT) {
        MMI_LOGE("Leave, pre key size %{public}d more than %{public}d", preKeySize, MAX_PRE_KEY_COUNT);
        return RET_ERR;
    }

    for (const auto &keyCode : keyOption->GetPreKeys()) {
        MMI_LOGD("keyOption->prekey:%{public}d", keyCode);
    }

    MMI_LOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
        subscribeId, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());

    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, keyOption);
    subscribers_.push_back(subscriber);

    InitSessionDeleteCallback();

    MMI_LOGT("Leave");
    return RET_OK;
}

int32_t KeyEventSubscriber::UnSubscribeKeyEvent(SessionPtr sess, int32_t subscribeId)
{
    MMI_LOGT("Enter, subscribeId:%{public}d", subscribeId);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it);
            MMI_LOGD("Leave");
            return RET_OK;
        }
    }

    MMI_LOGE("Leave, cannot find subscribe key event info");
    return RET_ERR;
}

bool KeyEventSubscriber::FilterSubscribeKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_LOGT("Enter");
    CHKPF(keyEvent, ERROR_NULL_POINTER);
    int32_t keyAction = keyEvent->GetKeyAction();
    MMI_LOGD("keyCode:%{public}d,keyAction:%{public}s", keyEvent->GetKeyCode(), KeyEvent::ActionToString(keyAction));
    for (const auto &keyCode : keyEvent->GetPressedKeys()) {
        MMI_LOGD("pressed KeyCode:%{public}d", keyCode);
    }
    bool handled = false;
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        handled = HandleKeyDown(keyEvent);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        handled = HandleKeyUp(keyEvent);
    } else {
        handled = HandleKeyCanel(keyEvent);
    }
    keyEvent_.reset();

    MMI_LOGT("Leave");
    return handled;
}

void KeyEventSubscriber::OnSessionDelete(SessionPtr sess)
{
    MMI_LOGT("Enter");
    for (auto it = subscribers_.begin(); it != subscribers_.end();) {
        if ((*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it++);
            continue;
        }
        ++it;
    }

    MMI_LOGT("Leave");
}

bool KeyEventSubscriber::IsPreKeysMatch(const std::vector<int32_t>& preKeys,
        const std::vector<int32_t>& pressedKeys) const
{
    if (preKeys.size() != pressedKeys.size()) {
        return false;
    }

    for (const auto &pressedKey : pressedKeys) {
        auto it = std::find(preKeys.begin(), preKeys.end(), pressedKey);
        if (it == preKeys.end()) {
            return false;
        }
    }

    return true;
}

void KeyEventSubscriber::NotifySubscriber(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
        const std::shared_ptr<Subscriber>& subscriber)
{
    MMI_LOGT("Enter");
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    OHOS::MMI::NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_LOGE("Leave, server disaptch subscriber failed");
        return;
    }
    MMI_LOGT("Leave");
}

bool KeyEventSubscriber::AddTimer(const std::shared_ptr<Subscriber>& subscriber,
        const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGT("Enter");
    CHKPF(subscriber, ERROR_NULL_POINTER);

    if (subscriber->timerId_ >= 0) {
        MMI_LOGW("Leave, timer already added, it may have been added by injection");
        return true;
    }

    auto& keyOption = subscriber->keyOption_;
    if (keyOption->GetFinalKeyDownDuration() <= 0) {
        MMI_LOGE("Leave, duration <= 0");
        return true;
    }

    if (!CloneKeyEvent(keyEvent)) {
        MMI_LOGE("Leave, cloneKeyEvent failed");
        return false;
    }

    std::weak_ptr<Subscriber> weakSubscriber = subscriber;
    subscriber->timerId_ = TimerMgr->AddTimer(keyOption->GetFinalKeyDownDuration(), 1, [this, weakSubscriber] () {
        MMI_LOGD("timer callback");
        auto subscriber = weakSubscriber.lock();
        CHKPV(subscriber);
        OnTimer(subscriber);
    });

    if (subscriber->timerId_ < 0) {
        MMI_LOGE("Leave, addTimer failed");
        return false;
    }
    subscriber->keyEvent_ = keyEvent_;
    MMI_LOGT("Leave, add timer success, subscribeId:%{public}d,"
        "duration:%{public}d,timerId:%{public}d",
        subscriber->id_, keyOption->GetFinalKeyDownDuration(), subscriber->timerId_);
    return true;
}

void KeyEventSubscriber::ClearTimer(const std::shared_ptr<Subscriber>& subscriber)
{
    MMI_LOGT("Enter");
    CHKPV(subscriber);

    if (subscriber->timerId_ < 0) {
        MMI_LOGE("Leave, subscribeId:%{public}d,null timerId < 0", subscriber->id_);
        return;
    }

    auto timerId = subscriber->timerId_;
    subscriber->keyEvent_.reset();
    subscriber->timerId_ = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_LOGT("Leave, subscribeId:%{public}d,subscribeId:%{public}d", subscriber->id_, timerId);
}

void KeyEventSubscriber::OnTimer(const std::shared_ptr<Subscriber> subscriber)
{
    MMI_LOGT("Enter");
    CHKPV(subscriber);

    subscriber->timerId_ = -1;
    if (subscriber->keyEvent_ == nullptr) {
        MMI_LOGE("Leave, subscriber->keyEvent is nullptr, subscribeId:%{public}d", subscriber->id_);
        return;
    }

    NotifySubscriber(subscriber->keyEvent_, subscriber);
    subscriber->keyEvent_.reset();
    MMI_LOGT("Leave, subscribeId:%{public}d", subscriber->id_);
}

bool KeyEventSubscriber::InitSessionDeleteCallback()
{
    MMI_LOGT("Enter");
    if (callbackInitialized_)  {
        MMI_LOGD("session delete callback has already been initialized");
        return true;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    std::function<void(SessionPtr)> callback = std::bind(&KeyEventSubscriber::OnSessionDelete,
            this, std::placeholders::_1);
    udsServerPtr->AddSessionDeletedCallback(callback);

    callbackInitialized_ = true;
    MMI_LOGT("Leave");
    return true;
}

bool KeyEventSubscriber::HandleKeyDown(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGT("Enter");
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(keyCode, pressedKeys);
    for (const auto &subscriber : subscribers_) {
        auto& keyOption = subscriber->keyOption_;
        MMI_LOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
            "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
            subscriber->id_, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
            keyOption->GetFinalKeyDownDuration());
        for (const auto &keyCode : keyOption->GetPreKeys()) {
            MMI_LOGD("keyOption->prekey:%{public}d", keyCode);
        }

        if (!keyOption->IsFinalKeyDown()) {
            MMI_LOGD("!keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            ClearTimer(subscriber);
            MMI_LOGD("keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            ClearTimer(subscriber);
            MMI_LOGD("preKeysMatch failed");
            continue;
        }

        if (keyOption->GetFinalKeyDownDuration() <= 0) {
            MMI_LOGD("keyOption->GetFinalKeyDownDuration() <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
            continue;
        }

        if (!AddTimer(subscriber, keyEvent)) {
            MMI_LOGE("Leave, add timer failed");
        }
    }

    MMI_LOGT("Leave %{public}s", handled ? "true" : "false");
    return handled;
}

bool KeyEventSubscriber::HandleKeyUp(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGT("Enter");
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(keyCode, pressedKeys);
    for (const auto &subscriber : subscribers_) {
        auto& keyOption = subscriber->keyOption_;
        MMI_LOGD("subscribeId:%{public}d,keyOption->finalKey:%{public}d,"
            "keyOption->isFinalKeyDown:%{public}s,keyOption->finalKeyDownDuriation:%{public}d",
            subscriber->id_, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
            keyOption->GetFinalKeyDownDuration());
        for (auto keyCode : keyOption->GetPreKeys()) {
            MMI_LOGD("keyOption->prekey:%{public}d", keyCode);
        }

        if (keyOption->IsFinalKeyDown()) {
            ClearTimer(subscriber);
            MMI_LOGD("keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            MMI_LOGD("keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            MMI_LOGD("preKeysMatch failed");
            continue;
        }

        auto duration = keyOption->GetFinalKeyDownDuration();
        if (duration <= 0) {
            MMI_LOGD("duration <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
            continue;
        }

        const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
        CHKPF(keyItem);
        auto upTime = keyEvent->GetActionTime();
        auto downTime = keyItem->GetDownTime();
        if (upTime - downTime >= (duration * 1000)) {
            MMI_LOGE("upTime - downTime >= duration");
            continue;
        }

        MMI_LOGD("upTime - downTime < duration");
        NotifySubscriber(keyEvent, subscriber);
        handled = true;
    }

    MMI_LOGT("Leave %{public}s", handled ? "true" : "false");
    return handled;
}

bool KeyEventSubscriber::HandleKeyCanel(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGT("Enter");
    for (const auto &subscriber : subscribers_) {
        ClearTimer(subscriber);
    }
    MMI_LOGT("Leave");
    return false;
}

bool KeyEventSubscriber::CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent, ERROR_NULL_POINTER);
    if (keyEvent_ == nullptr) {
        MMI_LOGW("keyEvent_ is nullptr");
        keyEvent_ = KeyEvent::Clone(keyEvent);
    }
    CHKPF(keyEvent_);
    return true;
}

void KeyEventSubscriber::RemoveKeyCode(int32_t keyCode, std::vector<int32_t>& keyCodes)
{
    for (auto it = keyCodes.begin(); it != keyCodes.end(); ++it) {
        if (*it == keyCode) {
            keyCodes.erase(it);
            return;
        }
    }
}

}  // namespace MMI
}  // namespace OHOS
