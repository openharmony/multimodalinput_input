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

#include "key_event_input_subscribe_filter.h"
#include "bytrace.h"
#include "define_multimodal.h"
#include "input_event_data_transformation.h"
#include "net_packet.h"
#include "proto.h"
#include "input_event_handler.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "KeyEventInputSubscribeFilter"};
static const uint8_t MAX_PRE_KEY_COUNT = 4;
}

int32_t KeyEventInputSubscribeFilter::SubscribeKeyEvent(
        SessionPtr sess, int32_t subscribeId, std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
{
    MMI_LOGD("Enter");
    if (!sess) {
        MMI_LOGE("Leave, null sess.");
        return RET_ERR;
    }

    if (!keyOption) {
        MMI_LOGD("Leave, the [KeyOption] is nullptr.");
        return RET_ERR;
    }

    if (keyOption->GetPreKeySize() > MAX_PRE_KEY_COUNT) {
        MMI_LOGD("Leave, pre key size more than %{public}d", MAX_PRE_KEY_COUNT);
        return RET_ERR;
    }

    for (auto keyCode : keyOption->GetPreKeys()) {
        MMI_LOGD("KeyOption->prekey=%{public}s", KeyEvent::KeyCodeToString(keyCode));
    }

    MMI_LOGD("SubscribeId=%{public}d,KeyOption->finalKey=%{public}d,"
            "KeyOption->isFinalKeyDown=%{public}d,KeyOption->finalKeyDownDuriation=%{public}d",
            subscribeId, keyOption->GetFinalKey(), ((keyOption->IsFinalKeyDown() == true) ? 1 : 0),
            keyOption->GetFinalKeyDownDuration());

    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, keyOption);
    subscribers_.push_back(subscriber);

    InitSessionDeleteCallback();

    MMI_LOGD("Leave");
    return RET_OK;
}

int32_t KeyEventInputSubscribeFilter::UnSubscribeKeyEvent(SessionPtr sess, int32_t subscribeId)
{
    MMI_LOGD("Enter subscribeId:%{public}d", subscribeId);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it);
            MMI_LOGD("Leave");
            return RET_OK;
        }
    }

    MMI_LOGE("Leave");
    return RET_ERR;
}

bool KeyEventInputSubscribeFilter::FilterSubscribeKeyEvent(UDSServer& udsServer,
        std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent)
{
    MMI_LOGD("Enter");

    if (!keyEvent) {
        MMI_LOGE("Leave, no subscriber");
        return false;
    }
    int32_t getKeyCode = keyEvent->GetKeyCode();
    std::string keyCodestring = std::to_string(getKeyCode);
    MMI_LOGT(" FilterSubscribeKeyEvent service trace getKeyCode = %{public}d\n", getKeyCode);
    int32_t eventKey = 1;
    FinishAsyncTrace(BYTRACE_TAG_MULTIMODALINPUT, keyCodestring, eventKey);

    bool handled = false;
    int32_t keyAction = keyEvent->GetKeyAction();
    MMI_LOGD("KeyCode:%{public}d, KeyAction:%{public}s", keyEvent->GetKeyCode(), KeyEvent::ActionToString(keyAction));
    for (auto& keyCode : keyEvent->GetPressedKeys()) {
        MMI_LOGD("Pressed KeyCode:%{public}d", keyCode);
    }
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        handled = HandleKeyDown(keyEvent);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        handled = HandleKeyUp(keyEvent);
    } else {
        handled = HandleKeyCanel(keyEvent);
    }

    keyEvent_.reset();
    return handled;
}

void KeyEventInputSubscribeFilter::OnSessionLost(SessionPtr sess)
{
    MMI_LOGD("Enter");
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ) {
        if ((*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it++);
            continue;
        }
        ++it;
    }

    MMI_LOGD("Leave");
}

bool KeyEventInputSubscribeFilter::IsPreKeysMatch(const std::vector<int32_t>& preKeys,
        const std::vector<int32_t>& pressedKeys) const
{
    if (preKeys.size() != pressedKeys.size()) {
        return false;
    }

    for (auto pressedKey : pressedKeys) {
        auto it = std::find(preKeys.begin(), preKeys.end(), pressedKey);
        if (it == preKeys.end()) {
            return false;
        }
    }

    return true;
}

void KeyEventInputSubscribeFilter::NotifySubscriber(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
        const std::shared_ptr<Subscriber>& subscriber)
{
    MMI_LOGD("Enter");

    auto udsServerPtr = InputHandler->GetUDSServer();
    if (!udsServerPtr) {
        MMI_LOGE("Leave, null udsServerPtr");
        return;
    }

    auto& udsServer = *udsServerPtr;
    OHOS::MMI::NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_LOGE("Leave, server disaptch subscriber failed");
        return;
    }

    MMI_LOGD("Leave");
}

bool KeyEventInputSubscribeFilter::AddTimer(const std::shared_ptr<Subscriber>& subscriber,
        const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGD("Enter");

    if (!subscriber) {
        MMI_LOGE("Leave, null subscriber");
        return false;
    }

    if(subscriber->timerId_ >= 0) {
        MMI_LOGD("Leave, Timer Already Added");
        return true;
    }

    auto& keyOption = subscriber->keyOption_;
    if (keyOption->GetFinalKeyDownDuration() <= 0) {
        MMI_LOGE("Leave, Duration <= 0");
        return true;
    }

    if (!CloneKeyEvent(keyEvent)) {
        MMI_LOGE("Leave, CloneKeyEvent Failed");
        return false;
    }

    std::weak_ptr<Subscriber> weakSubscriber = subscriber;
    subscriber->timerId_ = TimerMgr->AddTimer(keyOption->GetFinalKeyDownDuration(), 1, [this, weakSubscriber] () {
        MMI_LOGD("TimerCallback");
        auto subscriber = weakSubscriber.lock();
        if (!subscriber) {
            MMI_LOGE("Leave, TimerCallback, null subscriber");
            return;
        }

        OnTimer(subscriber);
    });

    if (subscriber->timerId_ < 0) {
        MMI_LOGE("Leave, AddTimer Failed");
        return false;
    }
    subscriber->keyEvent_ = keyEvent_;
    MMI_LOGD("Leave, AddTimer Success, duration:%{public}d, timerId:%{public}d", keyOption->GetFinalKeyDownDuration(), subscriber->timerId_);
    return true;
}

void KeyEventInputSubscribeFilter::ClearTimer(const std::shared_ptr<Subscriber>& subscriber)
{
    MMI_LOGD("Enter");
    if (!subscriber) {
        MMI_LOGE("Leave, null subscriber");
        return;
    }

    if(subscriber->timerId_ < 0) {
        MMI_LOGE("Leave, subscribeId:%{public}d, null timerId < 0", subscriber->id_);
        return;
    }

    auto timerId = subscriber->timerId_;
    subscriber->keyEvent_.reset();
    subscriber->timerId_ = -1;
    TimerMgr->RemoveTimer(timerId);
    MMI_LOGD("Leave, subscribeId:%{public}d, subscribeId:%{public}d", subscriber->id_, timerId);
}

void KeyEventInputSubscribeFilter::OnTimer(const std::shared_ptr<Subscriber> subscriber) {
    MMI_LOGD("Enter");
    if (!subscriber) {
        MMI_LOGE("Leave, null subscriber");
        return;
    }

    subscriber->timerId_ = -1;
    if (!subscriber->keyEvent_) {
        MMI_LOGE("Leave, null keyEvent, subscribeId:%{public}d", subscriber->id_);
        return;
    }

    NotifySubscriber(subscriber->keyEvent_, subscriber);
    subscriber->keyEvent_.reset();
    MMI_LOGD("Leave, null keyEvent, subscribeId:%{public}d", subscriber->id_);
}

bool KeyEventInputSubscribeFilter::InitSessionDeleteCallback()
{
    MMI_LOGD("Enter");
    if (sessionDeletedCallbackInitialized_)  {
        MMI_LOGD("Leave");
        return true;
    }

    auto udsServerPtr = InputHandler->GetUDSServer();
    if (!udsServerPtr) {
        MMI_LOGE("Leave, null udsServer");
        return false;
    }

    std::function<void(SessionPtr)> callback = std::bind(&KeyEventInputSubscribeFilter::OnSessionLost,
            this, std::placeholders::_1);
    udsServerPtr->AddSessionDeletedCallback(callback);

    sessionDeletedCallbackInitialized_ = true;
    MMI_LOGD("Leave");
    return true;
}

bool KeyEventInputSubscribeFilter::HandleKeyDown(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGD("Enter");
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(pressedKeys, keyCode);
    for (auto& subscriber : subscribers_) {
        auto& keyOption = subscriber->keyOption_;
        MMI_LOGD("SubscribeId=%{public}d, KeyOption->finalKey=%{public}d, "
                "KeyOption->isFinalKeyDown=%{public}d, KeyOption->finalKeyDownDuriation=%{public}d",
                subscriber->id_, keyOption->GetFinalKey(), ((keyOption->IsFinalKeyDown() == true) ? 1 : 0),
                keyOption->GetFinalKeyDownDuration());
        for (auto keyCode : keyOption->GetPreKeys()) {
            MMI_LOGD("KeyOption->prekey=%{public}d", keyCode);
        }

        if (!keyOption->IsFinalKeyDown()) {
            MMI_LOGD("Skip, !keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            ClearTimer(subscriber);
            MMI_LOGD("Skip, keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            ClearTimer(subscriber);
            MMI_LOGD("Skip, PreKeysMatch Failed");
            continue;
        }

        if (keyOption->GetFinalKeyDownDuration() <= 0) {
            MMI_LOGD("Hit, keyOption->GetFinalKeyDownDuration() <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
            continue;
        }

        if (!AddTimer(subscriber, keyEvent)) {
            MMI_LOGE("Leave, AddTimer Failed");
        }
    }

    MMI_LOGD("Leave %{public}s", handled ? "true" : "false");
    return handled;
}

bool KeyEventInputSubscribeFilter::HandleKeyUp(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGD("Enter");
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(pressedKeys, keyCode);
    for (auto& subscriber : subscribers_) {
        auto& keyOption = subscriber->keyOption_;
        MMI_LOGD("SubscribeId=%{public}d, KeyOption->finalKey=%{public}d, "
                "KeyOption->isFinalKeyDown=%{public}d, KeyOption->finalKeyDownDuriation=%{public}d",
                subscriber->id_, keyOption->GetFinalKey(), ((keyOption->IsFinalKeyDown() == true) ? 1 : 0),
                keyOption->GetFinalKeyDownDuration());
        for (auto keyCode : keyOption->GetPreKeys()) {
            MMI_LOGD("KeyOption->prekey=%{public}d", keyCode);
        }

        if (keyOption->IsFinalKeyDown()) {
            ClearTimer(subscriber);
            MMI_LOGD("Skip, keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            MMI_LOGD("Skip, keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            MMI_LOGD("Skip, PreKeysMatch Failed");
            continue;
        }

        auto duration = keyOption->GetFinalKeyDownDuration();
        if (duration <= 0) {
            MMI_LOGD("Hit, duration <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
            continue;
        }

        const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
        if (keyItem == nullptr) {
            MMI_LOGE("Skip, null keyItem");
            continue;
        }

        auto upTime = keyEvent->GetActionTime();
        auto downTime = keyItem->GetDownTime();
        if (upTime - downTime >= duration) {
            MMI_LOGE("Skip, upTime - downTime >= duration");
            continue;
        }

        MMI_LOGD("Hit, upTime - downTime < duration");
        NotifySubscriber(keyEvent, subscriber);
        handled = true;
    }

    MMI_LOGD("Leave %{public}s", handled ? "true" : "false");
    return handled;
}

bool KeyEventInputSubscribeFilter::HandleKeyCanel(const std::shared_ptr<KeyEvent>& keyEvent)
{
    MMI_LOGD("Enter");
    for (auto& subscriber : subscribers_) {
        ClearTimer(subscriber);
    }
    MMI_LOGD("Leave");
    return false;
}

bool KeyEventInputSubscribeFilter::CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    if (!keyEvent) {
        return false;
    }

    if (!keyEvent_) {
        keyEvent_ = KeyEvent::Clone(keyEvent);
    }

    if (!keyEvent_) {
        MMI_LOGE("Leave, Clone keyEvent Failed");
        return false;
    }

    return true;
}

void KeyEventInputSubscribeFilter::RemoveKeyCode(std::vector<int32_t>& keyCodes, int32_t keyCode)
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
