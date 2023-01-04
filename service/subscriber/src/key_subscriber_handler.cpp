/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "key_subscriber_handler.h"

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "timer_manager.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "KeySubscriberHandler"};
constexpr uint32_t MAX_PRE_KEY_COUNT = 4;
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void KeySubscriberHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (OnSubscribeKeyEvent(keyEvent)) {
        MMI_HILOGD("Subscribe keyEvent filter success. keyCode:%{public}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_SUBSCRIBE_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void KeySubscriberHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeySubscriberHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t KeySubscriberHandler::SubscribeKeyEvent(
    SessionPtr sess, int32_t subscribeId, std::shared_ptr<KeyOption> keyOption)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribe");
        return RET_ERR;
    }
    CHKPR(sess, ERROR_NULL_POINTER);
    CHKPR(keyOption, ERROR_NULL_POINTER);
    uint32_t preKeySize = keyOption->GetPreKeys().size();
    if (preKeySize > MAX_PRE_KEY_COUNT) {
        MMI_HILOGE("Leave, preKeySize:%{public}u", preKeySize);
        return RET_ERR;
    }

    for (const auto &keyCode : keyOption->GetPreKeys()) {
        MMI_HILOGD("keyOption->prekey:%{public}d", keyCode);
    }
    MMI_HILOGD("subscribeId:%{public}d, keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s, keyOption->finalKeyDownDuration:%{public}d",
        subscribeId, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, keyOption);
    InsertSubScriber(subscriber);
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t KeySubscriberHandler::UnsubscribeKeyEvent(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("subscribeId:%{public}d", subscribeId);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it);
            return RET_OK;
        }
    }
    return RET_ERR;
}

bool KeySubscriberHandler::OnSubscribeKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (IsRepeatedKeyEvent(keyEvent)) {
        MMI_HILOGD("Repeat KeyEvent, skip");
        return true;
    }
    keyEvent_ = KeyEvent::Clone(keyEvent);
    int32_t keyAction = keyEvent->GetKeyAction();
    MMI_HILOGD("keyCode:%{public}d, keyAction:%{public}s", keyEvent->GetKeyCode(),
        KeyEvent::ActionToString(keyAction));
    for (const auto &keyCode : keyEvent->GetPressedKeys()) {
        MMI_HILOGD("Pressed KeyCode:%{public}d", keyCode);
    }
    bool handled = false;
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        handled = HandleKeyDown(keyEvent);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        hasEventExecuting_ = false;
        handled = HandleKeyUp(keyEvent);
    } else if (keyAction == KeyEvent::KEY_ACTION_CANCEL) {
        hasEventExecuting_ = false;
        handled = HandleKeyCancel(keyEvent);
    } else {
        MMI_HILOGW("keyAction exception");
    }
    return handled;
}

void KeySubscriberHandler::InsertSubScriber(std::shared_ptr<Subscriber> subs)
{
    CALL_DEBUG_ENTER;
    CHKPV(subs);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if (subs->sess_ != nullptr && (*it)->id_ == subs->id_ && (*it)->sess_ == subs->sess_) {
            MMI_HILOGW("Repeat registration id:%{public}d desc:%{public}s",
                subs->id_, subs->sess_->GetDescript().c_str());
            return;
        }
    }
    subscribers_.push_back(subs);
}

void KeySubscriberHandler::OnSessionDelete(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    for (auto it = subscribers_.begin(); it != subscribers_.end();) {
        if ((*it)->sess_ == sess) {
            ClearTimer(*it);
            subscribers_.erase(it++);
            continue;
        }
        ++it;
    }
}

bool KeySubscriberHandler::IsPreKeysMatch(const std::set<int32_t> &preKeys,
                                          const std::vector<int32_t> &pressedKeys) const
{
    if (preKeys.size() == 0) {
        return true;
    }

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

void KeySubscriberHandler::NotifySubscriber(std::shared_ptr<KeyEvent> keyEvent,
                                            const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(subscriber);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
        return;
    }
}

bool KeySubscriberHandler::AddTimer(const std::shared_ptr<Subscriber> &subscriber,
                                    const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    CHKPF(subscriber);

    if (subscriber->timerId_ >= 0) {
        MMI_HILOGW("Leave, timer already added, it may have been added by injection");
        return true;
    }

    auto &keyOption = subscriber->keyOption_;
    bool isKeyDown = keyOption->IsFinalKeyDown();
    int32_t duration = isKeyDown ? keyOption->GetFinalKeyDownDuration() : keyOption->GetFinalKeyUpDelay();
    if (duration <= 0) {
        MMI_HILOGE("Leave, duration <= 0");
        return true;
    }

    if (!CloneKeyEvent(keyEvent)) {
        MMI_HILOGE("Leave, cloneKeyEvent failed");
        return false;
    }

    std::weak_ptr<Subscriber> weakSubscriber = subscriber;
    subscriber->timerId_ = TimerMgr->AddTimer(duration, 1, [this, weakSubscriber] () {
        MMI_HILOGD("Timer callback");
        auto subscriber = weakSubscriber.lock();
        CHKPV(subscriber);
        OnTimer(subscriber);
    });

    if (subscriber->timerId_ < 0) {
        MMI_HILOGE("Leave, addTimer failed");
        return false;
    }
    subscriber->keyEvent_ = keyEvent_;
    hasEventExecuting_ = true;
    MMI_HILOGD("Leave, add timer success, subscribeId:%{public}d,"
        "duration:%{public}d, timerId:%{public}d",
        subscriber->id_, duration, subscriber->timerId_);
    return true;
}

void KeySubscriberHandler::ClearTimer(const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);

    if (subscriber->timerId_ < 0) {
        MMI_HILOGW("Leave, subscribeId:%{public}d, null timerId < 0", subscriber->id_);
        return;
    }

    TimerMgr->RemoveTimer(subscriber->timerId_);
    auto timerId = subscriber->timerId_;
    subscriber->keyEvent_.reset();
    subscriber->timerId_ = -1;
    hasEventExecuting_ = false;
    MMI_HILOGD("subscribeId:%{public}d, timerId:%{public}d", subscriber->id_, timerId);
}

void KeySubscriberHandler::OnTimer(const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    subscriber->timerId_ = -1;
    if (subscriber->keyEvent_ == nullptr) {
        MMI_HILOGE("Leave, subscriber->keyEvent is nullptr, subscribeId:%{public}d", subscriber->id_);
        return;
    }

    NotifySubscriber(subscriber->keyEvent_, subscriber);
    subscriber->keyEvent_.reset();
    MMI_HILOGD("subscribeId:%{public}d", subscriber->id_);
}

bool KeySubscriberHandler::InitSessionDeleteCallback()
{
    CALL_DEBUG_ENTER;
    if (callbackInitialized_) {
        MMI_HILOGD("Session delete callback has already been initialized");
        return true;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    std::function<void(SessionPtr)> callback =
        std::bind(&KeySubscriberHandler::OnSessionDelete, this, std::placeholders::_1);
    udsServerPtr->AddSessionDeletedCallback(callback);
    callbackInitialized_ = true;
    return true;
}

bool KeySubscriberHandler::HandleKeyDown(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(keyCode, pressedKeys);
    for (const auto &subscriber : subscribers_) {
        auto &keyOption = subscriber->keyOption_;
        MMI_HILOGD("subscribeId:%{public}d, keyOption->finalKey:%{public}d,"
            "keyOption->isFinalKeyDown:%{public}s, keyOption->finalKeyDownDuration:%{public}d",
            subscriber->id_, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
            keyOption->GetFinalKeyDownDuration());
        for (const auto &keyCode : keyOption->GetPreKeys()) {
            MMI_HILOGD("keyOption->prekey:%{public}d", keyCode);
        }

        if (!keyOption->IsFinalKeyDown()) {
            MMI_HILOGD("!keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            ClearTimer(subscriber);
            MMI_HILOGD("keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            ClearTimer(subscriber);
            MMI_HILOGD("preKeysMatch failed");
            continue;
        }

        if (keyOption->GetFinalKeyDownDuration() <= 0) {
            MMI_HILOGD("keyOption->GetFinalKeyDownDuration() <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
            continue;
        }

        if (!AddTimer(subscriber, keyEvent)) {
            MMI_HILOGE("Leave, add timer failed");
        }
    }
    MMI_HILOGD("%{public}s", handled ? "true" : "false");
    return handled;
}

bool KeySubscriberHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(keyCode, pressedKeys);
    for (const auto &subscriber : subscribers_) {
        PrintKeyUpLog(subscriber);
        auto &keyOption = subscriber->keyOption_;
        if (keyOption->IsFinalKeyDown()) {
            ClearTimer(subscriber);
            MMI_HILOGD("keyOption->IsFinalKeyDown()");
            continue;
        }

        if (keyCode != keyOption->GetFinalKey()) {
            MMI_HILOGD("keyCode != keyOption->GetFinalKey()");
            continue;
        }

        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            MMI_HILOGD("PreKeysMatch failed");
            continue;
        }

        if (!IsNotifyPowerKeySubsciber(keyOption->GetFinalKey(), pressedKeys)) {
            MMI_HILOGD("In special case, subscriber are not notified");
            continue;
        }

        auto duration = keyOption->GetFinalKeyDownDuration();
        if (duration <= 0) {
            MMI_HILOGD("duration <= 0");
            HandleKeyUpWithDelay(keyEvent, subscriber);
            handled = true;
            continue;
        }

        const KeyEvent::KeyItem* keyItem = keyEvent->GetKeyItem();
        CHKPF(keyItem);
        auto upTime = keyEvent->GetActionTime();
        auto downTime = keyItem->GetDownTime();
        if (upTime - downTime >= (static_cast<int64_t>(duration) * 1000)) {
            MMI_HILOGE("upTime - downTime >= duration");
            continue;
        }
        MMI_HILOGD("upTime - downTime < duration");
        HandleKeyUpWithDelay(keyEvent, subscriber);
        handled = true;
    }
    MMI_HILOGD("%{public}s", handled ? "true" : "false");
    return handled;
}

bool KeySubscriberHandler::HandleKeyCancel(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    for (const auto &subscriber : subscribers_) {
        ClearTimer(subscriber);
    }
    return false;
}

bool KeySubscriberHandler::CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (keyEvent_ == nullptr) {
        MMI_HILOGW("keyEvent_ is nullptr");
        keyEvent_ = KeyEvent::Clone(keyEvent);
    }
    CHKPF(keyEvent_);
    return true;
}

void KeySubscriberHandler::RemoveKeyCode(int32_t keyCode, std::vector<int32_t> &keyCodes)
{
    for (auto it = keyCodes.begin(); it != keyCodes.end(); ++it) {
        if (*it == keyCode) {
            keyCodes.erase(it);
            return;
        }
    }
}

bool KeySubscriberHandler::IsRepeatedKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (!hasEventExecuting_) {
        return false;
    }

    if (keyEvent->GetKeyCode() != keyEvent_->GetKeyCode()) {
        return false;
    }

    if (keyEvent->GetKeyAction() != keyEvent_->GetKeyAction()) {
        return false;
    }

    if (keyEvent->GetKeyItems().size() != keyEvent_->GetKeyItems().size()) {
        return false;
    }

    for (const auto &item : keyEvent->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        bool findResult = false;
        for (const auto &item1 : keyEvent_->GetKeyItems()) {
            if (keyCode == item1.GetKeyCode()) {
                findResult = true;
                break;
            }
        }
        if (!findResult) {
            return false;
        }
    }
    return true;
}

void KeySubscriberHandler::RemoveSubscriberKeyUpTimer(int32_t keyCode)
{
    for (const auto& item : subscribers_) {
        if ((item->timerId_ >= 0) && (item->keyOption_->GetFinalKey() == keyCode)) {
            ClearTimer(item);
        }
    }
}

bool KeySubscriberHandler::IsNotifyPowerKeySubsciber(int32_t keyCode, const std::vector<int32_t> &keyCodes)
{
    if (keyCode != KeyEvent::KEYCODE_POWER) {
        return true;
    }

    for (const auto& pressedKey: keyCodes) {
        if (pressedKey == KeyEvent::KEYCODE_VOLUME_DOWN || pressedKey == KeyEvent::KEYCODE_VOLUME_UP) {
            return false;
        }
    }
    return true;
}

void KeySubscriberHandler::HandleKeyUpWithDelay(std::shared_ptr<KeyEvent> keyEvent,
    const std::shared_ptr<Subscriber> &subscriber)
{
    auto keyUpDelay = subscriber->keyOption_->GetFinalKeyUpDelay();
    if (keyUpDelay <= 0) {
        NotifySubscriber(keyEvent, subscriber);
    } else {
        if (!AddTimer(subscriber, keyEvent)) {
            MMI_HILOGE("Leave, add timer failed");
        }
    }
}

void KeySubscriberHandler::PrintKeyUpLog(const std::shared_ptr<Subscriber> &subscriber)
{
    CHKPV(subscriber);
    auto &keyOption = subscriber->keyOption_;
    MMI_HILOGD("subscribeId:%{public}d, keyOption->finalKey:%{public}d,"
        "keyOption->isFinalKeyDown:%{public}s, keyOption->finalKeyDownDuration:%{public}d,"
        "keyOption->finalKeyUpDelay:%{public}d",
        subscriber->id_, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration(), keyOption->GetFinalKeyUpDelay());
    for (const auto &keyCode : keyOption->GetPreKeys()) {
        MMI_HILOGD("keyOption->prekey:%{public}d", keyCode);
    }
}

void KeySubscriberHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Subscriber information:\t");
    mprintf(fd, "subscribers: count=%d", subscribers_.size());
    for (const auto &item : subscribers_) {
        std::shared_ptr<Subscriber> subscriber = item;
        CHKPV(subscriber);
        SessionPtr session = item->sess_;
        CHKPV(session);
        std::shared_ptr<KeyOption> keyOption = item->keyOption_;
        CHKPV(keyOption);
        mprintf(fd,
                "subscriber id:%d | timer id:%d | Pid:%d | Uid:%d | Fd:%d "
                "| FinalKey:%d | finalKeyDownDuration:%d | IsFinalKeyDown:%s\t",
                subscriber->id_, subscriber->timerId_, session->GetPid(),
                session->GetUid(), session->GetFd(), keyOption->GetFinalKey(),
                keyOption->GetFinalKeyDownDuration(), keyOption->IsFinalKeyDown() ? "true" : "false");
        std::set<int32_t> preKeys = keyOption->GetPreKeys();
        for (const auto &preKey : preKeys) {
            mprintf(fd, "preKeys:%d\t", preKey);
        }
    }
}
} // namespace MMI
} // namespace OHOS
