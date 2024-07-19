/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "key_subscriber_handler.h"

#include "app_state_observer.h"
#include "bytrace_adapter.h"
#include "call_manager_client.h"
#include "define_multimodal.h"
#include "device_event_monitor.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "event_log_helper.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeySubscriberHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t MAX_PRE_KEY_COUNT { 4 };
constexpr int32_t REMOVE_OBSERVER { -2 };
constexpr int32_t UNOBSERVED { -1 };
constexpr int32_t ACTIVE_EVENT { 2 };
std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr = nullptr;
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
    CALL_DEBUG_ENTER;
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
    MMI_HILOGI("SubscribeId:%{public}d, finalKey:%{public}d,"
        "isFinalKeyDown:%{public}s, finalKeyDownDuration:%{public}d, pid:%{public}d",
        subscribeId, keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration(), sess->GetPid());
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, keyOption);
    if (keyGestureMgr_.ShouldIntercept(keyOption)) {
        AddKeyGestureSubscriber(subscriber, keyOption);
    } else {
        AddSubscriber(subscriber, keyOption);
    }
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t KeySubscriberHandler::UnsubscribeKeyEvent(SessionPtr sess, int32_t subscribeId)
{
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGI("SubscribeId:%{public}d, pid:%{public}d", subscribeId, sess->GetPid());
    int32_t ret = RemoveSubscriber(sess, subscribeId);
    if (ret != RET_OK) {
        ret = RemoveKeyGestureSubscriber(sess, subscribeId);
    }
    return ret;
}

int32_t KeySubscriberHandler::RemoveSubscriber(SessionPtr sess, int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    for (auto iter = subscriberMap_.begin(); iter != subscriberMap_.end(); iter++) {
        auto &subscribers = iter->second;
        for (auto it = subscribers.begin(); it != subscribers.end(); it++) {
            if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
                ClearTimer(*it);
                auto option = (*it)->keyOption_;
                CHKPR(option, ERROR_NULL_POINTER);
                MMI_HILOGI("SubscribeId:%{public}d, finalKey:%{public}d, isFinalKeyDown:%{public}s,"
                    "finalKeyDownDuration:%{public}d, pid:%{public}d", subscribeId, option->GetFinalKey(),
                    option->IsFinalKeyDown() ? "true" : "false", option->GetFinalKeyDownDuration(), sess->GetPid());
                subscribers.erase(it);
                return RET_OK;
            }
        }
    }
    return RET_ERR;
}

void KeySubscriberHandler::AddKeyGestureSubscriber(
    std::shared_ptr<Subscriber> subscriber, std::shared_ptr<KeyOption> keyOption)
{
    CALL_INFO_TRACE;
    CHKPV(subscriber);
    CHKPV(subscriber->sess_);
    subscriber->timerId_ = keyGestureMgr_.AddKeyGesture(subscriber->sess_->GetPid(), keyOption,
        [this, subscriber](std::shared_ptr<KeyEvent> keyEvent) {
            NotifySubscriber(keyEvent, subscriber);
        });
    MMI_HILOGI("Handler(%{public}d) of key gesture was added", subscriber->timerId_);
    PrintKeyOption(keyOption);
    for (auto &iter : keyGestures_) {
        if (IsEqualKeyOption(keyOption, iter.first)) {
            iter.second.push_back(subscriber);
            return;
        }
    }
    keyGestures_[keyOption] = { subscriber };
}

int32_t KeySubscriberHandler::RemoveKeyGestureSubscriber(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    for (auto iter = keyGestures_.begin(); iter != keyGestures_.end(); ++iter) {
        auto &subscribers = iter->second;

        for (auto innerIter = subscribers.begin(); innerIter != subscribers.end(); ++innerIter) {
            auto subscriber = *innerIter;

            if ((subscriber->id_ != subscribeId) || (subscriber->sess_ != sess)) {
                continue;
            }
            MMI_HILOGI("Removing handler(%{public}d) of key gesture", subscriber->timerId_);
            keyGestureMgr_.RemoveKeyGesture(subscriber->timerId_);
            auto option = subscriber->keyOption_;
            MMI_HILOGI("SubscribeId:%{public}d, finalKey:%{public}d, isFinalKeyDown:%{public}s,"
                "finalKeyDownDuration:%{public}d, pid:%{public}d", subscribeId, option->GetFinalKey(),
                option->IsFinalKeyDown() ? "true" : "false", option->GetFinalKeyDownDuration(), sess->GetPid());
            subscribers.erase(innerIter);
            return RET_OK;
        }
    }
    return RET_ERR;
}

void KeySubscriberHandler::AddSubscriber(std::shared_ptr<Subscriber> subscriber,
    std::shared_ptr<KeyOption> option)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    CHKPV(option);
    PrintKeyOption(option);
    for (auto &iter : subscriberMap_) {
        if (IsEqualKeyOption(option, iter.first)) {
            MMI_HILOGI("Add subscriber Id:%{public}d", subscriber->id_);
            iter.second.push_back(std::move(subscriber));
            MMI_HILOGI("Subscriber size:%{public}zu", iter.second.size());
            return;
        }
    }
    MMI_HILOGI("Add subscriber Id:%{public}d", subscriber->id_);
    subscriberMap_[option] = {subscriber};
}

bool KeySubscriberHandler::IsEqualKeyOption(std::shared_ptr<KeyOption> newOption,
    std::shared_ptr<KeyOption> oldOption)
{
    CALL_DEBUG_ENTER;
    CHKPF(newOption);
    CHKPF(oldOption);
    if (!IsEqualPreKeys(newOption->GetPreKeys(), oldOption->GetPreKeys())) {
        MMI_HILOGD("Pre key not match");
        return false;
    }
    if (newOption->GetFinalKey() != oldOption->GetFinalKey()) {
        MMI_HILOGD("Final key not match");
        return false;
    }
    if (newOption->IsFinalKeyDown() != oldOption->IsFinalKeyDown()) {
        MMI_HILOGD("Is final key down not match");
        return false;
    }
    if (newOption->GetFinalKeyDownDuration() != oldOption->GetFinalKeyDownDuration()) {
        MMI_HILOGD("Final key down duration not match");
        return false;
    }
    if (newOption->GetFinalKeyUpDelay() != oldOption->GetFinalKeyUpDelay()) {
        MMI_HILOGD("Is final key up delay not match");
        return false;
    }
    MMI_HILOGD("Key option match");
    return true;
}

void KeySubscriberHandler::GetForegroundPids(std::set<int32_t> &pids)
{
    CALL_DEBUG_ENTER;
    std::vector<AppExecFwk::AppStateData> list = APP_OBSERVER_MGR->GetForegroundAppData();
    for (auto iter = list.begin(); iter != list.end(); iter++) {
        MMI_HILOGD("Foreground process pid:%{public}d", (*iter).pid);
        pids.insert((*iter).pid);
    }
}

int32_t KeySubscriberHandler::EnableCombineKey(bool enable)
{
    enableCombineKey_ = enable;
    MMI_HILOGI("Enable combineKey is successful in subscribe handler, enable:%{public}d", enable);
    return RET_OK;
}

bool KeySubscriberHandler::IsFunctionKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    MMI_HILOGD("Is Funciton Key In");
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_BRIGHTNESS_DOWN
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_BRIGHTNESS_UP) {
        return true;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_UP
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_DOWN
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_MUTE) {
        return true;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_MUTE
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_SWITCHVIDEOMODE
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_WLAN
        || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_CONFIG) {
        return true;
    }
    return false;
}

bool KeySubscriberHandler::IsEnableCombineKey(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    if (enableCombineKey_) {
        return true;
    }
    if (IsFunctionKey(keyEvent)) {
        auto items = keyEvent->GetKeyItems();
        return items.size() != 1 ? enableCombineKey_ : true;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER && keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        auto items = keyEvent->GetKeyItems();
        if (items.size() != 1) {
            return enableCombineKey_;
        }
        return true;
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_DPAD_RIGHT ||
        keyEvent->GetKeyCode() == KeyEvent::KEYCODE_DPAD_LEFT) {
        MMI_HILOGD("Subscriber mulit swipe keycode is:%{public}d", keyEvent->GetKeyCode());
        return IsEnableCombineKeySwipe(keyEvent);
    }
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_L) {
        for (const auto &item : keyEvent->GetKeyItems()) {
            int32_t keyCode = item.GetKeyCode();
            if (keyCode != KeyEvent::KEYCODE_L && keyCode != KeyEvent::KEYCODE_META_LEFT &&
                keyCode != KeyEvent::KEYCODE_META_RIGHT) {
                return enableCombineKey_;
            }
        }
        return true;
    }
    return enableCombineKey_;
}

bool KeySubscriberHandler::IsEnableCombineKeySwipe(const std::shared_ptr<KeyEvent> keyEvent)
{
    for (const auto &item : keyEvent->GetKeyItems()) {
        int32_t keyCode = item.GetKeyCode();
        if (keyCode != KeyEvent::KEYCODE_CTRL_LEFT && keyCode != KeyEvent::KEYCODE_META_LEFT &&
            keyCode != KeyEvent::KEYCODE_DPAD_RIGHT && keyCode != KeyEvent::KEYCODE_CTRL_RIGHT &&
            keyCode != KeyEvent::KEYCODE_DPAD_LEFT) {
            return enableCombineKey_;
        }
    }
    return true;
}

bool KeySubscriberHandler::HandleRingMute(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (keyEvent->GetKeyCode() != KeyEvent::KEYCODE_VOLUME_DOWN &&
        keyEvent->GetKeyCode() != KeyEvent::KEYCODE_VOLUME_UP &&
        keyEvent->GetKeyCode() != KeyEvent::KEYCODE_POWER) {
        MMI_HILOGD("There is no need to set mute");
        return false;
    }
    int32_t ret = -1;
    if (DEVICE_MONITOR->GetCallState() == StateType::CALL_STATUS_INCOMING) {
        if (callManagerClientPtr == nullptr) {
            callManagerClientPtr = DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
            if (callManagerClientPtr == nullptr) {
                MMI_HILOGE("CallManager init fail");
                return false;
            }
            callManagerClientPtr->Init(OHOS::TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
        }
        if (!DEVICE_MONITOR->GetHasHandleRingMute()) {
            ret = callManagerClientPtr->MuteRinger();
            if (ret != ERR_OK) {
                MMI_HILOGE("Set mute fail, ret:%{public}d", ret);
                return false;
            }
            MMI_HILOGI("Set mute success");
            DEVICE_MONITOR->SetHasHandleRingMute(true);
            if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
                needSkipPowerKeyUp_ = true;
            }
            return true;
        } else {
            if (keyEvent->GetKeyCode() != KeyEvent::KEYCODE_POWER) {
                MMI_HILOGD("Set mute success, block volumeKey");
                return true;
            }
        }
    }
    return false;
}

bool KeySubscriberHandler::OnSubscribeKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    if (HandleRingMute(keyEvent)) {
        MMI_HILOGI("Mute Ring in subscribe keyEvent");
        return true;
    }
    if (!IsEnableCombineKey(keyEvent)) {
        MMI_HILOGI("Combine key is taken over in subscribe keyEvent");
        return false;
    }
    if (keyGestureMgr_.Intercept(keyEvent)) {
        MMI_HILOGD("Key gesture recognized");
        return true;
    }
    if (IsRepeatedKeyEvent(keyEvent)) {
        MMI_HILOGD("Repeat KeyEvent, skip");
        return true;
    }
    keyEvent_ = KeyEvent::Clone(keyEvent);
    int32_t keyAction = keyEvent->GetKeyAction();
    MMI_HILOGD("keyCode:%{public}d, keyAction:%{public}s", keyEvent->GetKeyCode(),
        KeyEvent::ActionToString(keyAction));
    if (needSkipPowerKeyUp_ && keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER
        && keyAction == KeyEvent::KEY_ACTION_UP) {
        MMI_HILOGD("Skip power key up");
        needSkipPowerKeyUp_ = false;
        return true;
    }
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

void KeySubscriberHandler::OnSessionDelete(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    for (auto iter = subscriberMap_.begin(); iter != subscriberMap_.end(); iter++) {
        auto &subscribers = iter->second;
        for (auto it = subscribers.begin(); it != subscribers.end();) {
            if ((*it)->sess_ == sess) {
                ClearTimer(*it);
                subscribers.erase(it++);
                continue;
            }
            ++it;
        }
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

bool KeySubscriberHandler::IsEqualPreKeys(const std::set<int32_t> &preKeys, const std::set<int32_t> &pressedKeys)
{
    if (preKeys.size() != pressedKeys.size()) {
        MMI_HILOGD("Pre key size not equal");
        return false;
    }

    for (const auto &pressedKey : pressedKeys) {
        auto it = std::find(preKeys.begin(), preKeys.end(), pressedKey);
        if (it == preKeys.end()) {
            return false;
        }
    }
    MMI_HILOGD("Equal prekeys");
    return true;
}

bool KeySubscriberHandler::IsMatchForegroundPid(std::list<std::shared_ptr<Subscriber>> subs,
    std::set<int32_t> foregroundPids)
{
    CALL_DEBUG_ENTER;
    isForegroundExits_ = false;
    foregroundPids_.clear();
    for (const auto &item : subs) {
        CHKPF(item);
        auto sess = item->sess_;
        CHKPF(sess);
        if (foregroundPids.find(sess->GetPid()) != foregroundPids.end()) {
            MMI_HILOGD("Subscriber foregroundPid:%{public}d", sess->GetPid());
            foregroundPids_.insert(sess->GetPid());
            isForegroundExits_ = true;
        }
    }
    MMI_HILOGD("isForegroundExits_:%{public}d, foregroundPids:%{public}zu",
        isForegroundExits_, foregroundPids_.size());
    return isForegroundExits_;
}

void KeySubscriberHandler::NotifyKeyDownSubscriber(const std::shared_ptr<KeyEvent> &keyEvent,
    std::shared_ptr<KeyOption> keyOption, std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(keyOption);
    MMI_HILOGD("Notify key down subscribers size:%{public}zu", subscribers.size());
    if (keyOption->GetFinalKeyDownDuration() <= 0) {
        NotifyKeyDownRightNow(keyEvent, subscribers, handled);
    } else {
        NotifyKeyDownDelay(keyEvent, subscribers, handled);
    }
}
void KeySubscriberHandler::NotifyKeyDownRightNow(const std::shared_ptr<KeyEvent> &keyEvent,
    std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("The subscribe list size is %{public}zu", subscribers.size());
    for (auto &subscriber : subscribers) {
        CHKPC(subscriber);
        auto sess = subscriber->sess_;
        CHKPC(sess);
        if (!isForegroundExits_ || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER ||
            foregroundPids_.find(sess->GetPid()) != foregroundPids_.end()) {
            MMI_HILOGD("keyOption->GetFinalKeyDownDuration() <= 0");
            NotifySubscriber(keyEvent, subscriber);
            handled = true;
        }
    }
}

void KeySubscriberHandler::NotifyKeyDownDelay(const std::shared_ptr<KeyEvent> &keyEvent,
    std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("The subscribe list size is %{public}zu", subscribers.size());
    for (auto &subscriber : subscribers) {
        CHKPC(subscriber);
        auto sess = subscriber->sess_;
        CHKPC(sess);
        if (!isForegroundExits_ || keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER ||
            foregroundPids_.find(sess->GetPid()) != foregroundPids_.end()) {
            MMI_HILOGD("Add timer");
            if (!AddTimer(subscriber, keyEvent)) {
                MMI_HILOGE("Add time failed, subscriberId:%{public}d", subscriber->id_);
                continue;
            }
            handled = true;
        }
    }
}

void KeySubscriberHandler::NotifyKeyUpSubscriber(const std::shared_ptr<KeyEvent> &keyEvent,
    std::list<std::shared_ptr<Subscriber>> subscribers, bool &handled)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Subscribers size:%{public}zu", subscribers.size());
    for (auto &subscriber : subscribers) {
        CHKPC(subscriber);
        auto sess = subscriber->sess_;
        CHKPC(sess);
        if (!isForegroundExits_ || foregroundPids_.find(sess->GetPid()) != foregroundPids_.end()) {
            HandleKeyUpWithDelay(keyEvent, subscriber);
            handled = true;
        }
    }
}

void KeySubscriberHandler::NotifySubscriber(std::shared_ptr<KeyEvent> keyEvent,
    const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    CHKPV(subscriber);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
        DfxHisysevent::ReportPowerInfo(keyEvent, OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC);
    }
    SubscriberNotifyNap(subscriber);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_KEY);
    InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt);
    auto sess = subscriber->sess_;
    CHKPV(sess);
    int32_t fd = sess->GetFd();
    pkt << fd << subscriber->id_;
    if (!EventLogHelper::IsBetaVersion()) {
        MMI_HILOGI("Notify subscriber id:%{public}d, pid:%{public}d", subscriber->id_, sess->GetPid());
    } else {
        MMI_HILOGI("Notify subscriber id:%{public}d, keycode:%{public}d, pid:%{public}d",
            subscriber->id_, keyEvent->GetKeyCode(), sess->GetPid());
    }
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

void KeySubscriberHandler::ClearSubscriberTimer(std::list<std::shared_ptr<Subscriber>> subscribers)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Clear subscriber timer size:%{public}zu", subscribers.size());
    for (auto &subscriber : subscribers) {
        CHKPC(subscriber);
        ClearTimer(subscriber);
    }
}

void KeySubscriberHandler::ClearTimer(const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);

    if (subscriber->timerId_ < 0) {
        MMI_HILOGD("Leave, subscribeId:%{public}d, null timerId < 0", subscriber->id_);
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
        [this] (SessionPtr sess) { return this->OnSessionDelete(sess); };
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
    std::set<int32_t> pids;
    GetForegroundPids(pids);
    MMI_HILOGI("Foreground pid size:%{public}zu", pids.size());
    for (auto &iter : subscriberMap_) {
        auto keyOption = iter.first;
        auto subscribers = iter.second;
        PrintKeyOption(keyOption);
        IsMatchForegroundPid(subscribers, pids);
        if (!keyOption->IsFinalKeyDown()) {
            MMI_HILOGD("!keyOption->IsFinalKeyDown()");
            continue;
        }
        if (keyCode != keyOption->GetFinalKey()) {
            MMI_HILOGD("keyCode != keyOption->GetFinalKey()");
            ClearSubscriberTimer(subscribers);
            continue;
        }
        if (!IsPreKeysMatch(keyOption->GetPreKeys(), pressedKeys)) {
            MMI_HILOGD("preKeysMatch failed");
            ClearSubscriberTimer(subscribers);
            continue;
        }
        NotifyKeyDownSubscriber(keyEvent, keyOption, subscribers, handled);
    }
    MMI_HILOGD("Handle key down:%{public}s", handled ? "true" : "false");
    return handled;
}

void KeySubscriberHandler::SubscriberNotifyNap(const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    int32_t state = NapProcess::GetInstance()->GetNapClientPid();
    if (state == REMOVE_OBSERVER || state == UNOBSERVED) {
        MMI_HILOGD("Nap client status:%{public}d", state);
        return;
    }

    auto sess = subscriber->sess_;
    CHKPV(sess);
    OHOS::MMI::NapProcess::NapStatusData napData;
    napData.pid = sess->GetPid();
    napData.uid = sess->GetUid();
    napData.bundleName = sess->GetProgramName();
    if (NapProcess::GetInstance()->IsNeedNotify(napData)) {
        int32_t syncState = ACTIVE_EVENT;
        NapProcess::GetInstance()->AddMmiSubscribedEventData(napData, syncState);
        NapProcess::GetInstance()->NotifyBundleName(napData, syncState);
    }
}

bool KeySubscriberHandler::HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    bool handled = false;
    auto keyCode = keyEvent->GetKeyCode();
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    RemoveKeyCode(keyCode, pressedKeys);
    std::set<int32_t> pids;
    GetForegroundPids(pids);
    for (auto &iter : subscriberMap_) {
        auto keyOption = iter.first;
        auto subscribers = iter.second;
        PrintKeyOption(keyOption);
        IsMatchForegroundPid(subscribers, pids);
        if (keyOption->IsFinalKeyDown()) {
            MMI_HILOGD("keyOption->IsFinalKeyDown()");
            ClearSubscriberTimer(subscribers);
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
            NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
            continue;
        }
        std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
        CHK_KEY_ITEM(keyItem);
        auto upTime = keyEvent->GetActionTime();
        auto downTime = keyItem->GetDownTime();
        if (upTime - downTime >= (static_cast<int64_t>(duration) * 1000)) {
            MMI_HILOGE("upTime - downTime >= duration");
            continue;
        }
        NotifyKeyUpSubscriber(keyEvent, subscribers, handled);
    }
    MMI_HILOGD("Handle key up:%{public}s", handled ? "true" : "false");
    return handled;
}

bool KeySubscriberHandler::HandleKeyCancel(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    for (auto &iter : subscriberMap_) {
        auto keyOption = iter.first;
        auto subscribers = iter.second;
        for (auto &subscriber : subscribers) {
            PrintKeyUpLog(subscriber);
            ClearTimer(subscriber);
        }
    }
    return false;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool KeySubscriberHandler::IsKeyEventSubscribed(int32_t keyCode, int32_t trrigerType)
{
    CALL_DEBUG_ENTER;
    for (const auto &iter : subscriberMap_) {
        auto keyOption = iter.first;
        auto subscribers = iter.second;
        MMI_HILOGD("keyOption->finalKey:%{public}d, keyOption->isFinalKeyDown:%{public}s, "
            "keyOption->finalKeyDownDuration:%{public}d",
            keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
            keyOption->GetFinalKeyDownDuration());
        int32_t keyAction = KeyEvent::KEY_ACTION_UP;
        if (keyOption->IsFinalKeyDown()) {
            MMI_HILOGD("keyOption is final key down");
            keyAction = KeyEvent::KEY_ACTION_DOWN;
        }
        if (keyCode == keyOption->GetFinalKey() && trrigerType == keyAction && subscribers.size() > 0) {
            MMI_HILOGD("Current key event is subscribed");
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

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
    for (auto iter = subscriberMap_.begin(); iter != subscriberMap_.end(); iter++) {
        auto &subscribers = iter->second;
        for (auto it = subscribers.begin(); it != subscribers.end(); it++) {
            if (((*it)->timerId_ >= 0) && ((*it)->keyOption_->GetFinalKey() == keyCode)) {
                ClearTimer(*it);
            }
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

void KeySubscriberHandler::PrintKeyOption(const std::shared_ptr<KeyOption> keyOption)
{
    CHKPV(keyOption);
    MMI_HILOGD("keyOption->finalKey:%{public}d,keyOption->isFinalKeyDown:%{public}s, "
        "keyOption->finalKeyDownDuration:%{public}d",
        keyOption->GetFinalKey(), keyOption->IsFinalKeyDown() ? "true" : "false",
        keyOption->GetFinalKeyDownDuration());
    for (const auto &keyCode : keyOption->GetPreKeys()) {
        MMI_HILOGD("keyOption->prekey:%{public}d", keyCode);
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
    mprintf(fd, "subscribers: count = %zu", subscriberMap_.size());
    for (const auto &item : foregroundPids_) {
        mprintf(fd, "Foreground Pids: %d", item);
    }
    mprintf(fd,
            "enableCombineKey: %s | isForegroundExits: %s"
            "| needSkipPowerKeyUp: %s \t",
            enableCombineKey_ ? "true" : "false", isForegroundExits_ ? "true" : "false",
            needSkipPowerKeyUp_ ? "true" : "false");
    for (auto iter = subscriberMap_.begin(); iter != subscriberMap_.end(); iter++) {
        auto &subscribers = iter->second;
        for (auto item = subscribers.begin(); item != subscribers.end(); item++) {
            std::shared_ptr<Subscriber> subscriber = *item;
            CHKPV(subscriber);
            SessionPtr session = subscriber->sess_;
            CHKPV(session);
            std::shared_ptr<KeyOption> keyOption = subscriber->keyOption_;
            CHKPV(keyOption);
            mprintf(fd,
                    "subscriber id:%d | timer id:%d | Pid:%d | Uid:%d | Fd:%d "
                    "| FinalKey:%d | finalKeyDownDuration:%d | IsFinalKeyDown:%s "
                    "| ProgramName:%s \t",
                    subscriber->id_, subscriber->timerId_, session->GetPid(),
                    session->GetUid(), session->GetFd(), keyOption->GetFinalKey(),
                    keyOption->GetFinalKeyDownDuration(), keyOption->IsFinalKeyDown() ? "true" : "false",
                    session->GetProgramName().c_str());
            std::set<int32_t> preKeys = keyOption->GetPreKeys();
            for (const auto &preKey : preKeys) {
                mprintf(fd, "preKeys:%d\t", preKey);
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS
