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

#ifndef KEY_SUBSCRIBER_HANDLER_H
#define KEY_SUBSCRIBER_HANDLER_H

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "i_input_event_handler.h"
#include "key_event.h"
#include "key_gesture_manager.h"
#include "key_option.h"
#include "uds_server.h"
#include "nap_process.h"

namespace OHOS {
namespace MMI {
class KeySubscriberHandler final : public IInputEventHandler {
public:
    KeySubscriberHandler() = default;
    DISALLOW_COPY_AND_MOVE(KeySubscriberHandler);
    ~KeySubscriberHandler() = default;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    bool IsKeyEventSubscribed(int32_t keyCode, int32_t trrigerType);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t SubscribeKeyEvent(SessionPtr sess, int32_t subscribeId,
            const std::shared_ptr<KeyOption> keyOption);
    int32_t UnsubscribeKeyEvent(SessionPtr sess, int32_t subscribeId);
    void RemoveSubscriberKeyUpTimer(int32_t keyCode);
    int32_t EnableCombineKey(bool enable);
    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, std::shared_ptr<KeyOption> keyOption)
            : id_(id), sess_(sess), keyOption_(keyOption), timerId_(-1) {}
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        std::shared_ptr<KeyOption> keyOption_ { nullptr };
        int32_t timerId_ { -1 };
        std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
    };
    using SubscriberCollection = std::map<std::shared_ptr<KeyOption>, std::list<std::shared_ptr<Subscriber>>>;

    size_t CountSubscribers() const;
    void DumpSubscribers(int32_t fd, const SubscriberCollection &collection) const;
    void DumpSubscriber(int32_t fd, std::shared_ptr<Subscriber> subscriber) const;
    void InsertSubScriber(std::shared_ptr<Subscriber> subs);
    bool OnSubscribeKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    bool HandleKeyDown(const std::shared_ptr<KeyEvent> &keyEvent);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent);
    bool HandleKeyCancel(const std::shared_ptr<KeyEvent> &keyEvent);
    bool HandleRingMute(std::shared_ptr<KeyEvent> keyEvent);
    bool IsPreKeysMatch(const std::set<int32_t> &preKeys, const std::vector<int32_t> &pressedKeys) const;
    void NotifySubscriber(std::shared_ptr<KeyEvent> keyEvent,
        const std::shared_ptr<Subscriber> &subscriber);
    bool AddTimer(const std::shared_ptr<Subscriber> &subscriber, const std::shared_ptr<KeyEvent> &keyEvent);
    void ClearTimer(const std::shared_ptr<Subscriber> &subscriber);
    void OnTimer(const std::shared_ptr<Subscriber> subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();
    bool CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    void RemoveKeyCode(int32_t keyCode, std::vector<int32_t> &keyCodes);
    bool IsRepeatedKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
    bool IsFunctionKey(const std::shared_ptr<KeyEvent> keyEvent);
    bool IsEnableCombineKey(const std::shared_ptr<KeyEvent> key);
    bool IsEnableCombineKeySwipe(const std::shared_ptr<KeyEvent> key);
    bool IsNotifyPowerKeySubsciber(int32_t keyCode, const std::vector<int32_t> &keyCodes);
    void HandleKeyUpWithDelay(std::shared_ptr<KeyEvent> keyEvent, const std::shared_ptr<Subscriber> &subscriber);
    void PrintKeyUpLog(const std::shared_ptr<Subscriber> &subscriber);
    void SubscriberNotifyNap(const std::shared_ptr<Subscriber> subscriber);
    bool IsEqualKeyOption(std::shared_ptr<KeyOption> newOption, std::shared_ptr<KeyOption> oldOption);
    bool IsEqualPreKeys(const std::set<int32_t> &preKeys, const std::set<int32_t> &pressedKeys);
    void AddKeyGestureSubscriber(std::shared_ptr<Subscriber> subscriber, std::shared_ptr<KeyOption> option);
    int32_t RemoveKeyGestureSubscriber(SessionPtr sess, int32_t subscribeId);
    void AddSubscriber(std::shared_ptr<Subscriber> subscriber, std::shared_ptr<KeyOption> option);
    int32_t RemoveSubscriber(SessionPtr sess, int32_t subscribeId);
    bool IsMatchForegroundPid(std::list<std::shared_ptr<Subscriber>> subs, std::set<int32_t> foregroundPids);
    void NotifyKeyDownSubscriber(const std::shared_ptr<KeyEvent> &keyEvent, std::shared_ptr<KeyOption> keyOption,
        std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled);
    void NotifyKeyDownRightNow(const std::shared_ptr<KeyEvent> &keyEvent,
        std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled);
    void NotifyKeyDownDelay(const std::shared_ptr<KeyEvent> &keyEvent,
        std::list<std::shared_ptr<Subscriber>> &subscribers, bool &handled);
    void NotifyKeyUpSubscriber(const std::shared_ptr<KeyEvent> &keyEvent,
        std::list<std::shared_ptr<Subscriber>> subscribers, bool &handled);
    void PrintKeyOption(const std::shared_ptr<KeyOption> keyOption);
    void ClearSubscriberTimer(std::list<std::shared_ptr<Subscriber>> subscribers);
    void GetForegroundPids(std::set<int32_t> &pidList);

private:
    SubscriberCollection subscriberMap_;
    SubscriberCollection keyGestures_;
    KeyGestureManager keyGestureMgr_;
    bool callbackInitialized_ { false };
    bool hasEventExecuting_ { false };
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
    int32_t subscribePowerKeyId_ { -1 };
    bool subscribePowerKeyState_ { false };
    bool enableCombineKey_ { true };
    std::set<int32_t> foregroundPids_ {};
    bool isForegroundExits_ { false };
    bool needSkipPowerKeyUp_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_SUBSCRIBER_HANDLER_H
