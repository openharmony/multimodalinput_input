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
#ifndef KEY_EVENT_SUBSCRIBER_H
#define KEY_EVENT_SUBSCRIBER_H

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include "key_event.h"
#include "key_option.h"
#include "singleton.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class KeyEventSubscriber : public Singleton<KeyEventSubscriber> {
public:
    KeyEventSubscriber() = default;
    ~KeyEventSubscriber() = default;

    int32_t SubscribeKeyEvent(SessionPtr sess, int32_t subscribeId,
            const std::shared_ptr<OHOS::MMI::KeyOption> keyOption);
    int32_t UnSubscribeKeyEvent(SessionPtr sess, int32_t subscribeId);
    bool SubscribeKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);

private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, std::shared_ptr<KeyOption> keyOption)
            : id_(id), sess_(sess), keyOption_(keyOption), timerId_(-1)
        {
        }
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        std::shared_ptr<OHOS::MMI::KeyOption> keyOption_ { nullptr };
        int32_t timerId_ { -1 };
        std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
    };

private:
    bool HandleKeyDown(const std::shared_ptr<KeyEvent>& keyEvent);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent>& keyEvent);
    bool HandleKeyCanel(const std::shared_ptr<KeyEvent>& keyEvent);

    bool IsPreKeysMatch(const std::vector<int32_t>& preKeys, const std::vector<int32_t>& pressedKeys) const;

    void NotifySubscriber(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
            const std::shared_ptr<Subscriber>& subscriber);

    bool AddTimer(const std::shared_ptr<Subscriber>& subscriber, const std::shared_ptr<KeyEvent>& keyEvent);
    void ClearTimer(const std::shared_ptr<Subscriber>& subscriber);
    void OnTimer(const std::shared_ptr<Subscriber> subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();

    bool CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent);

    void RemoveKeyCode(int32_t keyCode, std::vector<int32_t>& keyCodes);

private:
    std::list<std::shared_ptr<Subscriber>> subscribers_ {};
    bool callbackInitialized_ { false };
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#define KeyEventSubscriber_ OHOS::MMI::KeyEventSubscriber::GetInstance()
#endif  // KEY_EVENT_SUBSCRIBER_H
