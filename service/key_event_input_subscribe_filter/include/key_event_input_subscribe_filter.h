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
#ifndef _KEY_EVENT_INPUT_SUBSCRIBE_FILTER_H_
#define _KEY_EVENT_INPUT_SUBSCRIBE_FILTER_H_

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

class KeyEventInputSubscribeFilter : public Singleton<KeyEventInputSubscribeFilter> {

public:
    KeyEventInputSubscribeFilter() = default;
    ~KeyEventInputSubscribeFilter() = default;

    int32_t SubscribeKeyEvent(SessionPtr sess, int32_t subscribeId,
            const std::shared_ptr<OHOS::MMI::KeyOption> keyOption);
    int32_t UnSubscribeKeyEvent(SessionPtr sess, int32_t subscribeId);
    bool FilterSubscribeKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);

private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, std::shared_ptr<KeyOption> keyOption)
            : id_(id), sess_(sess), keyOption_(keyOption), timerId_(-1)
        {
        }
        int32_t id_;
        SessionPtr sess_;
        std::shared_ptr<OHOS::MMI::KeyOption> keyOption_;
        int32_t timerId_;
        std::shared_ptr<KeyEvent> keyEvent_;
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
    void OnSessionLost(SessionPtr sess);
    bool InitSessionDeleteCallback();

    bool CloneKeyEvent(std::shared_ptr<KeyEvent> keyEvent);

    void RemoveKeyCode(std::vector<int32_t>& keyCodes, int32_t keyCode);

private:
    std::list<std::shared_ptr<Subscriber>> subscribers_;
    bool sessionDeletedCallbackInitialized_ {false};
    std::shared_ptr<KeyEvent> keyEvent_;
};
}
}
#define KeyEventInputSubscribeFlt OHOS::MMI::KeyEventInputSubscribeFilter::GetInstance()
#endif  // _KEY_EVENT_INPUT_SUBSCRIBE_FILTER_H_
