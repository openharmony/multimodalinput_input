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
    class SubscribeKeyEventInfo {
    public:
        explicit SubscribeKeyEventInfo(
            int32_t subscribeId, int32_t fd, std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
            : subscribeId_(subscribeId), fd_(fd), keyOption_(keyOption)
        {}
        ~SubscribeKeyEventInfo() = default;

        static KeyEventInputSubscribeFilter::SubscribeKeyEventInfo InValidSubscribeKeyEventInfo()
        {
            return SubscribeKeyEventInfo(-1, -1, nullptr);
        }

        bool IsInValid()
        {
            return subscribeId_ < 0 && fd_ < 0 && !keyOption_;
        }

        int32_t GetSubscribeId() const
        {
            return subscribeId_;
        }

        void SetSubscribeId(int32_t subscribeId)
        {
            subscribeId_ = subscribeId;
        }

        int32_t GetFd() const
        {
            return fd_;
        }

        void SetFd(int32_t fd)
        {
            fd_ = fd;
        }

        std::shared_ptr<OHOS::MMI::KeyOption> GetKeyOption() const
        {
            return keyOption_;
        }

        void SetKeyOption(const std::shared_ptr<OHOS::MMI::KeyOption> keyOption)
        {
            keyOption_ = keyOption;
        }

    private:
        int32_t subscribeId_;
        int32_t fd_;
        std::shared_ptr<OHOS::MMI::KeyOption> keyOption_;
    };

public:
    KeyEventInputSubscribeFilter() = default;
    ~KeyEventInputSubscribeFilter() = default;

    int32_t SubscribeKeyEventForServer(
        SessionPtr sess, int32_t subscribeId, const std::shared_ptr<OHOS::MMI::KeyOption> keyOption);
    int32_t UnSubscribeKeyEventForServer(SessionPtr sess, int32_t subscribeId);
    bool FilterSubscribeKeyEvent(UDSServer& udsServer, std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);

private:
    KeyEventInputSubscribeFilter::SubscribeKeyEventInfo MatchSusbscribeKeyEvent(
        std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent, const std::vector<int32_t>& pressedKeys);
    bool MatchPreKeysIsPressed(
        int32_t keyAction, const std::vector<int32_t>& preKeys, const std::vector<int32_t>& pressedKeys);
    void DispatchKeyEventSubscriber(UDSServer& udsServer, std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent,
        const SubscribeKeyEventInfo& subscribeInfo);
    void DelayDispatchKeyEventSubscriber(uint32_t timeOut, UDSServer& udsServer,
        std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent, const SubscribeKeyEventInfo& subscribeInfo);

private:
    std::mutex mtx_;
    std::map<SessionPtr, std::list<SubscribeKeyEventInfo>> subscribeKeyEventInfoMap_;
    static const uint8_t maxPreKeyCount_;
};
}
}
#define KeyEventInputSubscribeFlt OHOS::MMI::KeyEventInputSubscribeFilter::GetInstance()
#endif  // _KEY_EVENT_INPUT_SUBSCRIBE_FILTER_H_