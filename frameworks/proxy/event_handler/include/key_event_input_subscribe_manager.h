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

#ifndef KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H
#define KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H

#include <list>
#include <map>
#include <singleton.h>

#include "key_event.h"
#include "key_option.h"

namespace OHOS {
namespace MMI {
class KeyEventInputSubscribeManager final {
    DECLARE_SINGLETON(KeyEventInputSubscribeManager);

    struct MonitorIdentity {
        int32_t key_ { KeyEvent::KEYCODE_UNKNOWN };
        int32_t action_ { KeyEvent::KEY_ACTION_UNKNOWN };
        bool isRepeat_ { false };

        bool operator<(const MonitorIdentity &other) const;
        std::string Dump() const;
        bool Want(std::shared_ptr<KeyEvent>) const;
    };

    struct Monitor {
        std::function<void(std::shared_ptr<KeyEvent>)> callback_;
    };

public:
    class SubscribeKeyEventInfo {
    public:
        SubscribeKeyEventInfo(std::shared_ptr<KeyOption> keyOption,
            std::function<void(std::shared_ptr<KeyEvent>)> callback);
        ~SubscribeKeyEventInfo() = default;
        DISALLOW_MOVE(SubscribeKeyEventInfo);
        SubscribeKeyEventInfo(const SubscribeKeyEventInfo &other);
        SubscribeKeyEventInfo& operator = (const SubscribeKeyEventInfo &other);

        int32_t GetSubscribeId() const
        {
            return subscribeId_;
        }

        std::shared_ptr<KeyOption> GetKeyOption() const
        {
            return keyOption_;
        }

        std::function<void(std::shared_ptr<KeyEvent>)> GetCallback() const
        {
            return callback_;
        }

        bool operator<(const SubscribeKeyEventInfo &other) const;

    private:
        std::shared_ptr<KeyOption> keyOption_ { nullptr };
        std::function<void(std::shared_ptr<KeyEvent>)> callback_ { nullptr };
        int32_t subscribeId_ { -1 };
    };

public:
    DISALLOW_MOVE(KeyEventInputSubscribeManager);

    int32_t SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);
    int32_t UnsubscribeKeyEvent(int32_t subscribeId);

    int32_t SubscribeHotkey(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);
    int32_t UnsubscribeHotkey(int32_t subscriberId);

    int32_t SubscribeKeyMonitor(const KeyMonitorOption &keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);
    void UnsubscribeKeyMonitor(int32_t subscriberId);

    int32_t OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event, int32_t subscribeId);
    int32_t OnSubscribeKeyMonitor(std::shared_ptr<KeyEvent> event);

    void OnConnected();

private:
    std::shared_ptr<const KeyEventInputSubscribeManager::SubscribeKeyEventInfo> GetSubscribeKeyEvent(int32_t id);
    int32_t GenerateId();
    std::vector<std::function<void(std::shared_ptr<KeyEvent>)>> CheckKeyMonitors(std::shared_ptr<KeyEvent> event);

private:
    std::map<MonitorIdentity, std::map<int32_t, Monitor>> monitors_;
    std::set<SubscribeKeyEventInfo> subscribeInfos_;
    static int32_t subscribeIdManager_;
    std::mutex mtx_;
};

#define KeyEventInputSubscribeMgr ::OHOS::Singleton<KeyEventInputSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H