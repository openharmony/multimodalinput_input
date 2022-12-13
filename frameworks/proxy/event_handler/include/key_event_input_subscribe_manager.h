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

#ifndef KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H
#define KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H

#include <functional>
#include <memory>
#include <set>

#include <singleton.h>

#include "key_event.h"
#include "key_option.h"

namespace OHOS {
namespace MMI {
class KeyEventInputSubscribeManager final {
    DECLARE_SINGLETON(KeyEventInputSubscribeManager);

public:
    class SubscribeKeyEventInfo {
    public:
        SubscribeKeyEventInfo(std::shared_ptr<KeyOption> keyOption,
            std::function<void(std::shared_ptr<KeyEvent>)> callback);
        ~SubscribeKeyEventInfo() = default;

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

    int32_t OnSubscribeKeyEventCallback(std::shared_ptr<KeyEvent> event, int32_t subscribeId);
    void OnConnected();

private:
    const SubscribeKeyEventInfo* GetSubscribeKeyEvent(int32_t id);

private:
    std::set<SubscribeKeyEventInfo> subscribeInfos_;
    static int32_t subscribeIdManager_;
    std::mutex mtx_;
};

#define KeyEventInputSubscribeMgr ::OHOS::Singleton<KeyEventInputSubscribeManager>::GetInstance()
}  // namespace MMI
}  // namespace OHOS
#endif  // KEY_EVENT_INPUT_SUBSCRIBE_MANAGER_H