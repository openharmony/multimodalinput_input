/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SWITCH_EVENT_INPUT_SUBSCRIBE_MANAGER_H
#define SWITCH_EVENT_INPUT_SUBSCRIBE_MANAGER_H

#include <functional>
#include <map>
#include <memory>

#include <singleton.h>

#include "switch_event.h"

namespace OHOS {
namespace MMI {
class SwitchEventInputSubscribeManager final {
    DECLARE_SINGLETON(SwitchEventInputSubscribeManager);

public:
    class SubscribeSwitchEventInfo {
    public:
        SubscribeSwitchEventInfo(int32_t switchType,
            std::function<void(std::shared_ptr<SwitchEvent>)> callback);
        ~SubscribeSwitchEventInfo() = default;

        int32_t GetSwitchType() const
        {
            return switchType_;
        }

        std::function<void(std::shared_ptr<SwitchEvent>)> GetCallback() const
        {
            return callback_;
        }
    private:
        int32_t switchType_ { -1 };
        std::function<void(std::shared_ptr<SwitchEvent>)> callback_ { nullptr };
    };

public:
    DISALLOW_MOVE(SwitchEventInputSubscribeManager);

    int32_t SubscribeSwitchEvent(int32_t switchType, std::function<void(std::shared_ptr<SwitchEvent>)> callback);
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId);

    int32_t OnSubscribeSwitchEventCallback(std::shared_ptr<SwitchEvent> event, int32_t subscribeId);
    void OnConnected();

private:
    std::map<int32_t, SubscribeSwitchEventInfo> subscribeInfos_;
    static int32_t subscribeManagerId_;
    std::mutex mtx_;
};

#define SWITCH_EVENT_INPUT_SUBSCRIBE_MGR ::OHOS::Singleton<SwitchEventInputSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // SWITCH_EVENT_INPUT_SUBSCRIBE_MANAGER_H