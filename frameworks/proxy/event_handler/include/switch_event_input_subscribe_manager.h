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
    DISALLOW_MOVE(SwitchEventInputSubscribeManager);

    int32_t SubscribeSwitchEvent(std::function<void(std::shared_ptr<SwitchEvent>)> callback);
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId);

    int32_t OnSubscribeSwitchEventCallback(std::shared_ptr<SwitchEvent> event, int32_t subscribeId);
    void OnConnected();

private:
    std::map<int32_t, std::function<void(std::shared_ptr<SwitchEvent>)>> subscribeInfos_;
    static int32_t subscribeManagerId_;
    std::mutex mtx_;
};

#define SWITCH_EVENT_INPUT_SUBSCRIBE_MGR ::OHOS::Singleton<SwitchEventInputSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // SWITCH_EVENT_INPUT_SUBSCRIBE_MANAGER_H