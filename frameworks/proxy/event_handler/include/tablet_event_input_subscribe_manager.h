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

#ifndef TABLET_EVENT_INPUT_SUBSCRIBE_MANAGER_H
#define TABLET_EVENT_INPUT_SUBSCRIBE_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include "pointer_event.h"
#include <singleton.h>

namespace OHOS {
namespace MMI {
class TabletEventInputSubscribeManager final {
    DECLARE_SINGLETON(TabletEventInputSubscribeManager);
public:
    class SubscribeTabletEventInfo {
    public:
        SubscribeTabletEventInfo(std::function<void(std::shared_ptr<PointerEvent>)> callback)
            : callback_(callback)
        {
        }
        ~SubscribeTabletEventInfo() = default;
        std::function<void(std::shared_ptr<PointerEvent>)> GetCallback() const
        {
            return callback_;
        }
    private:
        std::function<void(std::shared_ptr<PointerEvent>)> callback_ { nullptr };
    };
public:
    DISALLOW_MOVE(TabletEventInputSubscribeManager);
    int32_t SubscribeTabletProximity(std::function<void(std::shared_ptr<PointerEvent>)> callback);
    int32_t UnsubscribetabletProximity(int32_t subscribeId);
    int32_t OnSubscribeTabletProximityCallback(std::shared_ptr<PointerEvent> event, int32_t subscribeId);
    void OnConnected();

private:
    std::map<int32_t, SubscribeTabletEventInfo> subscribeInfos_;
    static int32_t subscribeManagerId_;
    std::mutex mtx_;
};

#define TABLET_EVENT_INPUT_SUBSCRIBE_MGR ::OHOS::Singleton<TabletEventInputSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TABLET_EVENT_INPUT_SUBSCRIBE_MANAGER_H