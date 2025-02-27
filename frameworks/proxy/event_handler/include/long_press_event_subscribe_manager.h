/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LONG_PRESS_EVENT_SUBSCRIBE_MANAGER_H
#define LONG_PRESS_EVENT_SUBSCRIBE_MANAGER_H

#include <map>

#include <singleton.h>

#include "long_press_event.h"

namespace OHOS {
namespace MMI {
class LongPressEventSubscribeManager final {
    DECLARE_SINGLETON(LongPressEventSubscribeManager);

public:
    class SubscribeLongPressEventInfo {
    public:
        SubscribeLongPressEventInfo(const LongPressRequest &longPressRequest,
            std::function<void(LongPressEvent)> callback);
        ~SubscribeLongPressEventInfo() = default;

        LongPressRequest GetLongPressRequest() const
        {
            return longPressRequest_;
        }

        std::function<void(LongPressEvent)> GetCallback() const
        {
            return callback_;
        }
    private:
        LongPressRequest longPressRequest_;
        std::function<void(LongPressEvent)> callback_ { nullptr };
    };

public:
    DISALLOW_MOVE(LongPressEventSubscribeManager);

    int32_t SubscribeLongPressEvent(const LongPressRequest &longPressRequest,
        std::function<void(LongPressEvent)> callback);
    int32_t UnsubscribeLongPressEvent(int32_t subscribeId);

    int32_t OnSubscribeLongPressEventCallback(const LongPressEvent &longPressEvent, int32_t subscribeId);
    void OnConnected();

private:
    std::map<int32_t, SubscribeLongPressEventInfo> subscribeInfos_;
    static int32_t subscribeManagerId_;
    std::mutex mtx_;
};

#define LONG_PRESS_EVENT_SUBSCRIBE_MGR ::OHOS::Singleton<LongPressEventSubscribeManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // LONG_PRESS_EVENT_SUBSCRIBE_MANAGER_H