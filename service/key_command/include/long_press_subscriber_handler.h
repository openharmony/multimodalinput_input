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

#ifndef LONG_PRESS_SUBSCRIBER_HANDLER_H
#define LONG_PRESS_SUBSCRIBER_HANDLER_H

#include <algorithm>
#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "singleton.h"

#include "long_press_event.h"
#include "pointer_event.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class LongPressSubscriberHandler final {
    DECLARE_DELAYED_SINGLETON(LongPressSubscriberHandler);
public:
    DISALLOW_COPY_AND_MOVE(LongPressSubscriberHandler);
    
    int32_t SubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId, const LongPressRequest &longPressRequest);
    int32_t UnsubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId);
    
private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess, int32_t fingerCount, int32_t duration)
            : id_(id), sess_(sess), fingerCount_(fingerCount), duration_(duration), timerId_(-1) {}
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        int32_t fingerCount_ { -1 };
        int32_t duration_ {-1};
        int32_t timerId_ { -1 };
    };
    void InsertSubScriber(std::shared_ptr<Subscriber> subs);

private:
    void OnSubscribeLongPressEvent(int32_t duration);
    void NotifySubscriber(const std::shared_ptr<Subscriber> &subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();

private:
    std::atomic_bool callbackInitialized_ { false };
};
#define LONG_PRESS_EVENT_HANDLER ::OHOS::DelayedSingleton<LongPressSubscriberHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // LONG_PRESS_SUBSCRIBER_HANDLER_H
