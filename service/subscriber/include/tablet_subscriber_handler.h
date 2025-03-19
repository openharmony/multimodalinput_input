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

#ifndef TABLET_SUBSCRIBER_HANDLER_H
#define TABLET_SUBSCRIBER_HANDLER_H

#include <algorithm>
#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include "singleton.h"
#include "i_input_event_handler.h"
#include "key_event.h"
#include "switch_event.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class TabletSubscriberHandler final {
    DECLARE_DELAYED_SINGLETON(TabletSubscriberHandler);
public:
    DISALLOW_COPY_AND_MOVE(TabletSubscriberHandler);
    void HandleTabletEvent(const std::shared_ptr<PointerEvent> pointerEvent);
    int32_t SubscribeTabletProximity(SessionPtr sess, int32_t subscribeId);
    int32_t UnsubscribetabletProximity(SessionPtr sess, int32_t subscribeId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
private:
    struct Subscriber {
        Subscriber(int32_t id, SessionPtr sess)
            : id_(id), sess_(sess), timerId_(-1) {}
        int32_t id_ { -1 };
        SessionPtr sess_ { nullptr };
        int32_t timerId_ { -1 };
    };
    void InsertSubScriber(std::shared_ptr<Subscriber> subs);
private:
    bool OnSubscribeTabletProximity(std::shared_ptr<PointerEvent> keyEvent);
    void NotifySubscriber(std::shared_ptr<PointerEvent> keyEvent,
        const std::shared_ptr<Subscriber> &subscriber);
    void OnSessionDelete(SessionPtr sess);
    bool InitSessionDeleteCallback();
private:
    std::list<std::shared_ptr<Subscriber>> subscribers_ {};
    std::atomic_bool callbackInitialized_ { false };
};
#define TABLET_SCRIBER_HANDLER ::OHOS::DelayedSingleton<TabletSubscriberHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TABLET_SUBSCRIBER_HANDLER_H
