/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ANR_MANAGER_H
#define ANR_MANAGER_H

#include "nocopyable.h"
#include "singleton.h"

#include "uds_server.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class ANRManager final {
    DECLARE_DELAYED_SINGLETON(ANRManager);
public:
    DISALLOW_COPY_AND_MOVE(ANRManager);
    void Init(UDSServer& udsServer);
    bool TriggerANR(int32_t type, int64_t time, SessionPtr sess);
    int32_t SetANRNoticedPid(int32_t anrPid);
    void OnSessionLost(SessionPtr session);
    void AddTimer(int32_t type, int32_t id, int64_t currentTime, SessionPtr sess);
    void MarkProcessed(int32_t eventType, int32_t eventId, SessionPtr sess);
    void RemoveTimers(SessionPtr sess);
private:
    int32_t anrNoticedPid_ { -1 };
    UDSServer *udsServer_ { nullptr };
    int32_t anrTimerCount_ { 0 };
};

#define ANRMgr ::OHOS::DelayedSingleton<ANRManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // ANR_MANAGER_H