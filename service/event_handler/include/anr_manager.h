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
class ANRManager : public DelayedSingleton<ANRManager> {
public:
    ANRManager() = default;
    DISALLOW_COPY_AND_MOVE(ANRManager);
    ~ANRManager() = default;
    void Init(UDSServer& udsServer);
    bool TriggerANR(int64_t time, SessionPtr sess);
    int32_t SetANRNoticedPid(int32_t anrPid);
    void OnSessionLost(SessionPtr session);

private:
    int32_t anrNoticedPid_ { -1 };
    UDSServer *udsServer_ = nullptr;;
};
} // namespace MMI
} // namespace OHOS
#define ANRMgr OHOS::MMI::ANRManager::GetInstance()
#endif // ANR_MANAGER_H