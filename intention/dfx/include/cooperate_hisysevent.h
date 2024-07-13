/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COOPERATE_HISYSEVENT_H
#define COOPERATE_HISYSEVENT_H

#include <map>
#include <string>

#include "devicestatus_define.h"
#include "hisysevent.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum CooperateType : int32_t {
    ENABLE_SUCC = 0,
    ENABLE_FAIL = 1,
    DISABLE_SUCC = 2,
    DISABLE_FAIL = 3,
    LOCAL_ACTIVATE_SUCC = 4,
    LOCAL_ACTIVATE_FAIL = 5,
    REMOTE_ACTIVATE_SUCC = 6,
    REMOTE_ACTIVATE_FAIL = 7,
    LOCAL_DEACTIVATE_SUCC = 8,
    LOCAL_DEACTIVATE_FAIL = 9,
    REMOTE_DEACTIVATE_SUCC = 10,
    REMOTE_DEACTIVATE_FAIL = 11,
    OPENSESSION_SUCC = 12,
    OPENSESSION_FAIL = 13,
    UPDATESTATE_SUCC = 14,
    START_SUCC = 15,
    START_FAIL = 16,
    STOP_SUCC = 17,
    STOP_FAIL = 18,
};
enum CooperateState : size_t {
    COOPERATE_STATE_FREE = 0,
    COOPERATE_STATE_OUT,
    COOPERATE_STATE_IN,
    N_COOPERATE_STATES,
};

class CooperateDFX {
public:

    static int32_t WriteEnable(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteDisable(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteLocalStart(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteLocalStop(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteRemoteStart(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteRemoteStop(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteOpenSession(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteStart(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteStop(OHOS::HiviewDFX::HiSysEvent::EventType type);
    static int32_t WriteCooperateState(CooperateState curState);
    template<typename... Types>
    static int32_t WriteInputFunc(const CooperateType &cooperateType,
        OHOS::HiviewDFX::HiSysEvent::EventType eventType, Types... paras);

private:
    static std::map<CooperateState, std::string> CooperateState_;
    static std::map<CooperateType, std::pair<std::string, std::string>> serialStr_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_HISYSEVENT_H
