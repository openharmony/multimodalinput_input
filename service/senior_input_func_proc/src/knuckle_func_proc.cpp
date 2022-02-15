/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "knuckle_func_proc.h"
#include <set>
#include "proto.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KnuckleFuncProc" };
    }
}
}

using namespace std;
using namespace OHOS::MMI;
int32_t OHOS::MMI::KnuckleFuncProc::DeviceEventDispatchProcess(const RawInputEvent &event)
{
    if (CheckEventCode(event) == RET_ERR) {
        MMI_LOGE("knuckle event.code error. event.code:%{public}d", event.ev_code);
        return RET_ERR;
    }
    if (DeviceEventProcess(event) == RET_ERR) {
        MMI_LOGE("knuckle device event process fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t OHOS::MMI::KnuckleFuncProc::CheckEventCode(const RawInputEvent& event)
{
    static const std::set<MmiMessageId> g_knuckleAllowProcCodes = {
        MmiMessageId::ON_SCREEN_SHOT,
        MmiMessageId::ON_SCREEN_SPLIT,
        MmiMessageId::ON_START_SCREEN_RECORD,
        MmiMessageId::ON_STOP_SCREEN_RECORD,
    };

    auto findNum = static_cast<MmiMessageId>(event.ev_code);
    if (g_knuckleAllowProcCodes.find(findNum) != g_knuckleAllowProcCodes.end()) {
        return RET_OK;
    } else {
        return RET_ERR;
    }
}

int32_t OHOS::MMI::KnuckleFuncProc::GetDevType()
{
    return static_cast<int32_t>(INPUT_DEVICE_CAP_KNUCKLE);
}
