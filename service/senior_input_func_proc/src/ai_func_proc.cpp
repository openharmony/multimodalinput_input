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

#include "ai_func_proc.h"
#include <set>
#include "proto.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AIFuncProc" };
    }
}
}

using namespace std;
using namespace OHOS::MMI;
int32_t OHOS::MMI::AIFuncProc::DeviceEventDispatchProcess(const RawInputEvent &event)
{
    if (CheckEventCode(event) == RET_ERR) {
        MMI_LOGE("aisensor event.code error. event.code:%{public}d", event.ev_code);
        return RET_ERR;
    }
    if (DeviceEventProcess(event) == RET_ERR) {
        MMI_LOGE("aisensor device event process fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t OHOS::MMI::AIFuncProc::CheckEventCode(const RawInputEvent& event)
{
    static const std::set<MmiMessageId> g_aiSensorAllowProcCodes = {
        MmiMessageId::ON_SHOW_MENU,
        MmiMessageId::ON_SEND,
        MmiMessageId::ON_COPY,
        MmiMessageId::ON_PASTE,
        MmiMessageId::ON_CUT,
        MmiMessageId::ON_UNDO,
        MmiMessageId::ON_REFRESH,
        MmiMessageId::ON_CANCEL,
        MmiMessageId::ON_ENTER,
        MmiMessageId::ON_PREVIOUS,
        MmiMessageId::ON_NEXT,
        MmiMessageId::ON_BACK,
        MmiMessageId::ON_PRINT,
        MmiMessageId::ON_PLAY,
        MmiMessageId::ON_PAUSE,
        MmiMessageId::ON_SCREEN_SHOT,
        MmiMessageId::ON_SCREEN_SPLIT,
        MmiMessageId::ON_START_SCREEN_RECORD,
        MmiMessageId::ON_STOP_SCREEN_RECORD,
        MmiMessageId::ON_GOTO_DESKTOP,
        MmiMessageId::ON_RECENT,
        MmiMessageId::ON_SHOW_NOTIFICATION,
        MmiMessageId::ON_LOCK_SCREEN,
        MmiMessageId::ON_SEARCH,
        MmiMessageId::ON_CLOSE_PAGE,
        MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT,
        MmiMessageId::ON_MUTE,
        MmiMessageId::ON_ANSWER,
        MmiMessageId::ON_REFUSE,
        MmiMessageId::ON_HANG_UP,
        MmiMessageId::ON_START_DRAG,
        MmiMessageId::ON_MEDIA_CONTROL,
        MmiMessageId::ON_TELEPHONE_CONTROL
    };

    auto findNum = static_cast<MmiMessageId>(event.ev_code);
    if (g_aiSensorAllowProcCodes.find(findNum) == g_aiSensorAllowProcCodes.end()) {
        MMI_LOGE("Failed to find ev_code");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t OHOS::MMI::AIFuncProc::GetDevType()
{
    return static_cast<int32_t>(INPUT_DEVICE_CAP_AISENSOR);
}