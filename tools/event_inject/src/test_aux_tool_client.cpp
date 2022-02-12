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

#include "test_aux_tool_client.h"
#include "injection_event_dispatch.h"
#include "message_send_recv_stat_mgr.h"
#include "multimodal_input_connect_manager.h"
#include "proto.h"
#include "util.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "TestAuxToolClient"};
}

int32_t TestAuxToolClient::ExecuteAllCommand()
{
    struct timeval time;
    RawInputEvent rawEvent = {};
    for (uint32_t item = 0; item < AI_CODE_MAX; item++) {
        gettimeofday(&time, 0);
        rawEvent.stamp = static_cast<uint32_t>(time.tv_usec);
        rawEvent.ev_type = static_cast<uint32_t>(INPUT_DEVICE_CAP_AI_SENSOR);
        rawEvent.ev_code = GetAiSensorAllowProcCodes(item);
        rawEvent.ev_value = item;
        NetPacket cktAi(MmiMessageId::SENIOR_INPUT_FUNC);
        cktAi << rawEvent;
        SendMsg(cktAi);
    }
    return RET_OK;
}

bool TestAuxToolClient::Start(bool detachMode)
{
    CHKF(cMsgHandler_.Init(), MSG_HANDLER_INIT_FAIL);

    auto callback = std::bind(&TestAuxToolMsgHandler::OnMsgHandler, &cMsgHandler_, std::placeholders::_1,
                              std::placeholders::_2);
    CHKF(StartClient(callback, detachMode), START_CLI_FAIL);

    return true;
}

void TestAuxToolClient::OnDisconnected()
{
    MMI_LOGT("Disconnected from server... fd:%{public}d", GetFd());
}

void OHOS::MMI::TestAuxToolClient::OnThreadLoop()
{
    MMI_LOGT("enter isConnected_:%{public}d", isConnected_);
    if (isConnected_) {
        if (MessageSendRecvStatMgr::GetInstance().IsNoWaitMessage()) {
            MMI_LOGW("IsNoWaitMessage, and set to exit.");
            SetToExit();
        }
    }
}

void TestAuxToolClient::OnConnected()
{
    MMI_LOGD("Connection to server succeeded... fd:%{public}d", GetFd());
}

uint32_t OHOS::MMI::TestAuxToolClient::GetAiSensorAllowProcCodes(uint32_t item) const
{
    static const vector<MmiMessageId> aiSensorAllowProcCodes {
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
    MmiMessageId::ON_TELEPHONE_CONTROL,
    MmiMessageId::ON_TELEPHONE_CONTROL
    };

    return static_cast<uint32_t>(aiSensorAllowProcCodes[item]);
}

int32_t OHOS::MMI::TestAuxToolClient::Socket()
{
    MMI_LOGT("enter");
    const int32_t ret = MultimodalInputConnectManager::GetInstance()->
                        AllocSocketPair(IMultimodalInputConnect::CONNECT_MODULE_TYPE_SIMULATE_INJECT);
    if (ret != RET_OK) {
        MMI_LOGE("UDSSocket::Socket, call MultimodalInputConnectManager::AllocSocketPair return %{public}d", ret);
    }
    fd_ = MultimodalInputConnectManager::GetInstance()->GetClientSocketFdOfAllocedSocketPair();
    if (fd_ == IMultimodalInputConnect::INVALID_SOCKET_FD) {
        MMI_LOGE("UDSSocket::Socket, call MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair"
                 " return invalid fd.");
    } else {
        MMI_LOGD("UDSSocket::Socket, call MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair"
                 " return fd = %{public}d.", fd_);
    }

    return fd_;
}

bool OHOS::MMI::TestAuxToolClient::IsFirstConnectFailExit()
{
    return true;
}
