/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "test_aux_tool_msg_handler.h"
#include "libmmi_util.h"
#include "message_send_recv_stat_mgr.h"
#include "proto.h"
#include "time_cost_chk.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TestAuxToolMsgHandler" };
} // namespace

bool TestAuxToolMsgHandler::Init()
{
    MsgCallback funs[] = {
        {MmiMessageId::SENIOR_INPUT_FUNC, std::bind(&TestAuxToolMsgHandler::OnAiServerReply,
            this, std::placeholders::_1, std::placeholders::_2)},
        {MmiMessageId::HDI_INJECT, std::bind(&TestAuxToolMsgHandler::OnHdiServerReply,
            this, std::placeholders::_1, std::placeholders::_2)},
    };
    for (auto &it : funs) {
        CHKC(RegistrationEvent(it), EVENT_REG_FAIL);
    }
    return true;
}

void TestAuxToolMsgHandler::OnMsgHandler(const UDSClient &client, NetPacket &pkt)
{
    const MmiMessageId id = pkt.GetMsgId();
    OHOS::MMI::TimeCostChk chk("TestAuxToolMsgHandler::OnMsgHandler", "overtime 200(us)", CHECK_TIME, id);
    auto callback = GetMsgCallback(id);
    if (callback == nullptr) {
        MMI_LOGE("TestAuxToolMsgHandler::OnMsgHandler Unknown msg id:%{public}d,errCode:%{public}d",
                 id, UNKNOWN_MSG_ID);
        return;
    }
    auto ret = (*callback)(client, pkt);
    if (ret < 0) {
        MMI_LOGE("TestAuxToolMsgHandler::OnMsgHandler Msg handling failed. id:%{public}d,errCode:%{public}d",
                 id, ret);
    }
}

int32_t TestAuxToolMsgHandler::OnAiServerReply([[maybe_unused]] const UDSClient &client, NetPacket &pkt)
{
    int32_t replyCode = 0;
    pkt >> replyCode;
    MessageSendRecvStatMgr::GetInstance().Decrease();
    if (replyCode == RET_ERR) {
        MMI_LOGE("AIserver manage ai inject faild");
        return RET_ERR;
    }
    MMI_LOGI("AIserver manage ai inject successed");
    return RET_OK;
}

int32_t OHOS::MMI::TestAuxToolMsgHandler::OnHdiServerReply([[maybe_unused]] const UDSClient& client, NetPacket& pkt)
{
    int32_t replyCode = 0;
    pkt >> replyCode;
    MessageSendRecvStatMgr::GetInstance().Decrease();
    if (replyCode == RET_ERR) {
        MMI_LOGE("hdi inject faild");
        return RET_ERR;
    }
    MMI_LOGI("hdi inject successed");
    return RET_OK;
}