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

#include "ability_manager_client.h"
#include "anr_manager.h"
#include "dfx_hisysevent.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ANRManager" };
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
const std::string FOUNDATION = "foundation";
} // namespace

void ANRManager::Init(UDSServer& udsServer)
{
    CALL_DEBUG_ENTER;
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    udsServer_->AddSessionDeletedCallback(std::bind(&ANRManager::OnSessionLost, this, std::placeholders::_1));
}

bool ANRManager::TriggerANR(int32_t type, int64_t time, SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPF(udsServer_);
    CHKPF(sess);
    MMI_HILOGD("Current time: %{public}" PRId64 "", time);
    if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION) {
        MMI_HILOGD("Native event");
        return false;
    }

    if (sess->CheckAnrStatus(type)) {
        MMI_HILOGW("application not responding");
        return true;
    }
    int64_t earliest;
    if (sess->IsEventQueueEmpty(type)) {
        earliest = time;
    } else {
        earliest = sess->GetEarliestEventTime(type);
    }
    if (time < (earliest + INPUT_UI_TIMEOUT_TIME)) {
        sess->SetAnrStatus(type, false);
        MMI_HILOGD("the event reports normally");
        return false;
    }
    sess->SetAnrStatus(type, true);
    DfxHisysevent::ApplicationBlockInput(sess);
    if (anrNoticedPid_ < 0) {
        MMI_HILOGE("NoticedPid_ is invalid");
        return true;
    }
    NetPacket pkt(MmiMessageId::NOTICE_ANR);
    pkt << sess->GetPid();
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return true;
    }
    auto fd = udsServer_->GetClientFd(anrNoticedPid_);
    if (!udsServer_->SendMsg(fd, pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return true;
    }
    MMI_HILOGI("AAFwk send ANR process id succeeded");
    return true;
}

void ANRManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    if (anrNoticedPid_ == session->GetPid()) {
        MMI_HILOGD("NoticedPid_ is invalid");
        anrNoticedPid_ = -1;
    }
}

int32_t ANRManager::SetANRNoticedPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    anrNoticedPid_ = pid;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS