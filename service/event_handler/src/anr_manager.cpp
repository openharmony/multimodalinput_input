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

#include "anr_manager.h"

#include "ability_manager_client.h"
#include "dfx_hisysevent.h"

#include "input_event_handler.h"
#include "mmi_log.h"
#include "proto.h"
#include "timer_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ANRManager" };
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
const std::string FOUNDATION = "foundation";
constexpr int32_t ANR_DISPATCH = 0;
constexpr int32_t ANR_MONITOR = 1;
} // namespace

void ANRManager::Init(UDSServer &udsServer)
{
    CALL_DEBUG_ENTER;
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    udsServer_->AddSessionDeletedCallback(std::bind(&ANRManager::OnSessionLost, this, std::placeholders::_1));
}

void ANRManager::MarkProcessed(int32_t eventType, int32_t eventId, SessionPtr sess)
{
    CHKPV(sess);
    std::list<int32_t> timerIds = sess->DelEvents(eventType, eventId);
    for (int32_t item : timerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
        }
    }
}

void ANRManager::RemoveTimers(SessionPtr sess)
{
    CHKPV(sess);
    std::vector<int32_t> DispatchTimerIds = sess->GetTimerIds(ANR_DISPATCH);
    for (int32_t item : DispatchTimerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
        }
    }
    std::vector<int32_t> MonitorTimerIds = sess->GetTimerIds(ANR_MONITOR);
    for (int32_t item : MonitorTimerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
        }
    }
}

void ANRManager::AddTimer(int32_t type, int32_t id, int64_t currentTime, SessionPtr sess)
{
    CHKPV(sess);
    if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION) {
        MMI_HILOGD("Ignore native event");
        return;
    }
    int32_t timerId = TimerMgr->AddTimer(INPUT_UI_TIMEOUT_TIME, 1, [this, type, sess]() {
        CHKPV(sess);
        sess->SetAnrStatus(type, true);
        DfxHisysevent::ApplicationBlockInput(sess);
        if (anrNoticedPid_ < 0) {
            MMI_HILOGE("The anrNoticedPid_ is invalid");
            return;
        }
        NetPacket pkt(MmiMessageId::NOTICE_ANR);
        pkt << sess->GetPid();
        if (pkt.ChkRWError()) {
            MMI_HILOGE("Packet write failed");
            return;
        }
        auto fd = udsServer_->GetClientFd(anrNoticedPid_);
        if (!udsServer_->SendMsg(fd, pkt)) {
            MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
            return;
        }
        MMI_HILOGI("ANR remove all timers");
        std::vector<int32_t> timerIds = sess->GetTimerIds(type);
        for (int32_t item : timerIds) {
            if (item != -1) {
                TimerMgr->RemoveTimer(item);
            }
        }
    });
    sess->SaveANREvent(type, id, currentTime, timerId);
}

bool ANRManager::TriggerANR(int32_t type, int64_t time, SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPF(udsServer_);
    CHKPF(sess);
    MMI_HILOGD("Current time:%{public}" PRId64 "", time);
    if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION) {
        MMI_HILOGD("Native event");
        return false;
    }
    if (sess->CheckAnrStatus(type)) {
        MMI_HILOGW("Application not responding");
        return true;
    }
    MMI_HILOGI("AAFwk send ANR process id succeeded");
    return false;
}

void ANRManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    if (anrNoticedPid_ == session->GetPid()) {
        MMI_HILOGD("The anrNoticedPid_ is invalid");
        anrNoticedPid_ = -1;
    }
    MMI_HILOGI("SessionLost remove all Timers");
    RemoveTimers(session);
}

int32_t ANRManager::SetANRNoticedPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    anrNoticedPid_ = pid;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS