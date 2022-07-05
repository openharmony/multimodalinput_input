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
#include "dfx_hisysevent.h"
#include "input_event_handler.h"
#include "mmi_log.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AnrManager" };
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
} // namespace

void AnrManager::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    udsServer_->AddSessionDeletedCallback(std::bind(
        &AnrManager::OnSessionLost, this, std::placeholders::_1));
    MMI_HILOGD("The callback on session deleted is registered successfully");
}

bool AnrManager::TriggerAnr(int64_t time, SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPF(udsServer_);
    int64_t earliest;
    if (sess->IsEventQueueEmpty()) {
        earliest = time;
    } else {
        earliest = sess->GetEarliestEventTime();
    }
    MMI_HILOGD("Current time: %{public}" PRId64 "", time);
    if (time > (earliest + INPUT_UI_TIMEOUT_TIME)) {
        sess->isANRProcess_ = false;
        MMI_HILOGD("the event reports normally");
        return false;
    }
    DfxHisysevent::ApplicationBlockInput(sess);

    MMI_HILOGD("anrpid:%{public}d", anrNoticedPid_);
    if (anrNoticedPid_ < 0) {
        MMI_HILOGE("anrNoticedPid_ is invalid");
        return false;
    }
    auto anrNoticedFd = udsServer_->GetClientFd(anrNoticedPid_);
    NetPacket pkt(MmiMessageId::NOTICE_ANR);
    pkt << sess->GetPid();
    udsServer_->SendMsg(anrNoticedFd, pkt);
    MMI_HILOGI("AAFwk send ANR process id succeeded");
    return false;
}

void AnrManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    if (anrNoticedPid_ == session->GetPid()) {
        MMI_HILOGD("NoticedPid_ set invalid");
        anrNoticedPid_ = -1;
    }
}

int32_t AnrManager::SetAnrNoticedPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    anrNoticedPid_ = pid;
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
