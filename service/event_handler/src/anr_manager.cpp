/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "anr_manager.h"

#include "dfx_hisysevent.h"
#include "i_input_windows_manager.h"
#include "timer_manager.h"
#include "uds_session.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_ANRDETECT
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ANRManager"

namespace OHOS {
namespace MMI {
namespace {
const char* FOUNDATION { "foundation" };
constexpr int32_t MAX_TIMER_COUNT { 50 };
constexpr int32_t TIME_CONVERT_RATIO { 1000 };
} // namespace

ANRManager::ANRManager() {}
ANRManager::~ANRManager() {}

void ANRManager::Init(UDSServer &udsServer)
{
    CALL_DEBUG_ENTER;
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    udsServer_->AddSessionDeletedCallback([this] (SessionPtr session) {
        return this->OnSessionLost(session);
    }
    );
}

int32_t ANRManager::MarkProcessed(int32_t pid, int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("pid:%{public}d, eventType:%{public}d, eventId:%{public}d", pid, eventType, eventId);
    SessionPtr sess = udsServer_->GetSessionByPid(pid);
    if (sess == nullptr) {
        if (pid_ != pid) {
            pid_ = pid;
            MMI_HILOGE("The sess is null, return value is %{public}d", RET_ERR);
        }
        return RET_ERR;
    }
    std::list<int32_t> timerIds = sess->DelEvents(eventType, eventId);
    for (int32_t item : timerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
            anrTimerCount_--;
            MMI_HILOGD("Remove anr timer, anr type:%{public}d, eventId:%{public}d, timer id:%{public}d,"
                "count:%{public}d", eventType, eventId, item, anrTimerCount_);
        }
    }

    int64_t currentTime = GetSysClockTime();
    if (!(ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, sess)) && isTriggerANR_) {
        isTriggerANR_ = false;
        MMI_HILOGI("Exit anr state");
    }
    return RET_OK;
}

void ANRManager::RemoveTimers(SessionPtr sess)
{
    CHKPV(sess);
    std::vector<int32_t> DispatchTimerIds = sess->GetTimerIds(ANR_DISPATCH);
    for (int32_t item : DispatchTimerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
            anrTimerCount_--;
        }
    }
    std::vector<int32_t> MonitorTimerIds = sess->GetTimerIds(ANR_MONITOR);
    for (int32_t item : MonitorTimerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
            anrTimerCount_--;
        }
    }
}

void ANRManager::RemoveTimersByType(SessionPtr sess, int32_t type)
{
    CHKPV(sess);
    if (type != ANR_DISPATCH && type != ANR_MONITOR) {
        MMI_HILOGE("Remove times failed, your input parm is %{public}d, which is not legal", type);
        return;
    }
    std::vector<int32_t> timerIds = sess->GetTimerIds(ANR_MONITOR);
    for (int32_t item : timerIds) {
        if (item != -1) {
            TimerMgr->RemoveTimer(item);
            anrTimerCount_--;
        }
    }
}

void ANRManager::AddTimer(int32_t type, int32_t id, int64_t currentTime, SessionPtr sess)
{
    CHKPV(sess);
    if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION) {
        MMI_HILOGD("Not application event, skip. pid:%{public}d, anr type:%{public}d", sess->GetPid(), type);
        return;
    }
    if (anrTimerCount_ >= MAX_TIMER_COUNT) {
        MMI_HILOGD("Add timer failed, timer count reached the maximum number:%{public}d", MAX_TIMER_COUNT);
        return;
    }
    int32_t timerId = TimerMgr->AddTimer(INPUT_UI_TIMEOUT_TIME / TIME_CONVERT_RATIO, 1, [this, id, type, sess]() {
        CHKPV(sess);
        if (type == ANR_MONITOR || WIN_MGR->IsWindowVisible(sess->GetPid())) {
            sess->SetAnrStatus(type, true);
            isTriggerANR_ = true;
            DfxHisysevent::ApplicationBlockInput(sess);
            MMI_HILOG_FREEZEE("Application not responding. pid:%{public}d, anr type:%{public}d, eventId:%{public}d",
                sess->GetPid(), type, id);
            CHK_INVALID_RV(anrNoticedPid_, "Add anr timer failed, timer count reached the maximum number");
            NetPacket pkt(MmiMessageId::NOTICE_ANR);
            pkt << sess->GetPid();
            pkt << id;
            if (pkt.ChkRWError()) {
                MMI_HILOGE("Packet write failed");
                return;
            }
            auto fd = udsServer_->GetClientFd(anrNoticedPid_);
            if (!udsServer_->SendMsg(fd, pkt)) {
                MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
                return;
            }
        }
    }, "ANRManager");
    CHK_INVALID_RV(timerId, "Add anr timer failed, timer count reached the maximum number");
    anrTimerCount_++;
    MMI_HILOGD("Add anr timer success, anr type:%{public}d, eventId:%{public}d, timer id:%{public}d, count:%{public}d",
        type, id, timerId, anrTimerCount_);
    sess->SaveANREvent(type, id, currentTime, timerId);
}

bool ANRManager::TriggerANR(int32_t type, int64_t time, SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPF(udsServer_);
    CHKPF(sess);
    if (sess->GetTokenType() != TokenType::TOKEN_HAP || sess->GetProgramName() == FOUNDATION) {
        MMI_HILOGD("Not application event, skip. pid:%{public}d, anr type:%{public}d", sess->GetPid(), type);
        return false;
    }
    if (sess->CheckAnrStatus(type)) {
        MMI_HILOGD("Application not responding. pid:%{public}d, anr type:%{public}d", sess->GetPid(), type);
        return true;
    }
    MMI_HILOGD("Event dispatch normal");
    return false;
}

void ANRManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    if (anrNoticedPid_ == session->GetPid()) {
        MMI_HILOGI("The anrNoticedPid_ changes to invalid");
        anrNoticedPid_ = -1;
    }
    MMI_HILOGI("SessionLost remove all Timers");
    RemoveTimers(session);
}

int32_t ANRManager::SetANRNoticedPid(int32_t pid)
{
    CALL_INFO_TRACE;
    anrNoticedPid_ = pid;
    return RET_OK;
}

void ANRManager::HandleAnrState(SessionPtr sess, int32_t type, int64_t currentTime)
{
    CHKPV(sess);
    const auto &events = sess->GetEventsByType(type);
    std::vector<UDSSession::EventTime> timeoutEvents;
    MMI_HILOGD("Event list size. Type:%{public}d, Count:%{public}zu", type, events.size());

    const int64_t timeoutThreshold = INPUT_UI_TIMEOUT_TIME / TIME_CONVERT_RATIO;
    for (const auto &event : events) {
        const int64_t elapsedTime = currentTime - event.eventTime;
        if (elapsedTime > timeoutThreshold) {
            timeoutEvents.push_back(event);
        }
    }

    if (!timeoutEvents.empty()) {
        std::sort(timeoutEvents.begin(), timeoutEvents.end(),
            [](const UDSSession::EventTime &a, const UDSSession::EventTime &b) {
                return a.eventTime < b.eventTime;
            });
        const auto &lastEvent = timeoutEvents.back();
        for (const auto &event : timeoutEvents) {
            if (event.id != lastEvent.id) {
                auto timerIds = sess->DelEvents(type, event.id);
                for (auto timerId : timerIds) {
                    if (timerId != -1) {
                        TimerMgr->RemoveTimer(timerId);
                        anrTimerCount_--;
                    }
                }
            }
        }
        MMI_HILOGD("Keep anr state. Last timeout event. Type:%{public}d, PID:%{public}d",
            type, sess->GetPid());
    }
}
} // namespace MMI
} // namespace OHOS
