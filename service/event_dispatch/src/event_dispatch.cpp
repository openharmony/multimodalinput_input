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

#include "event_dispatch.h"
#include <cinttypes>

#include "ability_manager_client.h"
#include "bytrace_adapter.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "hitrace_meter.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input-event-codes.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatch" };
constexpr int64_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
} // namespace

EventDispatch::EventDispatch() {}

EventDispatch::~EventDispatch() {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventDispatch::HandleKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    DispatchKeyEventPid(*udsServer, keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventDispatch::HandleTouchEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void EventDispatch::HandlePointerEvent(std::shared_ptr<PointerEvent> point)
{
    CALL_LOG_ENTER;
    CHKPV(point);
    auto fd = WinMgr->UpdateTargetPointer(point);
    if (fd < 0) {
        MMI_HILOGE("The fd less than 0, fd: %{public}d", fd);
        DfxHisysevent::OnUpdateTargetPointer(point, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return;
    }
    DfxHisysevent::OnUpdateTargetPointer(point, fd, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto session = udsServer->GetSession(fd);
    CHKPV(session);
    if (session->isANRProcess_) {
        MMI_HILOGD("application not responding");
        return;
    }
    auto currentTime = GetSysClockTime();
    if (TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("the pointer event does not report normally, application not response");
        return;
    }

    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(point, pkt);
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    session->AddEvent(point->GetId(), currentTime);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t EventDispatch::DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_LOG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    auto fd = WinMgr->UpdateTarget(key);
    if (fd < 0) {
        MMI_HILOGE("Invalid fd, fd: %{public}d", fd);
        DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return RET_ERR;
    }
    DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    MMI_HILOGD("event dispatcher of server:KeyEvent:KeyCode:%{public}d,Action:%{public}d,EventType:%{public}d,"
        "Fd:%{public}d", key->GetKeyCode(), key->GetAction(), key->GetEventType(), fd);
    auto session = udsServer.GetSession(fd);
    CHKPR(session, RET_ERR);
    if (session->isANRProcess_) {
        MMI_HILOGD("application not responding");
        return RET_OK;
    }
    auto currentTime = GetSysClockTime();
    if (TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("the key event does not report normally, application not response");
        return RET_OK;
    }

    NetPacket pkt(MmiMessageId::ON_KEYEVENT);
    InputEventDataTransformation::KeyEventToNetPacket(key, pkt);
    BytraceAdapter::StartBytrace(key, BytraceAdapter::KEY_DISPATCH_EVENT);
    pkt << fd;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write structure of EventKeyboard failed");
        return RET_ERR;
    }
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    session->AddEvent(key->GetId(), currentTime);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

bool EventDispatch::TriggerANR(int64_t time, SessionPtr sess)
{
    CALL_LOG_ENTER;
    int64_t earliest;
    if (sess->IsEventQueueEmpty()) {
        earliest = time;
    } else {
        earliest = sess->GetEarliestEventTime();
    }
    MMI_HILOGD("Current time: %{public}" PRId64 "", time);
    if (time < (earliest + INPUT_UI_TIMEOUT_TIME)) {
        sess->isANRProcess_ = false;
        MMI_HILOGD("the event reports normally");
        return false;
    }
    DfxHisysevent::ApplicationBlockInput(sess);
    int32_t ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->SendANRProcessID(sess->GetPid());
    if (ret != 0) {
        MMI_HILOGE("AAFwk SendANRProcessID failed, AAFwk errCode: %{public}d", ret);
    }
    MMI_HILOGI("AAFwk send ANR process id succeeded");
    return true;
}
} // namespace MMI
} // namespace OHOS
