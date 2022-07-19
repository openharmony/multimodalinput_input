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

#include "anr_manager.h"
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
    CALL_DEBUG_ENTER;
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
        MMI_HILOGD("Application not responding");
        return;
    }
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("The pointer event does not report normally, application not response");
        return;
    }
    auto pid = udsServer->GetClientPid(fd);
    auto pointerEvent = std::make_shared<PointerEvent>(*point);
    auto pointerIdList = pointerEvent->GetPointersIdList();
    if (pointerIdList.size() > 1) {
        for (const auto& id : pointerIdList) {
            PointerEvent::PointerItem pointeritem;
            if (!pointerEvent->GetPointerItem(id, pointeritem)) {
                MMI_HILOGW("Can't find this poinerItem");
                continue;
            }
            auto itemPid = WinMgr->GetWindowPid(pointeritem.GetTargetWindowId());
            if (itemPid >= 0 && itemPid != pid) {
                pointerEvent->RemovePointerItem(id);
                MMI_HILOGD("pointerIdList size: %{public}zu", pointerEvent->GetPointersIdList().size());
            }
        }
    }
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    session->SaveANREvent(point->GetId(), currentTime);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t EventDispatch::DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    auto fd = WinMgr->UpdateTarget(key);
    if (fd < 0) {
        MMI_HILOGE("Invalid fd, fd: %{public}d", fd);
        DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return RET_ERR;
    }
    DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    MMI_HILOGD("Event dispatcher of server:KeyEvent:KeyCode:%{public}d,Action:%{public}d,EventType:%{public}d,"
        "Fd:%{public}d", key->GetKeyCode(), key->GetAction(), key->GetEventType(), fd);
    auto session = udsServer.GetSession(fd);
    CHKPR(session, RET_ERR);
    if (session->isANRProcess_) {
        MMI_HILOGD("Application not responding");
        return RET_OK;
    }
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(currentTime, session)) {
        session->isANRProcess_ = true;
        MMI_HILOGW("The key event does not report normally, application not response");
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
    session->SaveANREvent(key->GetId(), currentTime);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
