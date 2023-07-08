/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_dispatch_handler.h"

#include <cinttypes>

#include "dfx_hisysevent.h"
#include "hitrace_meter.h"

#include "anr_manager.h"
#include "bytrace_adapter.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "input-event-codes.h"
#include "mouse_device_state.h"
#include "napi_constants.h"
#include "proto.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) || defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDispatchHandler" };
#endif // OHOS_BUILD_ENABLE_KEYBOARD ||  OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
constexpr int32_t INTERVAL_TIME = 3000; // log time interval is 3 seconds.
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventDispatchHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    DispatchKeyEventPid(*udsServer, keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventDispatchHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    HandlePointerEventInner(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventDispatchHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    HandlePointerEventInner(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void EventDispatchHandler::FilterInvalidPointerItem(const std::shared_ptr<PointerEvent> pointerEvent, int32_t fd)
{
    CHKPV(pointerEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto pointerIdList = pointerEvent->GetPointerIds();
    if (pointerIdList.size() > 1) {
        for (const auto& id : pointerIdList) {
            PointerEvent::PointerItem pointeritem;
            if (!pointerEvent->GetPointerItem(id, pointeritem)) {
                MMI_HILOGW("Can't find this pointerItem");
                continue;
            }
            auto itemPid = WinMgr->GetWindowPid(pointeritem.GetTargetWindowId());
            if ((itemPid >= 0) && (itemPid != udsServer->GetClientPid(fd))) {
                pointerEvent->RemovePointerItem(id);
                MMI_HILOGD("pointerIdList size:%{public}zu", pointerEvent->GetPointerIds().size());
            }
        }
    }
}

void EventDispatchHandler::HandlePointerEventInner(const std::shared_ptr<PointerEvent> point)
{
    CALL_DEBUG_ENTER;
    CHKPV(point);
    if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        MMI_HILOGD("Clear extra data");
        WinMgr->ClearExtraData();
    }
    auto fd = WinMgr->GetClientFd(point);
    currentTime_ = point->GetActionTime();
    if (fd < 0 && currentTime_ - eventTime_ > INTERVAL_TIME) {
        eventTime_ = currentTime_;
        MMI_HILOGE("The fd less than 0, fd:%{public}d", fd);
        DfxHisysevent::OnUpdateTargetPointer(point, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto session = udsServer->GetSession(fd);
    CHKPV(session);
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session)) {
        MMI_HILOGD("The pointer event does not report normally, application not response");
        return;
    }
    auto pointerEvent = std::make_shared<PointerEvent>(*point);
    pointerEvent->SetSensorInputTime(point->GetSensorInputTime());
    FilterInvalidPointerItem(pointerEvent, fd);
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    ANRMgr->AddTimer(ANR_DISPATCH, point->GetId(), currentTime, session);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t EventDispatchHandler::DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    auto fd = WinMgr->UpdateTarget(key);
    currentTime_ = key->GetActionTime();
    if (fd < 0 && currentTime_ - eventTime_ > INTERVAL_TIME) {
        eventTime_ = currentTime_;
        MMI_HILOGE("Invalid fd, fd:%{public}d", fd);
        DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return RET_ERR;
    }
    MMI_HILOGD("Event dispatcher of server:KeyEvent:KeyCode:%{public}d,Action:%{public}d,EventType:%{public}d,"
        "Fd:%{public}d", key->GetKeyCode(), key->GetAction(), key->GetEventType(), fd);
    auto session = udsServer.GetSession(fd);
    CHKPR(session, RET_ERR);
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session)) {
        MMI_HILOGW("The key event does not report normally, application not response");
        return RET_OK;
    }

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
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
    ANRMgr->AddTimer(ANR_DISPATCH, key->GetId(), currentTime, session);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
