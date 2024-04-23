/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "app_debug_listener.h"
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
#include <transaction/rs_interfaces.h>

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

void EventDispatchHandler::HandleMultiWindowPointerEvent(std::shared_ptr<PointerEvent> point,
    PointerEvent::PointerItem pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(point);
    std::vector<int32_t> windowIds;
    WinMgr->GetTargetWindowIds(pointerItem.GetPointerId(), windowIds);
    int32_t count = 0;
    for (auto windowId : windowIds) {
        int32_t pointerId = point->GetPointerId();
        auto windowInfo = WinMgr->GetWindowAndDisplayInfo(windowId, point->GetTargetDisplayId());
        if (windowInfo == std::nullopt) {
            MMI_HILOGE("WindowInfo id nullptr");
        }
        auto fd = WinMgr->GetClientFd(point, windowInfo->id);
        auto pointerEvent = std::make_shared<PointerEvent>(*point);
        pointerEvent->SetTargetWindowId(windowId);
        pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
        int32_t windowX = pointerItem.GetDisplayX() - windowInfo->area.x;
        int32_t windowY = pointerItem.GetDisplayY() - windowInfo->area.y;
        if (!windowInfo->transform.empty()) {
            auto windowXY = WinMgr->TransformWindowXY(*windowInfo, pointerItem.GetDisplayX(),
                pointerItem.GetDisplayY());
            windowX = windowXY.first;
            windowY = windowXY.second;
        }
        pointerItem.SetDisplayX(windowX);
        pointerItem.SetDisplayY(windowY);
        pointerItem.SetTargetWindowId(windowId);
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
        pointerEvent->SetDispatchTimes(count++);
        DispatchPointerEventInner(pointerEvent, fd);
    }
}

void EventDispatchHandler::NotifyPointerEventToRS(int32_t pointAction, const std::string& programName, uint32_t pid)
{
    if (isTouchEnable_) {
        MMI_HILOGD("touch interface to RS Enable");
        OHOS::Rosen::RSInterfaces::GetInstance().NotifyTouchEvent(pointAction);
    } else {
        MMI_HILOGD("touch interface to RS NOT Enable");
    }
}

bool EventDispatchHandler::AcquireEnableMark(std::shared_ptr<PointerEvent> event)
{
    if (event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        enableMark_ = !enableMark_;
        MMI_HILOGD("Id:%{public}d, markEnabled:%{public}d", event->GetId(), enableMark_);
        return enableMark_;
    }
    return true;
}

void EventDispatchHandler::HandlePointerEventInner(const std::shared_ptr<PointerEvent> point)
{
    CALL_DEBUG_ENTER;
    CHKPV(point);
    int32_t pointerId = point->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!point->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    pointerItem.SetOriginPointerId(pointerItem.GetPointerId());
    point->UpdatePointerItem(pointerId, pointerItem);
    std::vector<int32_t> windowIds;
    WinMgr->GetTargetWindowIds(pointerItem.GetPointerId(), windowIds);
    if (!windowIds.empty()) {
        HandleMultiWindowPointerEvent(point, pointerItem);
        return;
    }
    auto fd = WinMgr->GetClientFd(point);
    DispatchPointerEventInner(point, fd);
}

void EventDispatchHandler::DispatchPointerEventInner(std::shared_ptr<PointerEvent> point, int32_t fd)
{
    CALL_DEBUG_ENTER;
    currentTime_ = point->GetActionTime();
    if (fd < 0 && currentTime_ - eventTime_ > INTERVAL_TIME) {
        eventTime_ = currentTime_;
        MMI_HILOGE("InputTracking id:%{public}d The fd less than 0, fd:%{public}d", point->GetId(), fd);
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto session = udsServer->GetSession(fd);
    CHKPV(session);
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session)) {
        MMI_HILOGW("InputTracking id:%{public}d, The pointer event does not report normally,"
            "application not response", point->GetId());
        return;
    }
    auto pointerEvent = std::make_shared<PointerEvent>(*point);
    pointerEvent->SetMarkEnabled(AcquireEnableMark(pointerEvent));
    pointerEvent->SetSensorInputTime(point->GetSensorInputTime());
    FilterInvalidPointerItem(pointerEvent, fd);
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(pointerEvent, pkt);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN
        || pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP
        || pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_DOWN
        || pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        NotifyPointerEventToRS(pointerEvent->GetPointerAction(), session->GetProgramName(),
            static_cast<uint32_t>(session->GetPid()));
    }
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
        MMI_HILOGI("InputTracking id:%{public}d, SendMsg to %{public}s:pid:%{public}d",
            pointerEvent->GetId(), session->GetProgramName().c_str(), session->GetPid());
    }
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    if (session->GetPid() != AppDebugListener::GetInstance()->GetAppDebugPid() && pointerEvent->IsMarkEnabled()) {
        MMI_HILOGD("session pid : %{public}d", session->GetPid());
        ANRMgr->AddTimer(ANR_DISPATCH, point->GetId(), currentTime, session);
    }
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

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(key, pkt);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write structure of EventKeyboard failed");
        return RET_ERR;
    }
    MMI_HILOGI("InputTracking id:%{public}d, SendMsg to %{public}s:pid:%{public}d",
        key->GetId(), session->GetProgramName().c_str(), session->GetPid());
    if (!udsServer.SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventKeyboard failed! errCode:%{public}d", MSG_SEND_FAIL);
        return MSG_SEND_FAIL;
    }
    if (session->GetPid() != AppDebugListener::GetInstance()->GetAppDebugPid()) {
        MMI_HILOGD("session pid : %{public}d", session->GetPid());
        ANRMgr->AddTimer(ANR_DISPATCH, key->GetId(), currentTime, session);
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
