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

#include <linux/input-event-codes.h>

#include "hitrace_meter.h"
#include "transaction/rs_interfaces.h"

#include "anr_manager.h"
#include "app_debug_listener.h"
#include "bytrace_adapter.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "event_log_helper.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "i_input_windows_manager.h"
#include "mouse_device_state.h"
#include "napi_constants.h"
#include "proto.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDispatchHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INTERVAL_TIME { 3000 }; // log time interval is 3 seconds.
constexpr int32_t INTERVAL_DURATION { 10 };
constexpr int32_t THREE_FINGERS { 3 };
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
            auto itemPid = WIN_MGR->GetWindowPid(pointeritem.GetTargetWindowId());
            if ((itemPid >= 0) && (itemPid != udsServer->GetClientPid(fd))) {
                pointerEvent->RemovePointerItem(id);
                MMI_HILOGD("pointerIdList size:%{public}zu", pointerEvent->GetPointerIds().size());
            }
        }
    }
}

std::shared_ptr<WindowInfo> EventDispatchHandler::SearchCancelList (int32_t pointerId, int32_t windowId)
{
    if (cancelEventList_.find(pointerId) == cancelEventList_.end()) {
        return nullptr;
    }
    auto windowList = cancelEventList_[pointerId];
    for (auto &info : windowList) {
        if (info->id == windowId) {
            return info;
        }
    }
    return nullptr;
}

bool EventDispatchHandler::ReissueEvent(std::shared_ptr<PointerEvent> &point, int32_t windowId,
    std::optional<WindowInfo> &windowInfo)
{
    int32_t pointerId = point->GetPointerId();
    if (windowInfo == std::nullopt) {
        std::shared_ptr<WindowInfo> curInfo = SearchCancelList(pointerId, windowId);
        if (curInfo != nullptr && point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
            point->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            windowInfo = std::make_optional(*curInfo);
            MMI_HILOG_DISPATCHI("Touch event send cancel to window:%{public}d", windowId);
        } else {
            if (point->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
                MMI_HILOGE("Window:%{public}d is nullptr", windowId);
            }
            return false;
        }
    }
    std::shared_ptr<WindowInfo> curWindowInfo = std::make_shared<WindowInfo>(*windowInfo);
    if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        if (cancelEventList_.find(pointerId) == cancelEventList_.end()) {
            cancelEventList_[pointerId] = std::set<std::shared_ptr<WindowInfo>, EventDispatchHandler::CancelCmp>();
        }
        cancelEventList_[pointerId].insert(curWindowInfo);
    } else if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
        if (cancelEventList_.find(pointerId) != cancelEventList_.end() &&
            cancelEventList_[pointerId].find(curWindowInfo) != cancelEventList_[pointerId].end()) {
            cancelEventList_[pointerId].erase(curWindowInfo);
        } else {
            return false;
        }
    }
    return true;
}

void EventDispatchHandler::HandleMultiWindowPointerEvent(std::shared_ptr<PointerEvent> point,
    PointerEvent::PointerItem pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(point);
    std::vector<int32_t> windowIds;
    WIN_MGR->GetTargetWindowIds(pointerItem.GetPointerId(), point->GetSourceType(), windowIds);
    int32_t count = 0;
    int32_t pointerId = point->GetPointerId();
    if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        if (cancelEventList_.find(pointerId) != cancelEventList_.end()) {
            cancelEventList_.erase(pointerId);
        }
    }
    for (auto windowId : windowIds) {
        auto pointerEvent = std::make_shared<PointerEvent>(*point);
        auto windowInfo = WIN_MGR->GetWindowAndDisplayInfo(windowId, point->GetTargetDisplayId());
        if (!ReissueEvent(pointerEvent, windowId, windowInfo)) {
            continue;
        }
        if (!windowInfo) {
            continue;
        }
        auto fd = WIN_MGR->GetClientFd(pointerEvent, windowInfo->id);
        if (fd < 0) {
            auto udsServer = InputHandler->GetUDSServer();
            CHKPV(udsServer);
            udsServer->GetClientFd(windowInfo->pid);
        }
        pointerEvent->SetTargetWindowId(windowId);
        pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
        int32_t windowX = pointerItem.GetDisplayX() - windowInfo->area.x;
        int32_t windowY = pointerItem.GetDisplayY() - windowInfo->area.y;
        if (!windowInfo->transform.empty()) {
            auto windowXY = WIN_MGR->TransformWindowXY(*windowInfo, pointerItem.GetDisplayX(),
                pointerItem.GetDisplayY());
            windowX = windowXY.first;
            windowY = windowXY.second;
        }
        pointerItem.SetWindowX(windowX);
        pointerItem.SetWindowY(windowY);
        pointerItem.SetTargetWindowId(windowId);
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
        pointerEvent->SetDispatchTimes(count++);
        DispatchPointerEventInner(pointerEvent, fd);
    }
    if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
        WIN_MGR->ClearTargetWindowId(pointerId);
    }
}

void EventDispatchHandler::NotifyPointerEventToRS(int32_t pointAction, const std::string& programName,
    uint32_t pid, int32_t pointCnt)
{
    OHOS::Rosen::RSInterfaces::GetInstance().NotifyTouchEvent(pointAction, pointCnt);
}

bool EventDispatchHandler::AcquireEnableMark(std::shared_ptr<PointerEvent> event)
{
    auto currentEventTime = std::chrono::high_resolution_clock::now();
    int64_t tm64Cost = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - LasteventBeginTime_).count();

    if (event->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_MOVE
        || event->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
        enableMark_ = (tm64Cost > INTERVAL_DURATION) ? true : false;
        if (enableMark_) {
            LasteventBeginTime_ = currentEventTime;
        }
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

    std::vector<int32_t> windowIds;
    WIN_MGR->GetTargetWindowIds(pointerItem.GetPointerId(), point->GetSourceType(), windowIds);
    if (!windowIds.empty()) {
        HandleMultiWindowPointerEvent(point, pointerItem);
        return;
    }
    auto fd = WIN_MGR->GetClientFd(point);
    DispatchPointerEventInner(point, fd);
}

void EventDispatchHandler::DispatchPointerEventInner(std::shared_ptr<PointerEvent> point, int32_t fd)
{
    currentTime_ = point->GetActionTime();
    if (fd < 0 && currentTime_ - eventTime_ > INTERVAL_TIME) {
        eventTime_ = currentTime_;
        if (point->GetPointerCount() < THREE_FINGERS &&
            point->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
            point->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
            point->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE) {
            MMI_HILOGE("InputTracking id:%{public}d The fd less than 0, fd:%{public}d", point->GetId(), fd);
        }
        return;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto sess = udsServer->GetSession(fd);
    if (sess == nullptr) {
        return;
    }
    auto currentTime = GetSysClockTime();
    BytraceAdapter::StartBytrace(point, BytraceAdapter::TRACE_STOP);
    if (ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, sess)) {
        MMI_HILOGD("The pointer event does not report normally,app not respon. PointerEvent(deviceid:%{public}d,"
            "action:%{public}s)", point->GetDeviceId(), point->DumpPointerAction());
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
    int32_t pointerAc = pointerEvent->GetPointerAction();
    if (pointerAc == PointerEvent::POINTER_ACTION_PULL_DOWN || pointerAc == PointerEvent::POINTER_ACTION_UP ||
        pointerAc == PointerEvent::POINTER_ACTION_DOWN || pointerAc == PointerEvent::POINTER_ACTION_PULL_UP) {
        NotifyPointerEventToRS(pointerAc, sess->GetProgramName(),
            static_cast<uint32_t>(sess->GetPid()), pointerEvent->GetPointerCount());
    }
    if (pointerAc != PointerEvent::POINTER_ACTION_MOVE && pointerAc != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerAc != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerAc != PointerEvent::POINTER_ACTION_PULL_MOVE) {
        MMI_HILOG_FREEZEI("SendMsg to %{public}s:pid:%{public}d, action:%{public}d",
            sess->GetProgramName().c_str(), sess->GetPid(), pointerEvent->GetPointerAction());
    }
    if (!udsServer->SendMsg(fd, pkt)) {
        MMI_HILOGE("Sending structure of EventTouch failed! errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
    if (sess->GetPid() != AppDebugListener::GetInstance()->GetAppDebugPid() && pointerEvent->IsMarkEnabled()) {
        MMI_HILOGD("Session pid:%{public}d", sess->GetPid());
        ANRMgr->AddTimer(ANR_DISPATCH, point->GetId(), currentTime, sess);
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t EventDispatchHandler::DispatchKeyEventPid(UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    int32_t ret = RET_OK;
    // 1.Determine whether the key event is a focus type event or an operation type event,
    // 2.Determine whether the current focus window has a safety sub window.
    auto secSubWindowTargets = WIN_MGR->UpdateTarget(key);
    for (const auto &item : secSubWindowTargets) {
        key->ClearFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
        if (item.second.privacyMode == SecureFlag::PRIVACY_MODE) {
            key->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
        }
        key->SetTargetWindowId(item.second.id);
        key->SetAgentWindowId(item.second.agentWindowId);
        ret = DispatchKeyEvent(item.first, udsServer, key);
    }
    return ret;
}

int32_t EventDispatchHandler::DispatchKeyEvent(int32_t fd, UDSServer& udsServer, std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPR(key, PARAM_INPUT_INVALID);
    currentTime_ = key->GetActionTime();
    if (fd < 0 && currentTime_ - eventTime_ > INTERVAL_TIME) {
        eventTime_ = currentTime_;
        MMI_HILOGE("Invalid fd, fd:%{public}d", fd);
        DfxHisysevent::OnUpdateTargetKey(key, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return RET_ERR;
    }
    MMI_HILOGD("Event dispatcher of server, KeyEvent:KeyCode:%{public}d, Action:%{public}d, EventType:%{public}d,"
        "Fd:%{public}d", key->GetKeyCode(), key->GetAction(), key->GetEventType(), fd);
    auto session = udsServer.GetSession(fd);
    CHKPR(session, RET_ERR);
    auto currentTime = GetSysClockTime();
    if (ANRMgr->TriggerANR(ANR_DISPATCH, currentTime, session)) {
        if (!EventLogHelper::IsBetaVersion()) {
            MMI_HILOGW("The key event does not report normally, application not response."
                "KeyEvent(deviceid:%{public}d, key action:%{public}d)",
                key->GetDeviceId(), key->GetKeyAction());
        } else {
            MMI_HILOGW("The key event does not report normally, application not response."
                "KeyEvent(deviceid:%{public}d, keycode:%{public}d, key action:%{public}d)",
                key->GetDeviceId(), key->GetKeyCode(), key->GetKeyAction());
        }
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
        MMI_HILOGD("Session pid:%{public}d", session->GetPid());
        ANRMgr->AddTimer(ANR_DISPATCH, key->GetId(), currentTime, session);
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS
