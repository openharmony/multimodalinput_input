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

#include "anr_manager.h"
#include "app_debug_listener.h"
#include "bytrace_adapter.h"
#include "cursor_drawing_component.h"
#include "dfx_hisysevent.h"
#include "event_log_helper.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "pointer_device_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDispatchHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int64_t ERROR_TIME {3000000};
constexpr int32_t INTERVAL_TIME { 3000 }; // log time interval is 3 seconds.
constexpr int32_t INTERVAL_DURATION { 10 };
constexpr int32_t THREE_FINGERS { 3 };
const std::string CURRENT_DEVICE_TYPE = system::GetParameter("const.product.devicetype", "unknown");
const std::string PRODUCT_TYPE_TABLET = "tablet";
constexpr int32_t PEN_ID { 101 };
} // namespace

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventDispatchHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    if (CURRENT_DEVICE_TYPE == PRODUCT_TYPE_TABLET) {
        AddFlagToEsc(keyEvent);
    }
    DispatchKeyEventPid(*udsServer, keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventDispatchHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    EnsureMouseEventCycle(pointerEvent);
    HandlePointerEventInner(pointerEvent);
    CleanMouseEventCycle(pointerEvent);
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
        CHKPC(info);
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
        if (curInfo != nullptr && (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
            point->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL)) {
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
            cancelEventList_[pointerId] = std::vector<std::shared_ptr<WindowInfo>>(0);
        }
        cancelEventList_[pointerId].push_back(curWindowInfo);
    } else if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
        if (cancelEventList_.find(pointerId) == cancelEventList_.end() ||
            !SearchWindow(cancelEventList_[pointerId], curWindowInfo)) {
            return false;
        }
    }
    return true;
}

bool EventDispatchHandler::SearchWindow(std::vector<std::shared_ptr<WindowInfo>> &windowList,
    std::shared_ptr<WindowInfo> targetWindow)
{
    for (auto &window : windowList) {
        CHKPC(window);
        if (window->id == targetWindow->id) {
            return true;
        }
    }
    return false;
}

void EventDispatchHandler::AddFlagToEsc(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    MMI_HILOGD("add Flag to ESC in: %{public}s", keyEvent->ToString().c_str());
    if (keyEvent->GetKeyCode() != KeyEvent::KEYCODE_ESCAPE) {
        return;
    }
    if (!escToBackFlag_ && keyEvent->HasFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE)) {
        keyEvent->ClearFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
    }

    if (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        escToBackFlag_ = true;
        return;
    }

    if (escToBackFlag_ && (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_UP ||
        keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_CANCEL) &&
        keyEvent->GetKeyItems().size() == 1) {
        MMI_HILOGI("Only esc up or cancel has added flag: %{public}s", keyEvent->ToString().c_str());
        keyEvent->AddFlag(InputEvent::EVENT_FLAG_KEYBOARD_ESCAPE);
        escToBackFlag_ = false;
    }
}

void EventDispatchHandler::HandleMultiWindowPointerEvent(std::shared_ptr<PointerEvent> point,
    PointerEvent::PointerItem pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPV(point);
    std::vector<int32_t> windowIds;
    int32_t devicePointerId = (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN ||
        pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PENCIL) ?
        pointerItem.GetPointerId() + PEN_ID : pointerItem.GetPointerId();
    WIN_MGR->GetTargetWindowIds(devicePointerId, point->GetSourceType(), windowIds);
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
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP &&
            windowInfo->windowInputType == WindowInputType::TRANSMIT_ALL && windowIds.size() > 1) {
            MMI_HILOGD("When the drag is finished, the multi-window distribution is canceled. window:%{public}d,"
                "windowInputType:%{public}d", windowId, static_cast<int32_t>(windowInfo->windowInputType));
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        }
        auto fd = WIN_MGR->GetClientFd(pointerEvent, windowInfo->id);
        if (fd < 0) {
            auto udsServer = InputHandler->GetUDSServer();
            CHKPV(udsServer);
            fd = udsServer->GetClientFd(windowInfo->pid);
            MMI_HILOGI("Window:%{public}d exit front desk, windowfd:%{public}d", windowId, fd);
        }
        pointerEvent->SetTargetWindowId(windowId);
        pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
        double windowX = pointerItem.GetDisplayXPos() - windowInfo->area.x;
        double windowY = pointerItem.GetDisplayYPos() - windowInfo->area.y;
        auto physicalDisplayInfo = WIN_MGR->GetPhysicalDisplay(windowInfo->displayId);
        CHKPV(physicalDisplayInfo);
        if (!windowInfo->transform.empty()) {
            auto windowXY = WIN_MGR->TransformWindowXY(*windowInfo,
                pointerItem.GetDisplayXPos() + physicalDisplayInfo->x,
                pointerItem.GetDisplayYPos() + physicalDisplayInfo->y);
            windowX = windowXY.first;
            windowY = windowXY.second;
        }
        pointerItem.SetWindowX(static_cast<int32_t>(windowX));
        pointerItem.SetWindowY(static_cast<int32_t>(windowY));
        pointerItem.SetWindowXPos(windowX);
        pointerItem.SetWindowYPos(windowY);
        pointerItem.SetTargetWindowId(windowId);
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
        pointerEvent->SetDispatchTimes(count++);
        DispatchPointerEventInner(pointerEvent, fd);
    }
    if (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_THROW ||
        point->GetPointerAction() == PointerEvent::POINTER_ACTION_HOVER_EXIT) {
        WIN_MGR->ClearTargetWindowId(devicePointerId);
    }
}

void EventDispatchHandler::NotifyPointerEventToRS(int32_t pointAction, const std::string& programName,
    uint32_t pid, int32_t pointCnt)
{
    (void)programName;
    (void)pid;
#ifndef OHOS_BUILD_ENABLE_WATCH
    auto begin = std::chrono::high_resolution_clock::now();
    if (POINTER_DEV_MGR.isInit) {
        CursorDrawingComponent::GetInstance().NotifyPointerEventToRS(pointAction, pointCnt);
    }
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::RS_NOTIFY_TOUCH_EVENT, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
#endif // OHOS_BUILD_ENABLE_WATCH
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

void EventDispatchHandler::SendWindowStateError(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    auto sess = udsServer->GetSessionByPid(WIN_MGR->GetWindowStateNotifyPid());
    if (sess != nullptr) {
        NetPacket pkt(MmiMessageId::WINDOW_STATE_ERROR_NOTIFY);
        pkt << pid << windowId;
        if (!sess->SendMsg(pkt)) {
            MMI_HILOGE("SendMsg failed");
            return;
        }
        windowStateErrorInfo_.windowId = -1;
        windowStateErrorInfo_.startTime = -1;
        windowStateErrorInfo_.pid = -1;
    }
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
    UpdateDisplayXY(point);
    std::vector<int32_t> windowIds;
    int32_t devicePointerId = (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN ||
        pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PENCIL) ?
        pointerItem.GetPointerId() + PEN_ID : pointerItem.GetPointerId();
    WIN_MGR->GetTargetWindowIds(devicePointerId, point->GetSourceType(), windowIds);
    if (!windowIds.empty()) {
        HandleMultiWindowPointerEvent(point, pointerItem);
        ResetDisplayXY(point);
        return;
    }
    auto pid = WIN_MGR->GetPidByWindowId(point->GetTargetWindowId());
    int32_t fd = GetClientFd(pid, point);
    auto udsServer = InputHandler->GetUDSServer();
    if (udsServer == nullptr) {
        ResetDisplayXY(point);
        return;
    }
    if (WIN_MGR->GetCancelEventFlag(point) && udsServer->GetSession(fd) == nullptr &&
        pid != -1 && point->GetTargetWindowId() != -1) {
        if (point->GetTargetWindowId() == windowStateErrorInfo_.windowId && pid == windowStateErrorInfo_.pid) {
            if (GetSysClockTime() - windowStateErrorInfo_.startTime >= ERROR_TIME) {
                SendWindowStateError(pid, point->GetTargetWindowId());
            }
        } else {
            windowStateErrorInfo_.windowId = point->GetTargetWindowId();
            windowStateErrorInfo_.startTime = GetSysClockTime();
            windowStateErrorInfo_.pid = pid;
        }
    }
    DispatchPointerEventInner(point, fd);
    ResetDisplayXY(point);
}

int32_t EventDispatchHandler::GetClientFd(int32_t pid, std::shared_ptr<PointerEvent> point)
{
    CHKPR(point, INVALID_FD);
    if (WIN_MGR->AdjustFingerFlag(point)) {
        return INVALID_FD;
    }
    if (point->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL &&
        point->GetPointerAction() != PointerEvent::POINTER_ACTION_HOVER_CANCEL &&
        (point->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN ||
        point->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) && (pid > 0)) {
        WIN_MGR->FoldScreenRotation(point);
        auto udsServer = InputHandler->GetUDSServer();
        CHKPR(udsServer, INVALID_FD);
        return udsServer->GetClientFd(pid);
    }
    return WIN_MGR->GetClientFd(point);
}

void EventDispatchHandler::UpdateDisplayXY(const std::shared_ptr<PointerEvent> &point)
{
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
    CHKPV(point);
    int32_t pointerId = point->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!point->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    int32_t targetDisplayId = point->GetTargetDisplayId();
    int32_t targetWindowId = pointerItem.GetTargetWindowId();
    std::optional<WindowInfo> opt = WIN_MGR->GetWindowAndDisplayInfo(targetWindowId, targetDisplayId);
    if (opt && point->GetFixedMode() == PointerEvent::FixedMode::AUTO) {
        WindowInputType windowInputType = opt.value().windowInputType;
        if (windowInputType != WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE &&
            windowInputType != WindowInputType::DUALTRIGGER_TOUCH &&
            windowInputType != WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE) {
            currentXY_.x = pointerItem.GetDisplayXPos();
            currentXY_.y = pointerItem.GetDisplayYPos();
            pointerItem.SetDisplayX(pointerItem.GetFixedDisplayX());
            pointerItem.SetDisplayY(pointerItem.GetFixedDisplayY());
            pointerItem.SetDisplayXPos(pointerItem.GetFixedDisplayXPos());
            pointerItem.SetDisplayYPos(pointerItem.GetFixedDisplayYPos());
            point->UpdatePointerItem(pointerId, pointerItem);
            currentXY_.fixed = true;
        } else {
            MMI_HILOGI("targetDisplayId=%{private}d, targetWindowId=%{private}d, windowInputType=%{private}d, "
                "not need to modify DX", targetDisplayId, targetWindowId, static_cast<int32_t>(windowInputType));
        }
    }
#endif
}

void EventDispatchHandler::ResetDisplayXY(const std::shared_ptr<PointerEvent> &point)
{
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
    CHKPV(point);
    int32_t pointerId = point->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!point->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    if (point->GetFixedMode() == PointerEvent::FixedMode::AUTO && currentXY_.fixed) {
        pointerItem.SetDisplayX(static_cast<int32_t>(currentXY_.x));
        pointerItem.SetDisplayY(static_cast<int32_t>(currentXY_.y));
        pointerItem.SetDisplayXPos(currentXY_.x);
        pointerItem.SetDisplayYPos(currentXY_.y);
        point->UpdatePointerItem(pointerId, pointerItem);
        currentXY_.fixed = false;
    }
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE
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
        bool isTrue = (point->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) ||
            (point->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) ||
            (point->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) ||
            (point->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) ||
            (point->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN) ||
            (point->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END);
        if (isTrue) {
            MMI_HILOGE("The pointer event does not report normally,app not respon. PointerEvent(deviceid:%{public}d,"
                "action:%{public}d)", point->GetDeviceId(), point->GetPointerAction());
        }
        MMI_HILOGD("The pointer event does not report normally,app not respon. PointerEvent(deviceid:%{public}d,"
            "action:%{public}s)", point->GetDeviceId(), point->DumpPointerAction());
        ANRMgr->HandleAnrState(sess, ANR_DISPATCH, currentTime);
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
    NotifyPointerEventToRS(pointerAc, sess->GetProgramName(),
        static_cast<uint32_t>(sess->GetPid()), pointerEvent->GetPointerCount());
    if (pointerAc != PointerEvent::POINTER_ACTION_MOVE && pointerAc != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerAc != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerAc != PointerEvent::POINTER_ACTION_PULL_MOVE) {
        MMI_HILOG_FREEZEI("SendMsg:%{public}d", sess->GetPid());
    }
    WIN_MGR->PrintEnterEventInfo(pointerEvent);
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
    MMI_HILOGD("Event dispatcher of server, KeyEvent:KeyCode:%{private}d, Action:%{public}d, EventType:%{public}d,"
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
                "KeyEvent(deviceid:%{public}d, keycode:%{private}d, key action:%{public}d)",
                key->GetDeviceId(), key->GetKeyCode(), key->GetKeyAction());
        }
        ANRMgr->HandleAnrState(session, ANR_DISPATCH, currentTime);
    }
    auto keyHandler = InputHandler->GetEventNormalizeHandler();
    CHKPR(keyHandler, RET_ERR);
    if (key->GetKeyCode() != keyHandler->GetCurrentHandleKeyCode()) {
        MMI_HILOGW("Keycode has been changed");
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
    MMI_HILOGD("InputTracking id:%{public}d, SendMsg to %{public}s:pid:%{public}d",
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

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventDispatchHandler::EnsureMouseEventCycle(std::shared_ptr<PointerEvent> event)
{
    WIN_MGR->EnsureMouseEventCycle(event);
}

void EventDispatchHandler::CleanMouseEventCycle(std::shared_ptr<PointerEvent> event)
{
    WIN_MGR->CleanMouseEventCycle(event);
}
#endif // OHOS_BUILD_ENABLE_POINTER
} // namespace MMI
} // namespace OHOS
