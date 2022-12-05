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

#include "input_windows_manager.h"

#include <cstdlib>
#include <cstdio>

#include "dfx_hisysevent.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "mouse_event_normalize.h"
#include "pointer_drawing_manager.h"
#include "util_ex.h"
#include "util_napi_error.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
#ifdef OHOS_BUILD_ENABLE_POINTER
constexpr int32_t DEFAULT_POINTER_STYLE = 0;
constexpr size_t MAX_WINDOW_COUNT = 20;
#endif // OHOS_BUILD_ENABLE_POINTER
} // namespace

InputWindowsManager::InputWindowsManager() {}
InputWindowsManager::~InputWindowsManager() {}

void InputWindowsManager::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
#ifdef OHOS_BUILD_ENABLE_POINTER
    udsServer_->AddSessionDeletedCallback(std::bind(&InputWindowsManager::OnSessionLost, this, std::placeholders::_1));
    InitMouseDownInfo();
#endif // OHOS_BUILD_ENABLE_POINTER
}

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::InitMouseDownInfo()
{
    mouseDownInfo_.id = -1;
    mouseDownInfo_.pid = -1;
    mouseDownInfo_.defaultHotAreas.clear();
    mouseDownInfo_.pointerHotAreas.clear();
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, INVALID_FD);
    const WindowInfo* windowInfo = nullptr;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == pointerEvent->GetTargetWindowId()) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(udsServer_, INVALID_FD);
    if (windowInfo != nullptr) {
        return udsServer_->GetClientFd(windowInfo->pid);
    }
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL) {
        return udsServer_->GetClientFd(-1);
    }
    int32_t pid = -1;
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
        if (iter != touchItemDownInfos_.end()) {
            pid = iter->second.pid;
            touchItemDownInfos_.erase(iter);
        }
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (mouseDownInfo_.pid != -1) {
            pid = mouseDownInfo_.pid;
            InitMouseDownInfo();
        }
    }
    
    return udsServer_->GetClientFd(pid);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CHKPR(inputEvent, INVALID_FD);
    CALL_DEBUG_ENTER;
    int32_t pid = GetPidAndUpdateTarget(inputEvent);
    if (pid <= 0) {
        MMI_HILOGE("Invalid pid");
        return INVALID_FD;
    }
    int32_t fd = udsServer_->GetClientFd(pid);
    if (fd < 0) {
        MMI_HILOGE("Invalid fd");
        return INVALID_FD;
    }
    return fd;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const
{
    int32_t displayId = inputEvent->GetTargetDisplayId();
    if (displayId < 0) {
        MMI_HILOGD("Target display is -1");
        if (displayGroupInfo_.displaysInfo.empty()) {
            return displayId;
        }
        displayId = displayGroupInfo_.displaysInfo[0].id;
        inputEvent->SetTargetDisplayId(displayId);
    }
    return displayId;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t InputWindowsManager::GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(inputEvent, INVALID_PID);
    const int32_t focusWindowId = displayGroupInfo_.focusWindowId;
    WindowInfo* windowInfo = nullptr;
    for (auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == focusWindowId) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(windowInfo, INVALID_PID);
    inputEvent->SetTargetWindowId(windowInfo->id);
    inputEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOGD("focusWindowId:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);
    return windowInfo->pid;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetWindowPid(int32_t windowId) const
{
    int32_t windowPid = -1;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == windowId) {
            windowPid = item.pid;
            break;
        }
    }
    return windowPid;
}

int32_t InputWindowsManager::GetWindowPid(int32_t windowId, const DisplayGroupInfo& displayGroupInfo) const
{
    int32_t windowPid = -1;
    for (const auto &item : displayGroupInfo.windowsInfo) {
        if (item.id == windowId) {
            windowPid = item.pid;
            break;
        }
    }
    return windowPid;
}

void InputWindowsManager::CheckFocusWindowChange(const DisplayGroupInfo &displayGroupInfo)
{
    const int32_t oldFocusWindowId = displayGroupInfo_.focusWindowId;
    const int32_t newFocusWindowId = displayGroupInfo.focusWindowId;
    if (oldFocusWindowId == newFocusWindowId) {
        return;
    }
    const int32_t oldFocusWindowPid = GetWindowPid(oldFocusWindowId);
    const int32_t newFocusWindowPid = GetWindowPid(newFocusWindowId, displayGroupInfo);
    DfxHisysevent::OnFocusWindowChanged(oldFocusWindowId, newFocusWindowId, oldFocusWindowPid, newFocusWindowPid);
}

void InputWindowsManager::CheckZorderWindowChange(const DisplayGroupInfo &displayGroupInfo)
{
    int32_t oldZorderFirstWindowId = -1;
    int32_t newZorderFirstWindowId = -1;
    if (!displayGroupInfo_.windowsInfo.empty()) {
        oldZorderFirstWindowId = displayGroupInfo_.windowsInfo[0].id;
    }
    if (!displayGroupInfo.windowsInfo.empty()) {
        newZorderFirstWindowId = displayGroupInfo.windowsInfo[0].id;
    }
    if (oldZorderFirstWindowId == newZorderFirstWindowId) {
        return;
    }
    const int32_t oldZorderFirstWindowPid = GetWindowPid(oldZorderFirstWindowId);
    const int32_t newZorderFirstWindowPid = GetWindowPid(newZorderFirstWindowId, displayGroupInfo);
    DfxHisysevent::OnZorderWindowChanged(oldZorderFirstWindowId, newZorderFirstWindowId,
        oldZorderFirstWindowPid, newZorderFirstWindowPid);
}

void InputWindowsManager::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    CheckFocusWindowChange(displayGroupInfo);
    CheckZorderWindowChange(displayGroupInfo);
    displayGroupInfo_ = displayGroupInfo;
    PrintDisplayInfo();
#ifdef OHOS_BUILD_ENABLE_POINTER
    UpdatePointerStyle();
#endif // OHOS_BUILD_ENABLE_POINTER

    if (!displayGroupInfo.displaysInfo.empty()) {
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
        IPointerDrawingManager::GetInstance()->OnDisplayInfo(displayGroupInfo);
        if (InputDevMgr->HasPointerDevice()) {
            MouseLocation mouseLocation = GetMouseInfo();
            int32_t displayId = MouseEventHdr->GetDisplayId();
            if (displayId < 0) {
                displayId = displayGroupInfo_.displaysInfo[0].id;
            }
            auto displayInfo = GetPhysicalDisplay(displayId);
            CHKPV(displayInfo);
            int32_t logicX = mouseLocation.physicalX + displayInfo->x;
            int32_t logicY = mouseLocation.physicalY + displayInfo->y;
            std::optional<WindowInfo> windowInfo;
            CHKPV(lastPointerEvent_);
            if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE &&
                lastPointerEvent_->GetPressedButtons().empty()) {
                windowInfo = GetWindowInfo(logicX, logicY);
            } else {
                windowInfo = SelectWindowInfo(logicX, logicY, lastPointerEvent_);
            }
            if (!windowInfo) {
                MMI_HILOGE("The windowInfo is nullptr");
                return;
            }
            int32_t windowPid = GetWindowPid(windowInfo->id);
            WinInfo info = { .windowPid = windowPid, .windowId = windowInfo->id };
            IPointerDrawingManager::GetInstance()->OnWindowInfo(info);
            IPointerDrawingManager::GetInstance()->DrawPointerStyle();
        }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    }
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (InputDevMgr->HasPointerDevice()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        NotifyPointerToWindow();
#endif // OHOS_BUILD_ENABLE_POINTER
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::SendPointerEvent(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    MouseLocation mouseLocation = GetMouseInfo();
    lastLogicX_ = mouseLocation.physicalX;
    lastLogicY_ = mouseLocation.physicalY;
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW) {
        auto touchWindow = GetWindowInfo(lastLogicX_, lastLogicY_);
        if (!touchWindow) {
            MMI_HILOGE("TouchWindow is nullptr");
            return;
        }
        lastWindowInfo_ = *touchWindow;
    }
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(lastLogicX_ - lastWindowInfo_.area.x);
    pointerItem.SetWindowY(lastLogicY_ - lastWindowInfo_.area.y);
    pointerItem.SetDisplayX(lastLogicX_);
    pointerItem.SetDisplayY(lastLogicY_);
    pointerItem.SetPointerId(0);

    pointerEvent->SetTargetDisplayId(-1);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display:%{public}d is not existent", displayId);
        return;
    }
    pointerEvent->SetTargetDisplayId(displayId);
    pointerEvent->SetTargetWindowId(lastWindowInfo_.id);
    pointerEvent->SetAgentWindowId(lastWindowInfo_.agentWindowId);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->UpdateId();

    auto fd = udsServer_->GetClientFd(lastWindowInfo_.pid);
    auto sess = udsServer_->GetSession(fd);
    CHKPV(sess);

    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void InputWindowsManager::DispatchPointer(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        MMI_HILOGD("The mouse is hide");
        return;
    }
    if (lastPointerEvent_ == nullptr) {
        SendPointerEvent(pointerAction);
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();

    PointerEvent::PointerItem lastPointerItem;
    int32_t lastPointerId = lastPointerEvent_->GetPointerId();
    if (!lastPointerEvent_->GetPointerItem(lastPointerId, lastPointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", lastPointerId);
        return;
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW) {
        std::optional<WindowInfo> windowInfo;
        if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE &&
            lastPointerEvent_->GetPressedButtons().empty()) {
            windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_);
        } else {
            windowInfo = SelectWindowInfo(lastLogicX_, lastLogicY_, lastPointerEvent_);
        }
        if (!windowInfo) {
            MMI_HILOGE("windowInfo is nullptr");
            return;
        }
        if (windowInfo->id != lastWindowInfo_.id) {
            lastWindowInfo_ = *windowInfo;
        }
    }
    PointerEvent::PointerItem currentPointerItem;
    currentPointerItem.SetWindowX(lastLogicX_ - lastWindowInfo_.area.x);
    currentPointerItem.SetWindowY(lastLogicY_ - lastWindowInfo_.area.y);
    currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
    currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
    currentPointerItem.SetPointerId(0);

    pointerEvent->SetTargetDisplayId(lastPointerEvent_->GetTargetDisplayId());
    pointerEvent->SetTargetWindowId(lastWindowInfo_.id);
    pointerEvent->SetAgentWindowId(lastWindowInfo_.agentWindowId);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(currentPointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetSourceType(lastPointerEvent_->GetSourceType());
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetDeviceId(lastPointerEvent_->GetDeviceId());

    auto fd = udsServer_->GetClientFd(lastWindowInfo_.pid);
    if (fd == RET_ERR) {
        auto windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_);
        if (!windowInfo) {
            MMI_HILOGE("The windowInfo is nullptr");
            return;
        }
        fd = udsServer_->GetClientFd(windowInfo->pid);
    }
    auto sess = udsServer_->GetSession(fd);
    if (sess == nullptr) {
        MMI_HILOGI("The last window has disappeared");
        return;
    }

    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void InputWindowsManager::NotifyPointerToWindow()
{
    CALL_INFO_TRACE;
    std::optional<WindowInfo> windowInfo;
    CHKPV(lastPointerEvent_);
    if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE &&
        lastPointerEvent_->GetPressedButtons().empty()) {
        windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_);
    } else {
        windowInfo = SelectWindowInfo(lastLogicX_, lastLogicY_, lastPointerEvent_);
    }
    if (!windowInfo) {
        MMI_HILOGE("The windowInfo is nullptr");
        return;
    }
    if (windowInfo->id == lastWindowInfo_.id) {
        MMI_HILOGI("The mouse pointer does not leave the window:%{public}d", lastWindowInfo_.id);
        lastWindowInfo_ = *windowInfo;
        return;
    }
    bool isFindLastWindow = false;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == lastWindowInfo_.id) {
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
            isFindLastWindow = true;
            break;
        }
    }
    if (!isFindLastWindow) {
        if (udsServer_ != nullptr && udsServer_->GetClientFd(lastWindowInfo_.pid) != INVALID_FD) {
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        }
    }
    lastWindowInfo_ = *windowInfo;
    DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
}
#endif // OHOS_BUILD_ENABLE_POINTER

void InputWindowsManager::PrintDisplayInfo()
{
    MMI_HILOGI("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    MMI_HILOGI("windowsInfos,num:%{public}zu", displayGroupInfo_.windowsInfo.size());
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        MMI_HILOGI("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags);
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGI("defaultHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGI("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }
    }

    MMI_HILOGI("displayInfos,num:%{public}zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        MMI_HILOGI("displayInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d",
            item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
            item.uniq.c_str(), item.direction);
    }
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
const DisplayInfo* InputWindowsManager::GetPhysicalDisplay(int32_t id) const
{
    for (auto &it : displayGroupInfo_.displaysInfo) {
        if (it.id == id) {
            return &it;
        }
    }
    MMI_HILOGW("Failed to obtain physical(%{public}d) display", id);
    return nullptr;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
const DisplayInfo* InputWindowsManager::FindPhysicalDisplayInfo(const std::string& uniq) const
{
    for (auto &it : displayGroupInfo_.displaysInfo) {
        if (it.uniq == uniq) {
            return &it;
        }
    }
    MMI_HILOGE("Failed to search for Physical,uniq:%{public}s", uniq.c_str());
    return nullptr;
}

void InputWindowsManager::RotateTouchScreen(DisplayInfo info, LogicalCoordinate& coord) const
{
    const Direction direction = info.direction;

    if (direction == Direction0) {
        MMI_HILOGD("direction is Direction0");
        return;
    }
    if (direction == Direction90) {
        MMI_HILOGD("direction is Direction90");
        int32_t temp = coord.x;
        coord.x = info.height - coord.y;
        coord.y = temp;
        MMI_HILOGD("physicalX:%{public}d, physicalY:%{public}d", coord.x, coord.y);
        return;
    }
    if (direction == Direction180) {
        MMI_HILOGD("direction is Direction180");
        coord.x = info.width - coord.x;
        coord.y = info.height - coord.y;
        MMI_HILOGD("physicalX:%{public}d, physicalY:%{public}d", coord.x, coord.y);
        return;
    }
    if (direction == Direction270) {
        MMI_HILOGD("direction is Direction270");
        int32_t temp = coord.y;
        coord.y = info.width - coord.x;
        coord.x = temp;
        MMI_HILOGD("physicalX:%{public}d, physicalY:%{public}d", coord.x, coord.y);
    }
}

void InputWindowsManager::GetPhysicalDisplayCoord(struct libinput_event_touch* touch,
    const DisplayInfo& info, EventTouch& touchInfo)
{
    LogicalCoordinate coord {
        .x = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, info.width)),
        .y = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, info.height)),
    };
    RotateTouchScreen(info, coord);
    touchInfo.point.x = coord.x;
    touchInfo.point.y = coord.y;
    touchInfo.toolRect.point.x = static_cast<int32_t>(libinput_event_touch_get_tool_x_transformed(touch, info.width));
    touchInfo.toolRect.point.y = static_cast<int32_t>(libinput_event_touch_get_tool_y_transformed(touch, info.height));
    touchInfo.toolRect.width = static_cast<int32_t>(
        libinput_event_touch_get_tool_width_transformed(touch, info.width));
    touchInfo.toolRect.height = static_cast<int32_t>(
        libinput_event_touch_get_tool_height_transformed(touch, info.height));
}

bool InputWindowsManager::TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
    EventTouch& touchInfo, int32_t& physicalDisplayId)
{
    CHKPF(touch);
    std::string screenId = InputDevMgr->GetScreenId(deviceId);
    if (screenId.empty()) {
        screenId = "default0";
    }
    auto info = FindPhysicalDisplayInfo(screenId);
    CHKPF(info);
    physicalDisplayId = info->id;
    if ((info->width <= 0) || (info->height <= 0)) {
        MMI_HILOGE("Get DisplayInfo is error");
        return false;
    }
    GetPhysicalDisplayCoord(touch, *info, touchInfo);
    return true;
}

bool InputWindowsManager::TransformTipPoint(struct libinput_event_tablet_tool* tip,
    LogicalCoordinate& coord, int32_t& displayId) const
{
    CHKPF(tip);
    auto displayInfo = FindPhysicalDisplayInfo("default0");
    CHKPF(displayInfo);
    MMI_HILOGD("PhysicalDisplay.width:%{public}d, PhysicalDisplay.height:%{public}d, "
               "PhysicalDisplay.topLeftX:%{public}d, PhysicalDisplay.topLeftY:%{public}d",
               displayInfo->width, displayInfo->height, displayInfo->x, displayInfo->y);
    displayId = displayInfo->id;
    PhysicalCoordinate phys {
        .x = libinput_event_tablet_tool_get_x_transformed(tip, displayInfo->width),
        .y = libinput_event_tablet_tool_get_y_transformed(tip, displayInfo->height)
    };

    coord.x = static_cast<int32_t>(phys.x);
    coord.y = static_cast<int32_t>(phys.y);
    MMI_HILOGD("physicalX:%{public}f, physicalY:%{public}f, displayId:%{public}d", phys.x, phys.y, displayId);
    return true;
}

bool InputWindowsManager::CalculateTipPoint(struct libinput_event_tablet_tool* tip,
    int32_t& targetDisplayId, LogicalCoordinate& coord) const
{
    CHKPF(tip);
    if (!TransformTipPoint(tip, coord, targetDisplayId)) {
        return false;
    }
    return true;
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
const DisplayGroupInfo& InputWindowsManager::GetDisplayGroupInfo()
{
    return displayGroupInfo_;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputWindowsManager::IsNeedRefreshLayer(int32_t windowId)
{
    CALL_DEBUG_ENTER;
    MouseLocation mouseLocation = GetMouseInfo();
    int32_t displayId = MouseEventHdr->GetDisplayId();
    if (displayId < 0) {
        displayId = displayGroupInfo_.displaysInfo[0].id;
    }
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPR(displayInfo, false);
    int32_t logicX = mouseLocation.physicalX + displayInfo->x;
    int32_t logicY = mouseLocation.physicalY + displayInfo->y;
    std::optional<WindowInfo> touchWindow = GetWindowInfo(logicX, logicY);
    if (!touchWindow) {
        MMI_HILOGE("TouchWindow is nullptr");
        return false;
    }
    if (touchWindow->id == windowId) {
        MMI_HILOGD("Need refresh pointer style, focusWindow type:%{public}d, window type:%{public}d",
            touchWindow->id, windowId);
        return true;
    }

    MMI_HILOGD("Not need refresh pointer style, focusWindow type:%{public}d, window type:%{public}d",
        touchWindow->id, windowId);
    return false;
}
#endif

void InputWindowsManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    int32_t pid = session->GetPid();

    auto it = pointerStyle_.find(pid);
    if (it != pointerStyle_.end()) {
        pointerStyle_.erase(it);
        MMI_HILOGD("Clear the pointer style map, pd:%{public}d", pid);
    }
}

int32_t InputWindowsManager::SetPointerStyle(int32_t pid, int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        MMI_HILOGE("The pointer style map is not include param pd:%{public}d", pid);
        return COMMON_PARAMETER_ERROR ;
    }
    
    auto iter = it->second.find(windowId);
    if (iter == it->second.end()) {
        MMI_HILOGE("The window id is invalid");
        return COMMON_PARAMETER_ERROR ;
    }
    
    iter->second = pointerStyle;
    MMI_HILOGD("Window id:%{public}d set pointer style:%{public}d success", windowId, pointerStyle);
    return RET_OK;
}

int32_t InputWindowsManager::GetPointerStyle(int32_t pid, int32_t windowId, int32_t &pointerStyle) const
{
    CALL_DEBUG_ENTER;
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        MMI_HILOGE("The pointer style map is not include param pd, %{public}d", pid);
        return RET_ERR;
    }
    
    auto iter = it->second.find(windowId);
    if (iter == it->second.end()) {
        MMI_HILOGW("The window id is invalid");
        pointerStyle = DEFAULT_POINTER_STYLE;
        return RET_OK;
    }
    
    MMI_HILOGD("Window type:%{public}d get pointer style:%{public}d success", windowId, iter->second);
    pointerStyle = iter->second;
    return RET_OK;
}

void InputWindowsManager::UpdatePointerStyle()
{
    CALL_DEBUG_ENTER;
    for (const auto& windowItem : displayGroupInfo_.windowsInfo) {
        int32_t pid = windowItem.pid;
        auto it = pointerStyle_.find(pid);
        if (it == pointerStyle_.end()) {
            std::map<int32_t, int32_t> tmpPointerStyle = {{windowItem.id, DEFAULT_POINTER_STYLE}};
            auto iter = pointerStyle_.insert(std::make_pair(pid, tmpPointerStyle));
            if (!iter.second) {
                MMI_HILOGW("The pd is duplicated");
            }
            continue;
        }

        auto subIter = it->second.find(windowItem.id);
        if (subIter == it->second.end()) {
            if (it->second.size() == MAX_WINDOW_COUNT) {
                MMI_HILOGD("The window count:%{public}zu exceeds limit in same pd", it->second.size());
                it->second.erase(it->second.begin());
            }
            auto iter = it->second.insert(std::make_pair(windowItem.id, DEFAULT_POINTER_STYLE));
            if (!iter.second) {
                MMI_HILOGW("The window type is duplicated");
            }
        }
    }

    MMI_HILOGD("Number of pointer style:%{public}zu", pointerStyle_.size());
}

#endif // OHOS_BUILD_ENABLE_POINTER

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputWindowsManager::IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects) const
{
    for (const auto &item : rects) {
        int32_t displayMaxX = 0;
        int32_t displayMaxY = 0;
        if (!AddInt32(item.x, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return false;
        }
        if (!AddInt32(item.y, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return false;
        }
        if (((x >= item.x) && (x < displayMaxX)) &&
            (y >= item.y) && (y < displayMaxY)) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputWindowsManager::AdjustDisplayCoordinate(
    const DisplayInfo& displayInfo, int32_t& physicalX, int32_t& physicalY) const
{
    int32_t width = 0;
    int32_t height = 0;
    if (displayInfo.direction == Direction0 || displayInfo.direction == Direction180) {
        width = displayInfo.width;
        height = displayInfo.height;
    } else {
        height = displayInfo.width;
        width = displayInfo.height;
    }
    if (physicalX <= 0) {
        physicalX = 0;
    }
    if (physicalX >= width && width > 0) {
        physicalX = width - 1;
    }
    if (physicalY <= 0) {
        physicalY = 0;
    }
    if (physicalY >= height && height > 0) {
        physicalY = height - 1;
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputWindowsManager::UpdateDisplayId(int32_t& displayId)
{
    if (displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGE("logicalDisplays_is empty");
        return false;
    }
    if (displayId < 0) {
        displayId = displayGroupInfo_.displaysInfo[0].id;
        return true;
    }
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        if (item.id == displayId) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
std::optional<WindowInfo> InputWindowsManager::SelectWindowInfo(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t action = pointerEvent->GetPointerAction();
    if ((firstBtnDownWindowId_ == -1) ||
        ((action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) && (pointerEvent->GetPressedButtons().size() == 1)) ||
        ((action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty()))) {
        int32_t targetWindowId = pointerEvent->GetTargetWindowId();
        for (const auto &item : displayGroupInfo_.windowsInfo) {
            if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
                MMI_HILOGD("Skip the untouchable window to continue searching, "
                           "window:%{public}d, flags:%{public}d", item.id, item.flags);
                continue;
            } else if ((targetWindowId < 0) && (IsInHotArea(logicalX, logicalY, item.pointerHotAreas))) {
                firstBtnDownWindowId_ = item.id;
                MMI_HILOGW("Find out the dispatch window of this pointer event when the targetWindowId "
                           "hasn't been setted up yet, window:%{public}d", firstBtnDownWindowId_);
                break;
            } else if ((targetWindowId >= 0) && (targetWindowId == item.id)) {
                firstBtnDownWindowId_ = targetWindowId;
                MMI_HILOGW("Find out the dispatch window of this pointer event when the targetWindowId "
                           "has been setted up already, window:%{public}d", firstBtnDownWindowId_);
                break;
            } else {
                MMI_HILOGW("Continue searching for the dispatch window of this pointer event");
            }
        }
    }
    MMI_HILOGD("firstBtnDownWindowId_:%{public}d", firstBtnDownWindowId_);
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == firstBtnDownWindowId_) {
            return std::make_optional(item);
        }
    }
    return std::nullopt;
}

std::optional<WindowInfo> InputWindowsManager::GetWindowInfo(int32_t logicalX, int32_t logicalY)
{
    CALL_DEBUG_ENTER;
    for (const auto& item : displayGroupInfo_.windowsInfo) {
        if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
            MMI_HILOGD("Skip the untouchable window to continue searching, "
                       "window:%{public}d, flags:%{public}d", item.id, item.flags);
            continue;
        } else if (IsInHotArea(logicalX, logicalY, item.pointerHotAreas)) {
            return std::make_optional(item);
        } else {
            MMI_HILOGW("Continue searching for the dispatch window");
        }
    }
    return std::nullopt;
}

void InputWindowsManager::UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow)
{
    CHKPV(pointerEvent);
    MMI_HILOGD("LastWindowInfo:%{public}d, touchWindow:%{public}d", lastWindowInfo_.id, touchWindow.id);
    if (lastWindowInfo_.id != touchWindow.id) {
        DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        lastLogicX_ = logicalX;
        lastLogicY_ = logicalY;
        lastPointerEvent_ = pointerEvent;
        lastWindowInfo_ = touchWindow;
        DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
        return;
    }
    lastLogicX_ = logicalX;
    lastLogicY_ = logicalY;
    lastPointerEvent_ = pointerEvent;
    lastWindowInfo_ = touchWindow;
}

int32_t InputWindowsManager::UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display:%{public}d is not existent", displayId);
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    auto physicalDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPR(physicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    if (!AddInt32(pointerItem.GetDisplayX(), physicalDisplayInfo->x, logicalX)) {
        MMI_HILOGE("The addition of logicalX overflows");
        return RET_ERR;
    }
    if (!AddInt32(pointerItem.GetDisplayY(), physicalDisplayInfo->y, logicalY)) {
        MMI_HILOGE("The addition of logicalY overflows");
        return RET_ERR;
    }
    auto touchWindow = SelectWindowInfo(logicalX, logicalY, pointerEvent);
    if (!touchWindow) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN || mouseDownInfo_.id == -1) {
            MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
            return RET_ERR;
        }
        touchWindow = std::make_optional(mouseDownInfo_);
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        MMI_HILOGD("mouse event send cancel, window:%{public}d", touchWindow->id);
    }
    int32_t mouseStyle = -1;
    int32_t ret = GetPointerStyle(touchWindow->pid, touchWindow->id, mouseStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, pointerStyleInfo is nullptr");
        return ret;
    }
    if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
        DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    }
    IPointerDrawingManager::GetInstance()->UpdateDisplayInfo(*physicalDisplayInfo);
    WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
    IPointerDrawingManager::GetInstance()->OnWindowInfo(info);
    IPointerDrawingManager::GetInstance()->DrawPointer(displayId, pointerItem.GetDisplayX(),
        pointerItem.GetDisplayY(), MOUSE_ICON(mouseStyle));

    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t windowX = logicalX - touchWindow->area.x;
    int32_t windowY = logicalY - touchWindow->area.y;
    pointerItem.SetWindowX(windowX);
    pointerItem.SetWindowY(windowY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    UpdatePointerEvent(logicalX, logicalY, pointerEvent, *touchWindow);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t action = pointerEvent->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        mouseDownInfo_ = *touchWindow;
    }
    if (action == PointerEvent::POINTER_ACTION_BUTTON_UP) {
        InitMouseDownInfo();
        MMI_HILOGD("Mouse up, clear mouse down info");
    }
    MMI_HILOGD("pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
               "logicalX:%{public}d,logicalY:%{public}d,"
               "displayX:%{public}d,displayY:%{public}d,windowX:%{public}d,windowY:%{public}d",
               touchWindow->pid, touchWindow->id, touchWindow->agentWindowId,
               logicalX, logicalY, pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), windowX, windowY);
    return ERR_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display is not existent");
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    MMI_HILOGD("display:%{public}d", displayId);
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPR(physicDisplayInfo, ERROR_NULL_POINTER);
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayY();
    AdjustDisplayCoordinate(*physicDisplayInfo, physicalX, physicalY);
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    if (!AddInt32(physicalX, physicDisplayInfo->x, logicalX)) {
        MMI_HILOGE("The addition of logicalX overflows");
        return RET_ERR;
    }
    if (!AddInt32(physicalY, physicDisplayInfo->y, logicalY)) {
        MMI_HILOGE("The addition of logicalY overflows");
        return RET_ERR;
    }
    WindowInfo *touchWindow = nullptr;
    auto targetWindowId = pointerItem.GetTargetWindowId();
    for (auto &item : displayGroupInfo_.windowsInfo) {
        if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
            MMI_HILOGD("Skip the untouchable window to continue searching, "
                       "window:%{public}d, flags:%{public}d", item.id, item.flags);
            continue;
        }
        if (targetWindowId >= 0) {
            if (item.id == targetWindowId) {
                touchWindow = &item;
                break;
            }
        } else if (IsInHotArea(logicalX, logicalY, item.defaultHotAreas)) {
            touchWindow = &item;
            break;
        }
    }
    if (touchWindow == nullptr) {
        auto it = touchItemDownInfos_.find(pointerId);
        if (it == touchItemDownInfos_.end() ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            MMI_HILOGE("The touchWindow is nullptr, logicalX:%{public}d, logicalY:%{public}d",
                logicalX, logicalY);
            return RET_ERR;
        }
        touchWindow = &it->second;
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        MMI_HILOGD("touch event send cancel, window:%{public}d", touchWindow->id);
    }
    auto windowX = logicalX - touchWindow->area.x;
    auto windowY = logicalY - touchWindow->area.y;
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    pointerItem.SetDisplayX(physicalX);
    pointerItem.SetDisplayY(physicalY);
    pointerItem.SetWindowX(windowX);
    pointerItem.SetWindowY(windowY);
    pointerItem.SetToolWindowX(pointerItem.GetToolDisplayX() + physicDisplayInfo->x - touchWindow->area.x);
    pointerItem.SetToolWindowY(pointerItem.GetToolDisplayY() + physicDisplayInfo->y - touchWindow->area.y);
    pointerItem.SetTargetWindowId(touchWindow->id);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    MMI_HILOGD("pid:%{public}d,logicalX:%{public}d,logicalY:%{public}d,"
               "physicalX:%{public}d,physicalY:%{public}d,windowX:%{public}d,windowY:%{public}d,"
               "displayId:%{public}d,TargetWindowId:%{public}d,AgentWindowId:%{public}d",
               touchWindow->pid, logicalX, logicalY, physicalX, physicalY,
               windowX, windowY, displayId, pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    int32_t pointerAction = pointerEvent->GetPointerAction();
    if (pointerAction == PointerEvent::POINTER_ACTION_DOWN) {
        touchItemDownInfos_.insert(std::make_pair(pointerId, *touchWindow));
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_UP) {
        auto iter = touchItemDownInfos_.find(pointerId);
        if (iter != touchItemDownInfos_.end()) {
            touchItemDownInfos_.erase(iter);
            MMI_HILOGD("Clear the touch info, action is up, pointerid:%{public}d", pointerId);
        }
    }
    return ERR_OK;
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
int32_t InputWindowsManager::UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t focusWindowId = displayGroupInfo_.focusWindowId;
    const WindowInfo* windowInfo = nullptr;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == focusWindowId) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(windowInfo, ERROR_NULL_POINTER);
    pointerEvent->SetTargetWindowId(windowInfo->id);
    pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOGD("focusWindow:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);

    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto source = pointerEvent->GetSourceType();
    switch (source) {
#ifdef OHOS_BUILD_ENABLE_TOUCH
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return UpdateTouchScreenTarget(pointerEvent);
        }
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return UpdateTouchPadTarget(pointerEvent);
        }
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
        case PointerEvent::SOURCE_TYPE_JOYSTICK: {
            return UpdateJoystickTarget(pointerEvent);
        }
#endif // OHOS_BUILD_ENABLE_JOYSTICK
        default: {
            MMI_HILOGE("Source type is unknown, source:%{public}d", source);
            break;
        }
    }
    return RET_ERR;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
bool InputWindowsManager::IsInsideDisplay(const DisplayInfo& displayInfo, int32_t physicalX, int32_t physicalY)
{
    return (physicalX >= 0 && physicalX < displayInfo.width) && (physicalY >= 0 && physicalY < displayInfo.height);
}

void InputWindowsManager::FindPhysicalDisplay(const DisplayInfo& displayInfo, int32_t& physicalX,
    int32_t& physicalY, int32_t& displayId)
{
    CALL_DEBUG_ENTER;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    if (!AddInt32(physicalX, displayInfo.x, logicalX)) {
        MMI_HILOGE("The addition of logicalX overflows");
        return;
    }
    if (!AddInt32(physicalY, displayInfo.y, logicalY)) {
        MMI_HILOGE("The addition of logicalY overflows");
        return;
    }
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        int32_t displayMaxX = 0;
        int32_t displayMaxY = 0;
        if (!AddInt32(item.x, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return;
        }
        if (!AddInt32(item.y, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return;
        }
        if ((logicalX >= item.x && logicalX < displayMaxX) &&
            (logicalY >= item.y && logicalY < displayMaxY)) {
            physicalX = logicalX - item.x;
            physicalY = logicalY - item.y;
            displayId = item.id;
            break;
        }
    }
}
void InputWindowsManager::UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y)
{
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPV(displayInfo);
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    int32_t lastDisplayId = displayId;
    if (!IsInsideDisplay(*displayInfo, integerX, integerY)) {
        FindPhysicalDisplay(*displayInfo, integerX, integerY, displayId);
    }
    if (displayId != lastDisplayId) {
        displayInfo = GetPhysicalDisplay(displayId);
        CHKPV(displayInfo);
    }
    int32_t width = 0;
    int32_t height = 0;
    if (displayInfo->direction == Direction0 || displayInfo->direction == Direction180) {
        width = displayInfo->width;
        height = displayInfo->height;
    } else {
        height = displayInfo->width;
        width = displayInfo->height;
    }
    if (integerX < 0) {
        integerX = 0;
    }
    if (integerX >= width) {
        integerX = width - 1;
    }
    if (integerY < 0) {
        integerY = 0;
    }
    if (integerY >= height) {
        integerY = height - 1;
    }
    x = static_cast<double>(integerX) + (x - floor(x));
    y = static_cast<double>(integerY) + (y - floor(y));
    mouseLocation_.physicalX = integerX;
    mouseLocation_.physicalY = integerY;
    MMI_HILOGD("Mouse Data: physicalX:%{public}d,physicalY:%{public}d, displayId:%{public}d",
        mouseLocation_.physicalX, mouseLocation_.physicalY, displayId);
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    if (mouseLocation_.physicalX == -1 || mouseLocation_.physicalY == -1) {
        if (!displayGroupInfo_.displaysInfo.empty()) {
            mouseLocation_.physicalX = displayGroupInfo_.displaysInfo[0].width / 2;
            mouseLocation_.physicalY = displayGroupInfo_.displaysInfo[0].height / 2;
        }
    }
    return mouseLocation_;
}
#endif // OHOS_BUILD_ENABLE_POINTER

void InputWindowsManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Windows information:\t");
    mprintf(fd, "windowsInfos,num:%zu", displayGroupInfo_.windowsInfo.size());
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        mprintf(fd,
                "\t windowsInfos: id:%d | pid:%d | uid:%d | area.x:%d | area.y:%d "
                "| area.width:%d | area.height:%d | defaultHotAreas.size:%zu "
                "| pointerHotAreas.size:%zu | agentWindowId:%d | flags:%d \t",
                item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
                item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
                item.agentWindowId, item.flags);
        for (const auto &win : item.defaultHotAreas) {
            mprintf(fd,
                    "\t defaultHotAreas: x:%d | y:%d | width:%d | height:%d \t",
                    win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            mprintf(fd,
                    "\t pointerHotAreas: x:%d | y:%d | width:%d | height:%d \t",
                    pointer.x, pointer.y, pointer.width, pointer.height);
        }
    }
    mprintf(fd, "Displays information:\t");
    mprintf(fd, "displayInfos,num:%zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        mprintf(fd,
                "\t displayInfos: id:%d | x:%d | y:%d | width:%d | height:%d | name:%s "
                "| uniq:%s | direction:%d \t",
                item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
                item.uniq.c_str(), item.direction);
    }
}
} // namespace MMI
} // namespace OHOS
