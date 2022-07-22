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
#include "input_device_manager.h"
#include "i_pointer_drawing_manager.h"
#include "mouse_event_handler.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
} // namespace

InputWindowsManager::InputWindowsManager() {}

InputWindowsManager::~InputWindowsManager() {}

void InputWindowsManager::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
}

int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    const WindowInfo* windowInfo = nullptr;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == pointerEvent->GetTargetWindowId()) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(windowInfo, RET_ERR);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    return udsServer_->GetClientFd(windowInfo->pid);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
int32_t InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    CALL_DEBUG_ENTER;
    int32_t pid = GetPidAndUpdateTarget(inputEvent);
    if (pid <= 0) {
        MMI_HILOGE("Invalid pid");
        return RET_ERR;
    }
    int32_t fd = udsServer_->GetClientFd(pid);
    if (fd < 0) {
        MMI_HILOGE("Invalid fd");
        return RET_ERR;
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
    static constexpr int32_t invalid_pid = -1;
    CHKPR(inputEvent, invalid_pid);
    const int32_t focusWindowId = displayGroupInfo_.focusWindowId;
    WindowInfo* windowInfo = nullptr;
    for (auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == focusWindowId) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(windowInfo, invalid_pid);
    inputEvent->SetTargetWindowId(windowInfo->id);
    inputEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOGD("focusWindowId:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);
    return windowInfo->pid;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetWindowPid(int32_t windowId) const
{
    int32_t windowPid = -1;
    for (const auto& item : displayGroupInfo_.windowsInfo) {
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
    for (auto &item : displayGroupInfo.windowsInfo) {
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
    if (!displayGroupInfo.displaysInfo.empty()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        IPointerDrawingManager::GetInstance()->OnDisplayInfo(displayGroupInfo.displaysInfo[0].id,
            displayGroupInfo.displaysInfo[0].width, displayGroupInfo.displaysInfo[0].height,
            displayGroupInfo.displaysInfo[0].direction);
#endif // OHOS_BUILD_ENABLE_POINTER
    }
    if (InputDevMgr->HasPointerDevice()) {
        NotifyPointerToWindow();
    }
    PrintDisplayInfo();
}

void InputWindowsManager::SendPointerEvent(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    const MouseLocation &mouseLocation = GetMouseInfo();
    lastLogicX_ = mouseLocation.physicalX;
    lastLogicY_ = mouseLocation.physicalY;
    auto touchWindow = SelectWindowInfo(lastLogicX_, lastLogicY_, pointerEvent);
    if (!touchWindow) {
        MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
        return;
    }
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(lastLogicX_ - touchWindow->area.x);
    pointerItem.SetWindowY(lastLogicY_ - touchWindow->area.y);
    pointerItem.SetDisplayX(lastLogicX_);
    pointerItem.SetDisplayY(lastLogicY_);

    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    lastWindowInfo_ = *touchWindow;

    auto fd = udsServer_->GetClientFd(touchWindow->pid);
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
    PointerEvent::PointerItem currentPointerItem;
    currentPointerItem.SetWindowX(lastLogicX_ - lastWindowInfo_.area.x);
    currentPointerItem.SetWindowY(lastLogicY_ - lastWindowInfo_.area.y);
    currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
    currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());

    pointerEvent->SetTargetWindowId(lastWindowInfo_.id);
    pointerEvent->AddPointerItem(currentPointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetSourceType(lastPointerEvent_->GetSourceType());

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

void InputWindowsManager::NotifyPointerToWindow()
{
    CALL_INFO_TRACE;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == lastWindowInfo_.id) {
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
            break;
        }
    }
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if ((IsInHotArea(lastLogicX_, lastLogicX_, item.pointerHotAreas)) && (lastWindowInfo_.id != item.id)) {
            lastWindowInfo_ = item;
            break;
        }
    }
    DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
}

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

bool InputWindowsManager::TouchPointToDisplayPoint(struct libinput_event_touch* touch,
    EventTouch& touchInfo, int32_t& physicalDisplayId)
{
    CHKPF(touch);
    auto info = FindPhysicalDisplayInfo("default0");
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
    int32_t action = pointerEvent->GetPointerAction();
    if ((firstBtnDownWindowId_ == -1) ||
        ((action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) && (pointerEvent->GetPressedButtons().size() == 1)) ||
        ((action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty()))) {
        int32_t targetWindowId = pointerEvent->GetTargetWindowId();
        for (const auto& item : displayGroupInfo_.windowsInfo) {
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
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == firstBtnDownWindowId_) {
            return std::make_optional(item);
        }
    }
    return std::nullopt;
}

void InputWindowsManager::UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow)
{
    CHKPV(pointerEvent);
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
    IPointerDrawingManager::GetInstance()->DrawPointer(displayId, pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    auto touchWindow = SelectWindowInfo(logicalX, logicalY, pointerEvent);
    if (!touchWindow) {
        MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
        return RET_ERR;
    }
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t windowX = logicalX - touchWindow->area.x;
    int32_t windowY = logicalY - touchWindow->area.y;
    pointerItem.SetWindowX(windowX);
    pointerItem.SetWindowY(windowY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto fd = udsServer_->GetClientFd(touchWindow->pid);
    UpdatePointerEvent(logicalX, logicalY, pointerEvent, *touchWindow);

    MMI_HILOGD("fd:%{public}d,pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
               "logicalX:%{public}d,logicalY:%{public}d,"
               "displayX:%{public}d,displayY:%{public}d,windowX:%{public}d,windowY:%{public}d",
               fd, touchWindow->pid, touchWindow->id, touchWindow->agentWindowId,
               logicalX, logicalY, pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), windowX, windowY);
    return fd;
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
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
        MMI_HILOGE("The touchWindow is nullptr, logicalX:%{public}d, logicalY:%{public}d",
            logicalX, logicalY);
        return RET_ERR;
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
    auto fd = udsServer_->GetClientFd(touchWindow->pid);
    MMI_HILOGD("pid:%{public}d,fd:%{public}d,logicalX:%{public}d,logicalY:%{public}d,"
               "physicalX:%{public}d,physicalY:%{public}d,windowX:%{public}d,windowY:%{public}d,"
               "displayId:%{public}d,TargetWindowId:%{public}d,AgentWindowId:%{public}d",
               touchWindow->pid, fd, logicalX, logicalY, physicalX, physicalY,
               windowX, windowY, displayId, pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
    return fd;
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}
#endif // OHOS_BUILD_ENABLE_POINTER

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

    int32_t width = 0;
    int32_t height = 0;
    if (displayInfo->direction == Direction0 || displayInfo->direction == Direction180) {
        width = displayInfo->width;
        height = displayInfo->height;
    } else {
        height = displayInfo->width;
        width = displayInfo->height;
    }

    if (displayId == lastDisplayId) {
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
    }
    x = static_cast<double>(integerX);
    y = static_cast<double>(integerY);
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