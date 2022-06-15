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

#include "i_pointer_drawing_manager.h"
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

int32_t InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    CALL_LOG_ENTER;
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

int32_t InputWindowsManager::GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const
{
    int32_t displayId = inputEvent->GetTargetDisplayId();
    if (displayId < 0) {
        MMI_HILOGD("target display is -1");
        if (displayGroupInfo_.displaysInfo.empty()) {
            return displayId;
        }
        displayId = displayGroupInfo_.displaysInfo[0].id;
        inputEvent->SetTargetDisplayId(displayId);
    }
    return displayId;
}

int32_t InputWindowsManager::GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CALL_LOG_ENTER;
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    const int32_t focusWindowId = displayGroupInfo_.focusWindowId;
    WindowInfo* windowInfo = nullptr;
    for (auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == focusWindowId) {
            windowInfo = &item;
            break;
        }
    }
    if (windowInfo == nullptr) {
        MMI_HILOGE("can't find logical display");
        return RET_ERR;
    }
    inputEvent->SetTargetWindowId(windowInfo->id);
    inputEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOGD("pid:%{public}d", windowInfo->pid);
    return windowInfo->pid;
}

void InputWindowsManager::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_LOG_ENTER;
    displayGroupInfo_ = displayGroupInfo;
    if (!displayGroupInfo.displaysInfo.empty()) {
        IPointerDrawingManager::GetInstance()->OnDisplayInfo(displayGroupInfo.displaysInfo[0].id,
            displayGroupInfo.displaysInfo[0].width, displayGroupInfo.displaysInfo[0].height);
    }
    PrintDisplayInfo();
}

void InputWindowsManager::PrintDisplayInfo()
{
    MMI_HILOGD("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    std::vector<WindowInfo> windowsInfos = displayGroupInfo_.windowsInfo;
    MMI_HILOGD("windowsInfos,num:%{public}zu", windowsInfos.size());
    for (const auto &item : windowsInfos) {
        MMI_HILOGD("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags);
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGD("defaultHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }
    }

    std::vector<DisplayInfo> displayInfos = displayGroupInfo_.displaysInfo;
    MMI_HILOGD("displayInfos,num:%{public}zu", displayInfos.size());
    for (const auto &item : displayInfos) {
        MMI_HILOGD("displayInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d",
            item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
            item.uniq.c_str(), item.direction);
    }
}

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
        MMI_HILOGD("logicalX:%{public}d, logicalY:%{public}d", coord.x, coord.y);
        return;
    }
    if (direction == Direction180) {
        MMI_HILOGD("direction is Direction180");
        coord.x = info.width - coord.x;
        coord.y = info.height - coord.y;
        return;
    }
    if (direction == Direction270) {
        MMI_HILOGD("direction is Direction270");
        int32_t temp = coord.y;
        coord.y = info.width - coord.x;
        coord.x = temp;
    }
}

void InputWindowsManager::GetGlobalLogicDisplayCoord(struct libinput_event_touch* touch,
    EventTouch& touchInfo, DisplayInfo info)
{
    LogicalCoordinate coord {
        .x = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, info.width)),
        .y = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, info.height)),
    };
    RotateTouchScreen(info, coord);
    touchInfo.point.x = coord.x;
    touchInfo.point.y = coord.y;
    PhysicalCoordinate toolPhysCoord {
        .x = libinput_event_touch_get_tool_x_transformed(touch, info.width),
        .y = libinput_event_touch_get_tool_y_transformed(touch, info.height)
    };
    touchInfo.toolRect.point.x = static_cast<int32_t>(toolPhysCoord.x);
    touchInfo.toolRect.point.y = static_cast<int32_t>(toolPhysCoord.y);
}

bool InputWindowsManager::TouchPointToDisplayPoint(struct libinput_event_touch* touch,
    EventTouch& touchInfo, int32_t& logicalDisplayId)
{
    CHKPF(touch);
    auto info = FindPhysicalDisplayInfo("default0");
    CHKPF(info);
    logicalDisplayId = info->id;
    if ((info->width <= 0) || (info->height <= 0)) {
        MMI_HILOGE("Get DisplayInfo is error");
        return false;
    }
    GetGlobalLogicDisplayCoord(touch, touchInfo, *info);
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
    LogicalCoordinate tCoord;
    if (!TransformTipPoint(tip, tCoord, targetDisplayId)) {
        return false;
    }
    return true;
}

DisplayGroupInfo InputWindowsManager::GetDisplayGroupInfo()
{
    return displayGroupInfo_;
}

bool InputWindowsManager::IsInsideWindow(int32_t x, int32_t y, const std::vector<Rect> &rects) const
{
    for (auto &item : rects) {
        if (((x >= item.x) && (x < (item.x + item.width))) &&
            (y >= item.y) && (y < (item.y + item.height))) {
            return true;
        }
    }
    return false;
}

void InputWindowsManager::AdjustGlobalCoordinate(
    const DisplayInfo& displayInfo, int32_t& globalX, int32_t& globalY) const
{
    if (globalX <= 0) {
        globalX = 0;
    }
    if (globalX >= displayInfo.width && displayInfo.width > 0) {
        globalX = displayInfo.width - 1;
    }
    if (globalY <= 0) {
        globalY = 0;
    }
    if (globalY >= displayInfo.height && displayInfo.height > 0) {
        globalY = displayInfo.height - 1;
    }
}

bool InputWindowsManager::UpdataDisplayId(int32_t& displayId)
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

void InputWindowsManager::SelectWindowInfo(const int32_t& globalLogicX, const int32_t& globalLogicY,
    const std::shared_ptr<PointerEvent>& pointerEvent, WindowInfo*& touchWindow)
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
            } else if ((targetWindowId < 0) && (IsInsideWindow(globalLogicX, globalLogicY, item.pointerHotAreas))) {
                firstBtnDownWindowId_ = item.id;
                MMI_HILOGW("find out the dispatch window of this pointerevent when the targetWindowId "
                           "hasn't been setted up yet, window:%{public}d", firstBtnDownWindowId_);
                break;
            } else if ((targetWindowId >= 0) && (targetWindowId == item.id)) {
                firstBtnDownWindowId_ = targetWindowId;
                MMI_HILOGW("find out the dispatch window of this pointerevent when the targetWindowId "
                           "has been setted up already, window:%{public}d", firstBtnDownWindowId_);
                break;
            } else {
                MMI_HILOGW("Continue searching for the dispatch window of this pointerevent");
            }
        }
    }
    for (auto &item : displayGroupInfo_.windowsInfo) {
        if (item.id == firstBtnDownWindowId_) {
            touchWindow = const_cast<WindowInfo*>(&item);
            break;
        }
    }
}

int32_t InputWindowsManager::UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdataDisplayId(displayId)) {
        MMI_HILOGE("This display:%{public}d is not exist", displayId);
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
    int32_t globalLogicX = pointerItem.GetGlobalX() + physicalDisplayInfo->x;
    int32_t globalLogicY = pointerItem.GetGlobalY() + physicalDisplayInfo->y;
    IPointerDrawingManager::GetInstance()->DrawPointer(displayId, pointerItem.GetGlobalX(), pointerItem.GetGlobalY());
    WindowInfo* touchWindow = nullptr;
    SelectWindowInfo(globalLogicX, globalLogicY, pointerEvent, touchWindow);
    if (touchWindow == nullptr) {
        MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
        return RET_ERR;
    }
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t localX = globalLogicX - touchWindow->area.x;
    int32_t localY = globalLogicY - touchWindow->area.y;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto fd = udsServer_->GetClientFd(touchWindow->pid);

    MMI_HILOGD("fd:%{public}d,pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
               "globalLogicX:%{public}d,globalLogicY:%{public}d,"
               "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d",
               fd, touchWindow->pid, touchWindow->id, touchWindow->agentWindowId,
               globalLogicX, globalLogicY, pointerItem.GetGlobalX(), pointerItem.GetGlobalY(), localX, localY);
    return fd;
}

int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdataDisplayId(displayId)) {
        MMI_HILOGE("This display is not exist");
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
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    AdjustGlobalCoordinate(*physicDisplayInfo, globalX, globalY);
    int32_t globalLogicX = pointerItem.GetGlobalX() + physicDisplayInfo->x;
    int32_t globalLogicY = pointerItem.GetGlobalY() + physicDisplayInfo->y;
    WindowInfo *touchWindow = nullptr;
    auto targetWindowId = pointerEvent->GetTargetWindowId();
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
        } else if (IsInsideWindow(globalLogicX, globalLogicY, item.defaultHotAreas)) {
            touchWindow = &item;
            break;
        }
    }
    if (touchWindow == nullptr) {
        MMI_HILOGE("touchWindow is nullptr, globalLogicX:%{public}d, globalLogicY:%{public}d",
            globalLogicX, globalLogicY);
        return RET_ERR;
    }
    auto localX = globalLogicX - touchWindow->area.x;
    auto localY = globalLogicY - touchWindow->area.y;
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    pointerItem.SetGlobalX(globalX);
    pointerItem.SetGlobalY(globalY);
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerItem.SetToolLocalX(pointerItem.GetToolGlobalX() + physicDisplayInfo->x - touchWindow->area.x);
    pointerItem.SetToolLocalY(pointerItem.GetToolGlobalY() + physicDisplayInfo->y - touchWindow->area.y);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    auto fd = udsServer_->GetClientFd(touchWindow->pid);
    MMI_HILOGD("pid:%{public}d,fd:%{public}d,globalLogicX:%{public}d,globalLogicY:%{public}d,"
               "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d,"
               "displayId:%{public}d,TargetWindowId:%{public}d,AgentWindowId:%{public}d",
               touchWindow->pid, fd, globalLogicX, globalLogicY, globalX, globalY,
               localX, localY, displayId, pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
    return fd;
}

int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    return RET_ERR;
}

int32_t InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto source = pointerEvent->GetSourceType();
    switch (source) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            return UpdateTouchScreenTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            return UpdateTouchPadTarget(pointerEvent);
        }
        default: {
            MMI_HILOGW("Source type is unknown, source:%{public}d", source);
            break;
        }
    }
    MMI_HILOGE("Source is not of the correct type, source:%{public}d", source);
    return RET_ERR;
}

bool InputWindowsManager::IsInsideDisplay(DisplayInfo displayInfo, int32_t globalX, int32_t globalY)
{
    return (globalX >= 0 && globalX < displayInfo.width) && (globalY >= 0 && globalY < displayInfo.height);
}

void InputWindowsManager::FindPhysicalDisplay(DisplayInfo displayInfo, int32_t& globalX,
    int32_t& globalY, int32_t& displayId)
{
    int32_t globalLogicX = globalX + displayInfo.x;
    int32_t globalLogicY = globalY + displayInfo.y;
    for (auto &item : displayGroupInfo_.displaysInfo) {
        if ((globalLogicX >= item.x && globalLogicX < item.x + item.width) &&
            (globalLogicY >= item.y && globalLogicY < item.y + item.height)) {
            globalX = globalLogicX - item.x;
            globalY = globalLogicY - item.y;
            displayId = item.id;
        }
    }
}
void InputWindowsManager::UpdateAndAdjustMouseLoction(int32_t& displayId, double& x, double& y)
{
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPV(displayInfo);
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    int32_t lastDisplayId = displayId;
    if (!IsInsideDisplay(*displayInfo, integerX, integerY)) {
        FindPhysicalDisplay(*displayInfo, integerX, integerY, displayId);
    }
    if (displayId == lastDisplayId) {
        if (integerX < 0) {
            integerX = 0;
        }
        if (integerX >= displayInfo->width) {
            integerX = displayInfo->width - 1;
        }
        if (integerY < 0) {
            integerY = 0;
        }
        if (integerY >= displayInfo->height) {
            integerY = displayInfo->height - 1;
        }
    }
    x = static_cast<double>(integerX);
    y = static_cast<double>(integerY);
    mouseLoction_.globalX = integerX;
    mouseLoction_.globalY = integerY;
    MMI_HILOGD("Mouse Data: globalX:%{public}d,globalY:%{public}d, displayId:%{public}d",
        mouseLoction_.globalX, mouseLoction_.globalY, displayId);
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    if (mouseLoction_.globalX == -1 || mouseLoction_.globalY == -1) {
        if (!displayGroupInfo_.displaysInfo.empty()) {
            mouseLoction_.globalX = displayGroupInfo_.displaysInfo[0].width / 2;
            mouseLoction_.globalY = displayGroupInfo_.displaysInfo[0].height / 2;
        }
    }
    return mouseLoction_;
}
} // namespace MMI
} // namespace OHOS