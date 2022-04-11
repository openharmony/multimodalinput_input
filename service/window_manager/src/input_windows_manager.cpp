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

bool InputWindowsManager::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    return true;
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
        if (logicalDisplays_.empty()) {
            return displayId;
        }
        displayId = logicalDisplays_[0].id;
        inputEvent->SetTargetDisplayId(displayId);
    }
    return displayId;
}

int32_t InputWindowsManager::GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent) const
{
    CALL_LOG_ENTER;
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    const int32_t targetDisplayId = GetDisplayId(inputEvent);
    if (targetDisplayId < 0) {
        MMI_HILOGE("No display is available.");
        return RET_ERR;
    }
    for (const auto &item : logicalDisplays_) {
        if (item.id != targetDisplayId) {
            continue;
        }
        MMI_HILOGD("target display:%{public}d", targetDisplayId);
        auto it = windowInfos_.find(item.focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_HILOGE("can't find window info, focuswindowId:%{public}d", item.focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetTargetWindowId(item.focusWindowId);
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_HILOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    MMI_HILOGE("can't find logical display,target display:%{public}d", targetDisplayId);
    return RET_ERR;
}

void InputWindowsManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    CALL_LOG_ENTER;
    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
    windowInfos_.clear();
    for (const auto &item : logicalDisplays) {
        for (const auto &window : item.windowsInfo) {
            auto iter = windowInfos_.insert(std::pair<int32_t, WindowInfo>(window.id, window));
            if (!iter.second) {
                MMI_HILOGE("Insert value failed, Window:%{public}d", window.id);
            }
        }
    }
    if (!logicalDisplays.empty()) {
        IPointerDrawingManager::GetInstance()->OnDisplayInfo(logicalDisplays[0].id,
            logicalDisplays[0].width, logicalDisplays_[0].height);
    }
    PrintDisplayInfo();
}

void InputWindowsManager::PrintDisplayInfo()
{
    MMI_HILOGD("physicalDisplays,num:%{public}zu", physicalDisplays_.size());
    for (const auto &item : physicalDisplays_) {
        MMI_HILOGD("PhysicalDisplays,id:%{public}d,leftDisplay:%{public}d,upDisplay:%{public}d,"
            "topLeftX:%{public}d,topLeftY:%{public}d,width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,logicWidth:%{public}d,logicHeight:%{public}d,"
            "direction:%{public}d",
            item.id, item.leftDisplayId, item.upDisplayId,
            item.topLeftX, item.topLeftY, item.width,
            item.height, item.name.c_str(), item.seatId.c_str(),
            item.seatName.c_str(), item.logicWidth, item.logicHeight, item.direction);
    }

    MMI_HILOGD("logicalDisplays,num:%{public}zu", logicalDisplays_.size());
    for (const auto &item : logicalDisplays_) {
        MMI_HILOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d,topLeftY:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}zu",
            item.id, item.topLeftX, item.topLeftY,
            item.width, item.height, item.name.c_str(),
            item.seatId.c_str(), item.seatName.c_str(), item.focusWindowId,
            item.windowsInfo.size());
    }

    MMI_HILOGD("window info,num:%{public}zu", windowInfos_.size());
    for (const auto &item : windowInfos_) {
        MMI_HILOGD("windowId:%{public}d,id:%{public}d,pid:%{public}d,uid:%{public}d,hotZoneTopLeftX:%{public}d,"
            "hotZoneTopLeftY:%{public}d,hotZoneWidth:%{public}d,hotZoneHeight:%{public}d,display:%{public}d,"
            "agentWindowId:%{public}d,winTopLeftX:%{public}d,winTopLeftY:%{public}d,flags:%{public}d",
            item.first, item.second.id, item.second.pid, item.second.uid, item.second.hotZoneTopLeftX,
            item.second.hotZoneTopLeftY, item.second.hotZoneWidth, item.second.hotZoneHeight,
            item.second.displayId, item.second.agentWindowId, item.second.winTopLeftX, item.second.winTopLeftY,
            item.second.flags);
    }
}

PhysicalDisplayInfo* InputWindowsManager::GetPhysicalDisplay(int32_t id)
{
    for (auto &it : physicalDisplays_) {
        if (it.id == id) {
            return &it;
        }
    }
    MMI_HILOGW("Failed to obtain physical(%{public}d) display", id);
    return nullptr;
}

PhysicalDisplayInfo* InputWindowsManager::FindPhysicalDisplayInfo(const std::string seatId,
    const std::string seatName)
{
    for (auto &it : physicalDisplays_) {
        if (it.seatId == seatId && it.seatName == seatName) {
            return &it;
        }
    }
    MMI_HILOGE("Failed to search for Physical,seat:%{public}s,name:%{public}s", seatId.c_str(), seatName.c_str());
    return nullptr;
}

void InputWindowsManager::RotateTouchScreen(PhysicalDisplayInfo* info, Direction direction,
    int32_t& logicalX, int32_t& logicalY)
{
    CHKPV(info);
    if (direction == Direction0) {
        MMI_HILOGD("direction is Direction0");
        return;
    }
    if (direction == Direction90) {
        MMI_HILOGD("direction is Direction90");
        int32_t temp = logicalX;
        logicalX = info->logicHeight - logicalY;
        logicalY = temp;
        MMI_HILOGD("logicalX is %{public}d, logicalY is %{public}d", logicalX, logicalY);
        return;
    }
    if (direction == Direction180) {
        MMI_HILOGD("direction is Direction180");
        logicalX = info->logicWidth - logicalX;
        logicalY = info->logicHeight - logicalY;
        return;
    }
    if (direction == Direction270) {
        MMI_HILOGD("direction is Direction270");
        int32_t temp = logicalY;
        logicalY = info->logicWidth - logicalX;
        logicalX = temp;
    }
}

bool InputWindowsManager::TransformDisplayPoint(struct libinput_event_touch* touch, Direction& direction,
    int32_t &globalLogicalX, int32_t &globalLogicalY)
{
    CHKPF(touch);
    auto info = FindPhysicalDisplayInfo("seat0", "default0");
    CHKPF(info);

    if ((info->width <= 0) || (info->height <= 0) || (info->logicWidth <= 0) || (info->logicHeight <= 0)) {
        MMI_HILOGE("Get DisplayInfo is error");
        return false;
    }

    auto physicalX = libinput_event_touch_get_x_transformed(touch, info->width) + info->topLeftX;
    auto physicalY = libinput_event_touch_get_y_transformed(touch, info->height) + info->topLeftY;
    if ((physicalX >= INT32_MAX) || (physicalY >= INT32_MAX)) {
        MMI_HILOGE("Physical display coordinates are out of range");
        return false;
    }
    int32_t localPhysicalX = static_cast<int32_t>(physicalX);
    int32_t localPhysicalY = static_cast<int32_t>(physicalY);

    auto logicX = (1L * info->logicWidth * localPhysicalX / info->width);
    auto logicY = (1L * info->logicHeight * localPhysicalY / info->height);
    if ((logicX >= INT32_MAX) || (logicY >= INT32_MAX)) {
        MMI_HILOGE("Physical display logical coordinates out of range");
        return false;
    }
    int32_t localLogcialX = static_cast<int32_t>(logicX);
    int32_t localLogcialY = static_cast<int32_t>(logicY);

    direction = info->direction;
    RotateTouchScreen(info, direction, localLogcialX, localLogcialY);

    globalLogicalX = localLogcialX;
    globalLogicalY = localLogcialY;

    for (auto left = GetPhysicalDisplay(info->leftDisplayId); left != nullptr;
        left = GetPhysicalDisplay(left->leftDisplayId)) {
        if (direction == Direction0 || direction == Direction180) {
            globalLogicalX += left->logicWidth;
        }
        if (direction == Direction90 || direction == Direction270) {
            globalLogicalX += left->logicHeight;
        }
    }

    for (auto upper = GetPhysicalDisplay(info->upDisplayId); upper != nullptr;
        upper = GetPhysicalDisplay(upper->upDisplayId)) {
        if (direction == Direction0 || direction == Direction180) {
            globalLogicalY += upper->logicHeight;
        }
        if (direction == Direction90 || direction == Direction270) {
            globalLogicalY += upper->logicWidth;
        }
    }

    return true;
}

bool InputWindowsManager::TouchMotionPointToDisplayPoint(struct libinput_event_touch* touch, Direction& direction,
    int32_t targetDisplayId, int32_t& displayX, int32_t& displayY)
{
    CHKPF(touch);
    int32_t globalLogicalX;
    int32_t globalLogicalY;
    auto isTransform = TransformDisplayPoint(touch, direction, globalLogicalX, globalLogicalY);
    if (!isTransform) {
        return isTransform;
    }

    for (const auto &display : logicalDisplays_) {
        if (targetDisplayId == display.id ) {
            displayX = globalLogicalX - display.topLeftX;
            displayY = globalLogicalY - display.topLeftY;
            AdjustGlobalCoordinate(displayX, displayY, display.width, display.height);
            MMI_HILOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
                targetDisplayId, displayX, displayY);
            return true;
        }
    }

    return false;
}

bool InputWindowsManager::TouchDownPointToDisplayPoint(struct libinput_event_touch* touch, Direction& direction,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{
    CHKPF(touch);
    int32_t globalLogicalX;
    int32_t globalLogicalY;
    auto isTransform = TransformDisplayPoint(touch, direction, globalLogicalX, globalLogicalY);
    if (!isTransform) {
        return isTransform;
    }

    for (const auto &display : logicalDisplays_) {
        if ((globalLogicalX < display.topLeftX) || (globalLogicalX > display.topLeftX + display.width)) {
            continue;
        }

        if ((globalLogicalY < display.topLeftY) || (globalLogicalY > display.topLeftY + display.height)) {
            continue;
        }

        logicalDisplayId = display.id;
        logicalX = globalLogicalX - display.topLeftX;
        logicalY = globalLogicalY - display.topLeftY;
        AdjustGlobalCoordinate(logicalX, logicalY, display.width, display.height);
        MMI_HILOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
            logicalDisplayId, logicalX, logicalY);
        return true;
    }

    return false;
}

const std::vector<LogicalDisplayInfo>& InputWindowsManager::GetLogicalDisplayInfo() const
{
    return logicalDisplays_;
}

bool InputWindowsManager::IsInsideWindow(int32_t x, int32_t y, const WindowInfo &info) const
{
    return (x >= info.hotZoneTopLeftX) && (x <= (info.hotZoneTopLeftX + info.hotZoneWidth)) &&
        (y >= info.hotZoneTopLeftY) && (y <= (info.hotZoneTopLeftY + info.hotZoneHeight));
}

void InputWindowsManager::AdjustGlobalCoordinate(int32_t& globalX, int32_t& globalY,
    int32_t width, int32_t height)
{
    if (globalX <= 0) {
        globalX = 0;
    }
    if (globalX >= width && width > 0) {
        globalX = width - 1;
    }
    if (globalY <= 0) {
        globalY = 0;
    }
    if (globalY >= height && height > 0) {
        globalY = height - 1;
    }
}

bool InputWindowsManager::UpdataDisplayId(int32_t& displayId)
{
    if (logicalDisplays_.empty()) {
        MMI_HILOGE("logicalDisplays_is empty");
        return false;
    }
    if (displayId < 0) {
        displayId = logicalDisplays_[0].id;
        return true;
    }
    for (const auto &item : logicalDisplays_) {
        if (item.id == displayId) {
            return true;
        }
    }
    return false;
}

LogicalDisplayInfo* InputWindowsManager::GetLogicalDisplayId(int32_t displayId)
{
    for (auto &it : logicalDisplays_) {
        if (it.id == displayId) {
            return &it;
        }
    }
    return nullptr;
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
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayId(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    IPointerDrawingManager::GetInstance()->DrawPointer(displayId, globalX, globalY);
    int32_t action = pointerEvent->GetPointerAction();
    bool isFirstBtnDown = (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN)
        && (pointerEvent->GetPressedButtons().size() == 1);
    bool isMove = (action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty());
    if ((firstBtnDownWindowId_ == -1) || isFirstBtnDown || isMove) {
        for (const auto& item : logicalDisplayInfo->windowsInfo) {
            if ((item.flags & FLAG_NOT_TOUCHABLE) == FLAG_NOT_TOUCHABLE) {
                continue;
            }
            if (IsInsideWindow(globalX, globalY, item)) {
                firstBtnDownWindowId_ = item.id;
                break;
            }
        }
    }
    WindowInfo* firstBtnDownWindow = nullptr;
    for (auto &item : logicalDisplayInfo->windowsInfo) {
        if (item.id == firstBtnDownWindowId_) {
            firstBtnDownWindow = &item;
            break;
        }
    }
    CHKPR(firstBtnDownWindow, ERROR_NULL_POINTER);
    pointerEvent->SetTargetWindowId(firstBtnDownWindow->id);
    pointerEvent->SetAgentWindowId(firstBtnDownWindow->agentWindowId);
    int32_t localX = globalX - firstBtnDownWindow->winTopLeftX;
    int32_t localY = globalY - firstBtnDownWindow->winTopLeftY;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    CHKPR(udsServer_, ERROR_NULL_POINTER);
    auto fd = udsServer_->GetClientFd(firstBtnDownWindow->pid);

    MMI_HILOGD("fd:%{public}d,pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
               "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d",
               fd, firstBtnDownWindow->pid, firstBtnDownWindow->id, firstBtnDownWindow->agentWindowId,
               globalX, globalY, localX, localY);
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
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayId(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    auto targetWindowId = pointerEvent->GetTargetWindowId();
    WindowInfo *touchWindow = nullptr;
    for (auto& item : logicalDisplayInfo->windowsInfo) {
        if ((item.flags & FLAG_NOT_TOUCHABLE) == FLAG_NOT_TOUCHABLE) {
            continue;
        }
        if (targetWindowId < 0) {
            if (IsInsideWindow(globalX, globalY, item)) {
                touchWindow = &item;
                break;
            }
        } else {
            if (targetWindowId == item.id) {
                touchWindow = &item;
                break;
            }
        }
    }
    if (touchWindow == nullptr) {
        MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", targetWindowId);
        return RET_ERR;
    }

    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    int32_t localX = globalX - touchWindow->winTopLeftX;
    int32_t localY = globalY - touchWindow->winTopLeftY;
    pointerItem.SetLocalX(localX);
    pointerItem.SetLocalY(localY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    auto fd = udsServer_->GetClientFd(touchWindow->pid);
    MMI_HILOGD("pid:%{public}d,fd:%{public}d,globalX01:%{public}d,"
               "globalY01:%{public}d,localX:%{public}d,localY:%{public}d,"
               "TargetWindowId:%{public}d,AgentWindowId:%{public}d",
               touchWindow->pid, fd, globalX, globalY, localX, localY,
               pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
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

void InputWindowsManager::UpdateAndAdjustMouseLoction(double& x, double& y)
{
    const std::vector<LogicalDisplayInfo> logicalDisplayInfo = GetLogicalDisplayInfo();
    if (logicalDisplayInfo.empty()) {
        MMI_HILOGE("logicalDisplayInfo is empty");
        return;
    }
    int32_t width = 0;
    int32_t height = 0;
    for (const auto &item : logicalDisplayInfo) {
        width += item.width;
        height += item.height;
    }
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    if (integerX >= width && width > 0) {
        x = static_cast<double>(width);
        mouseLoction_.globalX = width - 1;
    } else if (integerX < 0) {
        x = 0;
        mouseLoction_.globalX = 0;
    } else {
        mouseLoction_.globalX = integerX;
    }
    if (integerY >= height && height > 0) {
        y = static_cast<double>(height);
        mouseLoction_.globalY = height - 1;
    } else if (integerY < 0) {
        y = 0;
        mouseLoction_.globalY = 0;
    } else {
        mouseLoction_.globalY = integerY;
    }
    MMI_HILOGD("Mouse Data: globalX:%{public}d,globalY:%{public}d", mouseLoction_.globalX, mouseLoction_.globalY);
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    if (mouseLoction_.globalX == -1 || mouseLoction_.globalY == -1) {
        if (!logicalDisplays_.empty()) {
            mouseLoction_.globalX = logicalDisplays_[0].width / 2;
            mouseLoction_.globalY = logicalDisplays_[0].height / 2;
        }
    }
    return mouseLoction_;
}
} // namespace MMI
} // namespace OHOS