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
#include <cstdio>
#include <cstdlib>
#include "event_dump.h"
#include "util.h"
#include "util_ex.h"
#include "pointer_drawing_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputWindowsManager"};
constexpr uint8_t TOP_LEFT_X  = 0;
constexpr uint8_t TOP_LEFT_Y  = 1;
constexpr uint8_t TOP_RIGHT_X = 2;
constexpr uint8_t TOP_RIGHT_Y = 3;
constexpr uint8_t CORNER = 4;
} // namespace

InputWindowsManager::InputWindowsManager() {}

InputWindowsManager::~InputWindowsManager() {}
/*
 * FullName:  Init
 * Returns:   bool
 * Qualifier: init windows manager server
 */
bool InputWindowsManager::Init(UDSServer& udsServer)
{
    // save server handle
    udsServer_ = &udsServer;
    return true;
}

/*********************************新框架接口添加****************************/
int32_t InputWindowsManager::UpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    MMI_LOGD("enter");
    int32_t pid = GetPidAndUpdateTarget(inputEvent);
    if (pid <= 0) {
        MMI_LOGE("Invalid pid");
        return RET_ERR;
    }
    int32_t fd = udsServer_->GetClientFd(pid);
    if (fd < 0) {
        MMI_LOGE("Invalid fd");
        return RET_ERR;
    }
    MMI_LOGD("leave");
    return fd;
}

int32_t InputWindowsManager::GetDisplayId(std::shared_ptr<InputEvent> inputEvent)
{
    int32_t displayId = inputEvent->GetTargetDisplayId();
    if (displayId < 0) {
        MMI_LOGD("target display is -1");
        if (logicalDisplays_.empty()) {
            return displayId;
        }
        displayId = logicalDisplays_[0].id;
        inputEvent->SetTargetDisplayId(displayId);
    }
    return displayId;
}

int32_t InputWindowsManager::GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent)
{
    MMI_LOGD("enter");
    CHKPR(inputEvent, ERROR_NULL_POINTER);
    const int32_t targetDisplayId = GetDisplayId(inputEvent);
    if (targetDisplayId < 0) {
        MMI_LOGE("No display is available.");
        return RET_ERR;
    }
    for (const auto &item : logicalDisplays_) {
        if (item.id != targetDisplayId) {
            continue;
        }
        MMI_LOGD("target display:%{public}d", targetDisplayId);
        auto it = windowInfos_.find(item.focusWindowId);
        if (it == windowInfos_.end()) {
            MMI_LOGE("can't find window info, focuswindowId:%{public}d", item.focusWindowId);
            return RET_ERR;
        }
        inputEvent->SetTargetWindowId(item.focusWindowId);
        inputEvent->SetAgentWindowId(it->second.agentWindowId);
        MMI_LOGD("pid:%{public}d", it->second.pid);
        return it->second.pid;
    }

    MMI_LOGE("leave,can't find logical display,target display:%{public}d", targetDisplayId);
    return RET_ERR;
}

void InputWindowsManager::UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
    const std::vector<LogicalDisplayInfo> &logicalDisplays)
{
    MMI_LOGD("enter");
    physicalDisplays_.clear();
    logicalDisplays_.clear();
    windowInfos_.clear();

    physicalDisplays_ = physicalDisplays;
    logicalDisplays_ = logicalDisplays;
    int32_t numLogicalDisplay = logicalDisplays.size();
    for (int32_t i = 0; i < numLogicalDisplay; i++) {
        size_t numWindow = logicalDisplays[i].windowsInfo_.size();
        for (size_t j = 0; j < numWindow; j++) {
            WindowInfo myWindow = logicalDisplays[i].windowsInfo_[j];
            auto iter = windowInfos_.insert(std::pair<int32_t, WindowInfo>(myWindow.id, myWindow));
            if (!iter.second) {
                MMI_LOGE("Insert value failed, Window:%{public}d", myWindow.id);
            }
        }
    }
    if (!logicalDisplays.empty()) {
        PointerDrawMgr->TellDisplayInfo(logicalDisplays[0].id, logicalDisplays[0].width, logicalDisplays_[0].height);
    }
    PrintDisplayDebugInfo();
    MMI_LOGD("leave");
}

void InputWindowsManager::PrintDisplayDebugInfo()
{
    MMI_LOGD("physicalDisplays,num:%{public}zu", physicalDisplays_.size());
    for (const auto &item : physicalDisplays_) {
        MMI_LOGD("PhysicalDisplays,id:%{public}d,leftDisplay:%{public}d,upDisplay:%{public}d,"
            "topLeftX:%{public}d,topLeftY:%{public}d,width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,logicWidth:%{public}d,logicHeight:%{public}d,"
            "direction:%{public}d",
            item.id, item.leftDisplayId, item.upDisplayId,
            item.topLeftX, item.topLeftY, item.width,
            item.height, item.name.c_str(), item.seatId.c_str(),
            item.seatName.c_str(), item.logicWidth, item.logicHeight, item.direction);
    }

    MMI_LOGD("logicalDisplays,num:%{public}zu", logicalDisplays_.size());
    for (const auto &item : logicalDisplays_) {
        MMI_LOGD("logicalDisplays, id:%{public}d,topLeftX:%{public}d,topLeftY:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "seatId:%{public}s,seatName:%{public}s,focusWindowId:%{public}d,window num:%{public}zu",
            item.id, item.topLeftX, item.topLeftY,
            item.width, item.height, item.name.c_str(),
            item.seatId.c_str(), item.seatName.c_str(), item.focusWindowId,
            item.windowsInfo_.size());
    }

    MMI_LOGD("window info,num:%{public}zu", windowInfos_.size());
    for (const auto &item : windowInfos_) {
        MMI_LOGD("windowId:%{public}d,id:%{public}d,pid:%{public}d,uid:%{public}d,hotZoneTopLeftX:%{public}d,"
            "hotZoneTopLeftY:%{public}d,hotZoneWidth:%{public}d,hotZoneHeight:%{public}d,display:%{public}d,"
            "agentWindowId:%{public}d,winTopLeftX:%{public}d,winTopLeftY:%{public}d",
            item.first, item.second.id, item.second.pid, item.second.uid, item.second.hotZoneTopLeftX,
            item.second.hotZoneTopLeftY, item.second.hotZoneWidth, item.second.hotZoneHeight,
            item.second.displayId, item.second.agentWindowId, item.second.winTopLeftX, item.second.winTopLeftY);
    }
}

bool InputWindowsManager::TouchPadPointToDisplayPoint_2(struct libinput_event_touch* touch,
    int32_t& logicalX, int32_t& logicalY, int32_t& logicalDisplayId)
{
    CHKPF(touch);
    if (screensInfo_ != nullptr) {
        if ((*screensInfo_) != nullptr)
        logicalDisplayId = (*screensInfo_)->screenId;
        logicalX = static_cast<int32_t>(libinput_event_touch_get_x_transformed(touch, (*screensInfo_)->width));
        logicalY = static_cast<int32_t>(libinput_event_touch_get_y_transformed(touch, (*screensInfo_)->height));
        return true;
    }
    MMI_LOGE("ScreensInfo_ is null");
    return false;
}

PhysicalDisplayInfo* InputWindowsManager::GetPhysicalDisplay(int32_t id)
{
    for (auto &it : physicalDisplays_) {
        if (it.id == id) {
            return &it;
        }
    }
    MMI_LOGE("Failed to obtain physical(%{public}d) display", id);
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
    MMI_LOGE("Failed to search for Physical,seat:%{public}s,name:%{public}s", seatId.c_str(), seatName.c_str());
    return nullptr;
}

void InputWindowsManager::RotateTouchScreen(PhysicalDisplayInfo* info, Direction direction,
    int32_t& logicalX, int32_t& logicalY)
{
    CHKPV(info);
    if (direction == Direction0) {
        MMI_LOGD("direction is Direction0");
        return;
    }
    if (direction == Direction90) {
        MMI_LOGD("direction is Direction90");
        int32_t temp = logicalX;
        logicalX = info->logicHeight - logicalY;
        logicalY = temp;
        MMI_LOGD("logicalX is %{public}d, logicalY is %{public}d", logicalX, logicalY);
        return;
    }
    if (direction == Direction180) {
        MMI_LOGD("direction is Direction180");
        logicalX = info->logicWidth - logicalX;
        logicalY = info->logicHeight - logicalY;
        return;
    }
    if (direction == Direction270) {
        MMI_LOGD("direction is Direction270");
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
        MMI_LOGE("Get DisplayInfo is error");
        return false;
    }

    auto physicalX = libinput_event_touch_get_x_transformed(touch, info->width) + info->topLeftX;
    auto physicalY = libinput_event_touch_get_y_transformed(touch, info->height) + info->topLeftY;
    if ((physicalX >= INT32_MAX) || (physicalY >= INT32_MAX)) {
        MMI_LOGE("Physical display coordinates are out of range");
        return false;
    }
    int32_t localPhysicalX = static_cast<int32_t>(physicalX);
    int32_t localPhysicalY = static_cast<int32_t>(physicalY);

    auto logicX = (1L * info->logicWidth * localPhysicalX / info->width);
    auto logicY = (1L * info->logicHeight * localPhysicalY / info->height);
    if ((logicX >= INT32_MAX) || (logicY >= INT32_MAX)) {
        MMI_LOGE("Physical display logical coordinates out of range");
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
            MMI_LOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
                targetDisplayId, displayX, displayY);
            displayX = globalLogicalX - display.topLeftX;
            displayY = globalLogicalY - display.topLeftY;
        }
        return true;
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
        if (globalLogicalX < display.topLeftX || globalLogicalX > display.topLeftX + display.width) {
            continue;
        }

        if (globalLogicalY < display.topLeftY || globalLogicalY > display.topLeftY + display.height) {
            continue;
        }

        logicalDisplayId = display.id;
        logicalX = globalLogicalX - display.topLeftX;
        logicalY = globalLogicalY - display.topLeftY;
        MMI_LOGD("targetDisplay is %{public}d, displayX is %{public}d, displayY is %{public}d ",
            logicalDisplayId, logicalX, logicalY);
        return true;
    }

    return false;
}

const std::vector<LogicalDisplayInfo>& InputWindowsManager::GetLogicalDisplayInfo() const
{
    return logicalDisplays_;
}

const std::map<int32_t, WindowInfo>& InputWindowsManager::GetWindowInfo() const
{
    return windowInfos_;
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
    if (globalX >= width) {
        globalX = width;
    }
    if (globalY <= 0) {
        globalY = 0;
    }
    if (globalY >= height) {
        globalY = height;
    }
}

bool InputWindowsManager::UpdataDisplayId(int32_t& displayId)
{
    if (logicalDisplays_.empty()) {
        MMI_LOGE("logicalDisplays_is empty");
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

void InputWindowsManager::AdjustCoordinate(double &coordinateX, double &coordinateY)
{
    if (coordinateX < 0) {
        coordinateX = 0;
    }

    if (coordinateY < 0) {
        coordinateY = 0;
    }

    if (logicalDisplays_.empty()) {
        return;
    }

    if (coordinateX > logicalDisplays_[0].width) {
        coordinateX = logicalDisplays_[0].width;
    }
    if (coordinateY > logicalDisplays_[0].height) {
        coordinateY = logicalDisplays_[0].height;
    }
}

int32_t InputWindowsManager::UpdateMouseTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return RET_ERR;
}

int32_t InputWindowsManager::UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdataDisplayId(displayId)) {
        MMI_LOGE("This display:%{public}d is not exist", displayId);
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayId(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    PointerDrawMgr->DrawPointer(displayId, globalX, globalY);
    int32_t action = pointerEvent->GetPointerAction();
    bool isFirstBtnDown = (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN)
        && (pointerEvent->GetPressedButtons().size() == 1);
    bool isMove = (action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty());
    if ((firstBtnDownWindowId_ == -1) || isFirstBtnDown || isMove) {
        for (auto &item : logicalDisplayInfo->windowsInfo_) {
            if (IsInsideWindow(globalX, globalY, item)) {
                firstBtnDownWindowId_ = item.id;
                break;
            }
        }
    }
    WindowInfo* firstBtnDownWindow = nullptr;
    for (auto &item : logicalDisplayInfo->windowsInfo_) {
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

    MMI_LOGD("fd:%{public}d,pid:%{public}d,id:%{public}d,agentWindowId:%{public}d,"
             "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d",
             fd, firstBtnDownWindow->pid, firstBtnDownWindow->id, firstBtnDownWindow->agentWindowId,
             globalX, globalY, localX, localY);
    return fd;
}

int32_t InputWindowsManager::UpdateTouchScreenTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    return RET_ERR;
}

int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdataDisplayId(displayId)) {
        MMI_LOGE("This display is not exist");
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_LOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    MMI_LOGD("display:%{public}d", displayId);
    LogicalDisplayInfo *logicalDisplayInfo = GetLogicalDisplayId(displayId);
    CHKPR(logicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t globalX = pointerItem.GetGlobalX();
    int32_t globalY = pointerItem.GetGlobalY();
    MMI_LOGD("globalX:%{public}d,globalY:%{public}d", globalX, globalY);
    AdjustGlobalCoordinate(globalX, globalY, logicalDisplayInfo->width, logicalDisplayInfo->height);
    auto targetWindowId = pointerEvent->GetTargetWindowId();
    MMI_LOGD("targetWindow:%{public}d", targetWindowId);
    WindowInfo *touchWindow = nullptr;
    for (auto item : logicalDisplayInfo->windowsInfo_) {
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
        MMI_LOGE("touchWindow is nullptr, targetWindow:%{public}d", targetWindowId);
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
    MMI_LOGD("pid:%{public}d,fd:%{public}d,globalX01:%{public}d,"
             "globalY01:%{public}d,localX:%{public}d,localY:%{public}d,"
             "TargetWindowId:%{public}d,AgentWindowId:%{public}d",
             touchWindow->pid, fd, globalX, globalY, localX, localY,
             pointerEvent->GetTargetWindowId(), pointerEvent->GetAgentWindowId());
    return fd;
}

int32_t InputWindowsManager::UpdateTouchPadTargetOld(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    return RET_ERR;
}

int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("Enter");
    return RET_ERR;
}

int32_t InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
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
            MMI_LOGW("Source type is unknown, source:%{public}d", source);
            break;
        }
    }
    MMI_LOGE("Source is not of the correct type, source:%{public}d", source);
    MMI_LOGD("leave");
    return RET_ERR;
}

void InputWindowsManager::UpdateAndAdjustMouseLoction(double& x, double& y)
{
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
    const std::vector<LogicalDisplayInfo> logicalDisplayInfo = GetLogicalDisplayInfo();
    if (logicalDisplayInfo.empty()) {
        MMI_LOGE("logicalDisplayInfo is empty");
        return;
    }
    for (const auto &item : logicalDisplayInfo) {
        bool isOutside[CORNER] = { false, false, false, false };
        if (item.id >= 0) {
            if (integerX < item.topLeftX) {
                mouseLoction_.globalX = item.topLeftX;
                x = item.topLeftX;
                isOutside[TOP_LEFT_X] = true;
            } else {
                isOutside[TOP_LEFT_X] = false;
            }
            if (integerX > (item.topLeftX + item.width)) {
                mouseLoction_.globalX = item.topLeftX + item.width;
                x = item.topLeftX + item.width;
                isOutside[TOP_RIGHT_X] = true;
            } else {
                isOutside[TOP_RIGHT_X] = false;
            }
            if (integerY < item.topLeftY) {
                mouseLoction_.globalY = item.topLeftY;
                y = item.topLeftY;
                isOutside[TOP_LEFT_Y] = true;
            } else {
                isOutside[TOP_LEFT_Y] = false;
            }
            if (integerY > (item.topLeftY + item.height)) {
                mouseLoction_.globalY = item.topLeftY + item.height;
                y = item.topLeftY + item.height;
                isOutside[TOP_RIGHT_Y] = true;
            } else {
                isOutside[TOP_RIGHT_Y] = false;
            }
            if ((isOutside[TOP_LEFT_X] != true) && (isOutside[TOP_LEFT_Y] != true) &&
                (isOutside[TOP_RIGHT_X] != true) && (isOutside[TOP_RIGHT_Y] != true)) {
                mouseLoction_.globalX = x;
                mouseLoction_.globalY = y;
                break;
            }
        }
    }
    MMI_LOGD("Mouse Data: globalX:%{public}d,globalY:%{public}d", mouseLoction_.globalX, mouseLoction_.globalY);
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    return mouseLoction_;
}
} // namespace MMI
} // namespace OHOS