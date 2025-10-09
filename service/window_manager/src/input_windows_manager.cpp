/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "input_windows_manager.h"
#include <linux/input.h>

#include "account_manager.h"
#include "display_manager_lite.h"
#include "event_log_helper.h"
#include "json_parser.h"
#include "pixel_map.h"
#ifndef OHOS_BUILD_ENABLE_WATCH
#include "knuckle_drawing_component.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "key_command_handler_util.h"
#include "mmi_matrix3.h"
#include "cursor_drawing_component.h"
#include "scene_board_judgement.h"
#ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
#include "touch_drawing_manager.h"
#endif // #ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
#ifdef OHOS_BUILD_ENABLE_ANCO
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "magic_pointer_velocity_tracker.h"
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
#include "hitrace_meter.h"
#include "pull_throw_subscriber_handler.h"
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
#include "dfx_hisysevent_device.h"
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
#include "pointer_device_manager.h"
#include "product_name_definition.h"
#include "product_type_parser.h"
#include "bundle_name_parser.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManager"

namespace OHOS {
namespace MMI {
namespace {
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
constexpr int32_t DEFAULT_POINTER_STYLE { 0 };
constexpr int32_t CURSOR_CIRCLE_STYLE { 41 };
constexpr int32_t AECH_DEVELOPER_DEFINED_STYLE { 47 };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLDABLE_DEVICE_POLICY = system::GetParameter("const.window.foldabledevice.rotate_policy", "");
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr char ROTATE_WINDOW_ROTATE { '0' };
constexpr int32_t FOLDABLE_DEVICE { 2 };
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
constexpr int32_t OUTWINDOW_HOT_AREA { 20 };
constexpr int32_t SCALE_X { 0 };
constexpr int32_t SCALE_Y { 4 };
constexpr int32_t ANCHOR_POINT_X { 6 };
constexpr int32_t ANCHOR_POINT_Y { 7 };
constexpr int32_t TOP_LEFT_AREA { 0 };
constexpr int32_t TOP_AREA { 1 };
constexpr int32_t TOP_RIGHT_AREA { 2 };
constexpr int32_t RIGHT_AREA { 3 };
constexpr int32_t BOTTOM_RIGHT_AREA { 4 };
constexpr int32_t BOTTOM_AREA { 5 };
constexpr int32_t BOTTOM_LEFT_AREA { 6 };
constexpr int32_t LEFT_AREA { 7 };
[[ maybe_unused ]] constexpr int32_t WAIT_TIME_FOR_REGISTER { 2000 };
constexpr int32_t RS_PROCESS_TIMEOUT { 500 * 1000 };
constexpr int32_t HICAR_MIN_DISPLAY_ID { 1000 };
#ifdef OHOS_BUILD_ENABLE_ANCO
constexpr int32_t SHELL_WINDOW_COUNT { 1 };
#endif // OHOS_BUILD_ENABLE_ANCO
constexpr double HALF_RATIO { 0.5 };
constexpr int32_t TWOFOLD { 2 };
constexpr int32_t COMMON_PARAMETER_ERROR { 401 };
const std::string BIND_CFG_FILE_NAME { "/data/service/el1/public/multimodalinput/display_bind.cfg" };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string DEFAULT_ICON_PATH { "/system/etc/multimodalinput/mouse_icon/Default.svg" };
const std::string NAVIGATION_SWITCH_NAME { "settings.input.stylus_navigation_hint" };
const std::string PRODUCT_TYPE_HYM = OHOS::system::GetParameter("const.build.product", "HYM");
const std::string PRODUCT_TYPE = system::GetParameter("const.product.devicetype", "unknown");
const std::string PRODUCT_TYPE_PC = "2in1";
constexpr uint32_t FOLD_STATUS_MASK { 1U << 27U };
constexpr int32_t REPEAT_COOLING_TIME { 100 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
constexpr int32_t POINTER_MOVEFLAG = { 7 };
constexpr size_t POINTER_STYLE_WINDOW_NUM = { 10 };
constexpr size_t SINGLE_TOUCH { 1 };
constexpr int32_t CAST_INPUT_DEVICEID { 0xAAAAAAFF };
constexpr int32_t CAST_SCREEN_DEVICEID { 0xAAAAAAFE };
constexpr int32_t DEFAULT_DPI { 0 };
constexpr int32_t DEFAULT_POSITION { 0 };
constexpr int32_t MAIN_GROUPID { 0 };
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
constexpr uint32_t WINDOW_NAME_TYPE_SCREENSHOT { 1 };
constexpr uint32_t WINDOW_NAME_TYPE_VOICEINPUT { 2 };
constexpr uint32_t SCREEN_CAPTURE_WINDOW_ZORDER { 8000 };
constexpr uint32_t CAST_WINDOW_TYPE { 2106 };
constexpr uint32_t GUIDE_WINDOW_TYPE { 2500 };
constexpr uint32_t VOICE_WINDOW_ZORDER { 4000 };
#define SCREEN_RECORD_WINDOW_WIDTH 400
#define SCREEN_RECORD_WINDOW_HEIGHT 200
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
constexpr uint32_t CURSOR_POSITION_EXPECTED_SIZE { 2 };
constexpr int32_t ENABLE_OUT_SCREEN_TOUCH { 1 };
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
constexpr int64_t SIMULATE_EVENT_LATENCY { 5 };
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
} // namespace

enum PointerHotArea : int32_t {
    TOP = 0,
    BOTTOM = 1,
    LEFT = 2,
    RIGHT = 3,
    TOP_LEFT = 4,
    TOP_RIGHT = 5,
    BOTTOM_LEFT = 6,
    BOTTOM_RIGHT = 7,
};

std::shared_ptr<IInputWindowsManager> IInputWindowsManager::instance_;
std::mutex IInputWindowsManager::mutex_;

std::shared_ptr<IInputWindowsManager> IInputWindowsManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<InputWindowsManager>();
        }
    }
    return instance_;
}

void IInputWindowsManager::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    instance_.reset();
}

InputWindowsManager::InputWindowsManager() : bindInfo_(BIND_CFG_FILE_NAME)
{
    MMI_HILOGI("Bind cfg file name:%{private}s", BIND_CFG_FILE_NAME.c_str());
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    lastWindowInfo_.id = -1;
    lastWindowInfo_.pid = -1;
    lastWindowInfo_.uid = -1;
    lastWindowInfo_.agentWindowId = -1;
    lastWindowInfo_.area = { 0, 0, 0, 0 };
    lastWindowInfo_.flags = -1;
    lastWindowInfo_.windowType = 0;
    lastWindowInfo_.windowNameType = 0;
    mouseDownInfo_.id = -1;
    mouseDownInfo_.pid = -1;
    mouseDownInfo_.uid = -1;
    mouseDownInfo_.agentWindowId = -1;
    mouseDownInfo_.area = { 0, 0, 0, 0 };
    mouseDownInfo_.flags = -1;
    mouseDownInfo_.windowType = 0;
    mouseDownInfo_.windowNameType = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    lastTouchWindowInfo_.id = -1;
    lastTouchWindowInfo_.pid = -1;
    lastTouchWindowInfo_.uid = -1;
    lastTouchWindowInfo_.agentWindowId = -1;
    lastTouchWindowInfo_.area = { 0, 0, 0, 0 };
    lastTouchWindowInfo_.flags = -1;
    lastTouchWindowInfo_.windowType = 0;
    lastTouchWindowInfo_.windowNameType = 0;
#endif // OHOS_BUILD_ENABLE_TOUCH
    displayGroupInfo_.groupId = MAIN_GROUPID;
    displayGroupInfo_.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo_.focusWindowId = -1;
    displayGroupInfoMap_[MAIN_GROUPID] = displayGroupInfo_;
    displayGroupInfoMapTmp_[MAIN_GROUPID] = displayGroupInfo_;
    captureModeInfoMap_[MAIN_GROUPID] = captureModeInfo_;
    pointerDrawFlagMap_[MAIN_GROUPID] = pointerDrawFlag_;
    mouseLocationMap_[MAIN_GROUPID] = mouseLocation_;
    windowsPerDisplayMap_[MAIN_GROUPID] = windowsPerDisplay_;
    lastPointerEventforWindowChangeMap_[MAIN_GROUPID] =  lastPointerEventforWindowChange_;
    displayModeMap_[MAIN_GROUPID] = displayMode_;
    lastDpiMap_[MAIN_GROUPID] = lastDpi_;
    CursorPosition cursorPos = {};
    cursorPosMap_[MAIN_GROUPID] = cursorPos;
}

InputWindowsManager::~InputWindowsManager()
{
    CALL_INFO_TRACE;
}

void InputWindowsManager::DeviceStatusChanged(int32_t deviceId, const std::string &name, const std::string &sysUid,
    const std::string devStatus)
{
    CALL_INFO_TRACE;
    if (devStatus == "add") {
        bindInfo_.AddInputDevice(deviceId, name, sysUid);
    } else {
        bindInfo_.RemoveInputDevice(deviceId);
    }
}

void InputWindowsManager::Init(UDSServer& udsServer)
{
    udsServer_ = &udsServer;
    CHKPV(udsServer_);
    bindInfo_.Load();
#ifdef OHOS_BUILD_ENABLE_POINTER
    udsServer_->AddSessionDeletedCallback([this] (SessionPtr session) { return this->OnSessionLost(session); });
    InitMouseDownInfo();
#endif // OHOS_BUILD_ENABLE_POINTER
    INPUT_DEV_MGR->SetInputStatusChangeCallback(
        [this] (int32_t deviceId, const std::string name, const std::string &sysUid, const std::string devStatus) {
            return this->DeviceStatusChanged(deviceId, name, sysUid, devStatus);
        }
        );
}

bool InputWindowsManager::IgnoreTouchEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
        return false;
    }
    PointerEvent::PointerItem pointer {};
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointer)) {
        MMI_HILOGE("Corrupted pointer event");
        return false;
    }
    /* Fold status is indicated by 27th bit of long axis of touch. */
    uint32_t longAxis = static_cast<uint32_t>(pointer.GetLongAxis());
    if (cancelTouchStatus_) {
        if (longAxis & FOLD_STATUS_MASK) {
            // Screen in the process of folding, ignore this event
            return true;
        } else {
            // Screen folding is complete
            cancelTouchStatus_ = false;
            return false;
        }
    } else if (longAxis & FOLD_STATUS_MASK) {
        // The screen begins to collapse, reissues the cancel event, and ignores this event
        MMI_HILOGI("Screen begins to collapse, reissue cancel event");
        cancelTouchStatus_ = true;
        ReissueCancelTouchEvent(pointerEvent);
        return true;
    }
    return false;
}

void InputWindowsManager::ReissueCancelTouchEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_TOUCH
    auto items = pointerEvent->GetAllPointerItems();
    for (const auto &item : items) {
        if (!item.IsPressed()) {
            continue;
        }
        int32_t pointerId = item.GetPointerId();
        auto tPointerEvent = std::make_shared<PointerEvent>(*pointerEvent);
        tPointerEvent->SetPointerId(pointerId);
        bool isDragging = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
            (item.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId);
        if (isDragging) {
            tPointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_CANCEL);
        } else {
            tPointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        }
        tPointerEvent->SetActionTime(GetSysClockTime());
        tPointerEvent->UpdateId();
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPV(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleTouchEvent(tPointerEvent);
        auto iter = touchItemDownInfos_.find(pointerId);
        if (iter != touchItemDownInfos_.end()) {
            iter->second.flag = false;
        }
    }
#endif // OHOS_BUILD_ENABLE_TOUCH
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::InitMouseDownInfo()
{
    mouseDownInfo_.id = -1;
    mouseDownInfo_.pid = -1;
    mouseDownInfo_.defaultHotAreas.clear();
    mouseDownInfo_.pointerHotAreas.clear();
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

const std::vector<WindowInfo> InputWindowsManager::GetWindowGroupInfoByDisplayIdCopy(int32_t displayId) const
{
    CALL_DEBUG_ENTER;
    int32_t groupId = FindDisplayGroupId(displayId);
    if (displayId < 0) {
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    std::map<int32_t, WindowGroupInfo>& windowsPerDisplay =
        const_cast<std::map<int32_t, WindowGroupInfo> &>(windowsPerDisplay_);

    const auto& iter = windowsPerDisplayMap_.find(groupId);
    windowsPerDisplay = (iter != windowsPerDisplayMap_.end()) ? iter->second : windowsPerDisplay_;
    const auto& it = windowsPerDisplay.find(displayId);
    if (it == windowsPerDisplay.end()) {
        MMI_HILOGD("GetWindowInfo displayId:%{public}d is null from windowGroupInfo_", displayId);
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    if (it->second.windowsInfo.empty()) {
        MMI_HILOGW("GetWindowInfo displayId:%{public}d is empty", displayId);
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    return it->second.windowsInfo;
}

const std::vector<WindowInfo>& InputWindowsManager::GetWindowGroupInfoByDisplayId(int32_t displayId) const
{
    CALL_DEBUG_ENTER;
    int32_t groupId = FindDisplayGroupId(displayId);
    if (displayId < 0) {
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    std::map<int32_t, WindowGroupInfo>& windowsPerDisplay =
        const_cast<std::map<int32_t, WindowGroupInfo> &>(windowsPerDisplay_);

    const auto& iter = windowsPerDisplayMap_.find(groupId);
    windowsPerDisplay = (iter != windowsPerDisplayMap_.end()) ? iter->second : windowsPerDisplay_;
    const auto& it = windowsPerDisplay.find(displayId);
    if (it == windowsPerDisplay.end()) {
        MMI_HILOGD("GetWindowInfo displayId:%{public}d is null from windowGroupInfo_", displayId);
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    if (it->second.windowsInfo.empty()) {
        MMI_HILOGW("GetWindowInfo displayId:%{public}d is empty", displayId);
        const auto& windoInfo = GetWindowInfoVector(groupId);
        return windoInfo;
    }
    return it->second.windowsInfo;
}

bool InputWindowsManager::CheckAppFocused(int32_t pid)
{
    int32_t focusWindowId = DEFAULT_VALUE;
    for (const auto& item : displayGroupInfoMap_) {
        focusWindowId = item.second.focusWindowId;
        for (const auto& windowinfo : item.second.windowsInfo) {
            if ((windowinfo.id == focusWindowId) && (windowinfo.pid == pid)) {
                return true;
            } else if (windowinfo.id == focusWindowId) {
                MMI_HILOGW("CheckAppFocused focusWindowId:%{public}d, pid:%{public}d, windowinfo.pid:%{public}d",
                    focusWindowId, pid, windowinfo.pid);
                break;
            }
        }
    }
    MMI_HILOGW("CheckAppFocused failed:%{public}d", focusWindowId);
    return false;
}

bool InputWindowsManager::GetCancelEventFlag(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
        if (iter != touchItemDownInfos_.end()) {
            return iter->second.flag;
        }
        return true;
    } else if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE ||
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        return mouseDownInfo_.pid == -1;
    }
    return false;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputWindowsManager::AdjustFingerFlag(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return false;
    }
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    bool isPenHover = pointerEvent->GetPointerItem(pointerId, pointerItem) && pointerItem.IsPressed() == false &&
        (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN ||
        pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PENCIL);
    if (isPenHover) {
        return false;
    }
    auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
    return (iter != touchItemDownInfos_.end() && !(iter->second.flag));
}

int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, INVALID_FD);
    const WindowInfo* windowInfo = nullptr;
    auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        int32_t pointerId = pointerEvent->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        bool isPenHover = pointerEvent->GetPointerItem(pointerId, pointerItem) && pointerItem.IsPressed() == false &&
            (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN ||
            pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PENCIL);
        if (isPenHover) {
            MMI_HILOG_DISPATCHD("Skip hover event");
        } else if (iter != touchItemDownInfos_.end() && !(iter->second.flag)) {
            MMI_HILOG_DISPATCHD("Drop event");
            return INVALID_FD;
        }
    }
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    for (const auto &item : windowsInfo) {
        bool checkUIExtentionWindow = false;
        // Determine whether it is a safety sub window
        for (auto &uiExtentionWindowInfo : item.uiExtentionWindowInfo) {
            if (uiExtentionWindowInfo.id == pointerEvent->GetTargetWindowId()) {
                MMI_HILOGD("Find windowInfo by window id %{public}d", uiExtentionWindowInfo.id);
                windowInfo = &uiExtentionWindowInfo;
                checkUIExtentionWindow = true;
                break;
            }
        }
        if (checkUIExtentionWindow) {
            break;
        }
        bool checkWindow = (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
            !IsValidZorderWindow(item, pointerEvent);
        if (checkWindow) {
            MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching,"
                "window:%{public}d, flags:%{public}d", item.id, item.flags);
            continue;
        }
        if (item.id == pointerEvent->GetTargetWindowId()) {
            MMI_HILOG_DISPATCHD("find windowinfo by window id %{public}d", item.id);
            windowInfo = &item;
            UpdateWindowInfoFlag(item.flags, pointerEvent);
            break;
        }
    }

    if (windowInfo == nullptr && pointerEvent->GetTargetDisplayId() != firstBtnDownWindowInfo_.second) {
        windowsInfo.clear();
        windowsInfo = GetWindowGroupInfoByDisplayId(firstBtnDownWindowInfo_.second);
        for (const auto &item : windowsInfo) {
            bool checkUIExtentionWindow = false;
            // Determine whether it is a safety sub window
            for (auto &uiExtentionWindowInfo : item.uiExtentionWindowInfo) {
                if (uiExtentionWindowInfo.id == pointerEvent->GetTargetWindowId()) {
                    MMI_HILOGD("Find windowInfo by window id %{public}d", uiExtentionWindowInfo.id);
                    windowInfo = &uiExtentionWindowInfo;
                    checkUIExtentionWindow = true;
                    break;
                }
            }
            if (checkUIExtentionWindow) {
                break;
            }
            bool checkWindow = (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
                !IsValidZorderWindow(item, pointerEvent);
            if (checkWindow) {
                MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching,"
                    "window:%{public}d, flags:%{public}d", item.id, item.flags);
                continue;
            }
            if (item.id == pointerEvent->GetTargetWindowId()) {
                MMI_HILOG_DISPATCHD("find windowinfo by window id %{public}d", item.id);
                windowInfo = &item;
                UpdateWindowInfoFlag(item.flags, pointerEvent);
                break;
            }
        }
    }
    if (windowInfo == nullptr) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
            dragPointerStyle_.id = DEFAULT_POINTER_STYLE;
            CursorDrawingComponent::GetInstance().DrawPointerStyle(dragPointerStyle_);
        }
        MMI_HILOG_DISPATCHD("window info is null, pointerAction:%{public}d", pointerEvent->GetPointerAction());
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_LEAVE_WINDOW ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW) {
            windowInfo = &lastWindowInfo_;
        }
    }
    CHKPR(udsServer_, INVALID_FD);
    if (windowInfo != nullptr) {
        FoldScreenRotation(pointerEvent);
        MMI_HILOG_DISPATCHD("get agentPid:%{public}d from idxPidMap", windowInfo->agentPid);
        return udsServer_->GetClientFd(windowInfo->agentPid);
    }
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL &&
        pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_HOVER_CANCEL) {
        MMI_HILOG_DISPATCHD("window info is null, so pointerEvent is dropped! return -1");
        return udsServer_->GetClientFd(-1);
    }
    int32_t agentPid = -1;
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (iter != touchItemDownInfos_.end()) {
            MMI_HILOG_DISPATCHI("Cant not find agentPid");
            agentPid = iter->second.window.agentPid;
            iter->second.flag = false;
            MMI_HILOG_DISPATCHD("touchscreen occurs, new agentPid:%{public}d", agentPid);
        }
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    if ((pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) ||
        (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_CROWN)) {
        if (mouseDownInfo_.agentPid != -1) {
            agentPid = GetWindowAgentPid(mouseDownInfo_.agentWindowId);
            if (agentPid < 0) {
                agentPid = mouseDownInfo_.agentPid;
            }
            MMI_HILOGD("mouseevent occurs, update the agentPid:%{public}d", agentPid);
            InitMouseDownInfo();
        } else if (axisBeginWindowInfo_ && axisBeginWindowInfo_->agentPid != -1) {
            agentPid = GetWindowAgentPid(axisBeginWindowInfo_->agentWindowId);
            if (agentPid < 0) {
                agentPid = axisBeginWindowInfo_->agentPid;
            }
            MMI_HILOGD("The axisBeginEvent occurs, update the agentPid:%{public}d", agentPid);
            axisBeginWindowInfo_ = std::nullopt;
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    MMI_HILOGD("Get clientFd by %{public}d", agentPid);
    return udsServer_->GetClientFd(agentPid);
}

void InputWindowsManager::FoldScreenRotation(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (iter == touchItemDownInfos_.end()) {
            MMI_HILOG_DISPATCHD("Unable to find finger information for touch.pointerId:%{public}d",
                pointerEvent->GetPointerId());
            return;
        }
    }
    auto displayId = pointerEvent->GetTargetDisplayId();
    Direction physicDisplayInfoDirection = GetLogicalPositionDirection(displayId);
    if (lastDirection_.first != displayId || lastDirection_.second == static_cast<Direction>(-1)) {
        lastDirection_ = std::make_pair(displayId, physicDisplayInfoDirection);
        return;
    }
    if (physicDisplayInfoDirection != lastDirection_.second) {
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
            PointerEvent::PointerItem item;
            if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
                MMI_HILOGE("Get pointer item failed. pointer:%{public}d", pointerEvent->GetPointerId());
                lastDirection_ = std::make_pair(displayId, physicDisplayInfoDirection);
                return;
            }
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE && !(item.IsPressed())) {
                lastDirection_ = std::make_pair(displayId, physicDisplayInfoDirection);
                return;
            }
        }
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_HOVER_MOVE) {
            int32_t pointerAction = pointerEvent->GetPointerAction();
            if (IsAccessibilityFocusEvent(pointerEvent)) {
                    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_CANCEL);
            } else {
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            }
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            pointerEvent->SetOriginPointerAction(pointerAction);
            MMI_HILOG_DISPATCHI("touch event send cancel");
            if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
                iter->second.flag = false;
            }
        }
    }
    lastDirection_ = std::make_pair(displayId, physicDisplayInfoDirection);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

OLD::DisplayGroupInfo& InputWindowsManager::FindTargetDisplayGroupInfo(int32_t displayId)
{
    for (auto& it : displayGroupInfoMap_) {
        for (const auto& item : it.second.displaysInfo) {
            if (item.id == displayId) {
                return it.second;
            }
        }
    }
    return GetDefaultDisplayGroupInfo();
}

int32_t InputWindowsManager::FindDisplayGroupId(int32_t displayId) const
{
    for (const auto& it : displayGroupInfoMap_) {
        for (const auto& item : it.second.displaysInfo) {
            if (item.id == displayId) {
                return it.second.groupId;
            }
        }
    }
    return DEFAULT_GROUP_ID;
}

OLD::DisplayGroupInfo& InputWindowsManager::GetDefaultDisplayGroupInfo()
{
    for (auto &item : displayGroupInfoMap_) {
        if (item.second.type == GroupType::GROUP_DEFAULT) {
            return item.second;
        }
    }
    return displayGroupInfo_;
}

const OLD::DisplayGroupInfo& InputWindowsManager::GetConstMainDisplayGroupInfo() const
{
    for (auto &it : displayGroupInfoMap_)
        if (it.second.type == GroupType::GROUP_DEFAULT) {
            return it.second;
        }
    return displayGroupInfo_;
}

const OLD::DisplayGroupInfo& InputWindowsManager::FindDisplayGroupInfo(int32_t displayId) const {
    for (auto& it : displayGroupInfoMap_) {
        for (auto& item : it.second.displaysInfo) {
            if (item.id == displayId) {
                return it.second;
            }
        }
    }
    return displayGroupInfo_;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
std::vector<std::pair<int32_t, TargetInfo>> InputWindowsManager::UpdateTarget(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    if (!isParseConfig_) {
        ParseConfig();
        isParseConfig_ = true;
    }
    std::vector<std::pair<int32_t, TargetInfo>> secSubWindowTargets;
    if (keyEvent == nullptr) {
        MMI_HILOG_DISPATCHE("keyEvent is nullptr");
        return secSubWindowTargets;
    }
    auto secSubWindows = GetPidAndUpdateTarget(keyEvent);
    for (const auto &item : secSubWindows) {
        int32_t fd = INVALID_FD;
        int32_t agentPid = item.first;
        if (agentPid <= 0) {
            MMI_HILOG_DISPATCHE("Invalid agentPid:%{public}d", agentPid);
            continue;
        }
        CHKPC(udsServer_);
        fd = udsServer_->GetClientFd(agentPid);
        if (fd < 0) {
            MMI_HILOG_DISPATCHE("The windowAgentPid:%{public}d matching fd:%{public}d is invalid", agentPid, fd);
            continue;
        }
        secSubWindowTargets.emplace_back(std::make_pair(fd, item.second));
    }
    return secSubWindowTargets;
}

void InputWindowsManager::HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    int32_t groupId = FindDisplayGroupId(keyEvent->GetTargetDisplayId());
    int32_t focusWindowId = GetFocusWindowId(groupId);
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(keyEvent->GetTargetDisplayId());
    for (auto &item : windowsInfo) {
        if (item.id == focusWindowId) {
            keyEvent->SetTargetWindowId(item.id);
            keyEvent->SetAgentWindowId(item.agentWindowId);
            if (item.privacyMode == SecureFlag::PRIVACY_MODE) {
                keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
            }
            UpdateWindowInfoFlag(item.flags, keyEvent);
            return;
        }
    }
}

void InputWindowsManager::ReissueEvent(std::shared_ptr<KeyEvent> keyEvent, int32_t focusWindowId)
{
    CHKPV(keyEvent);
    if (keyEvent->GetKeyAction() != KeyEvent::KEY_ACTION_CANCEL && focusWindowId_ != -1 &&
        focusWindowId_ != focusWindowId && keyEvent->IsRepeatKey()) {
        auto keyEventReissue = std::make_shared<KeyEvent>(*keyEvent);
        auto keyItem = keyEventReissue->GetKeyItems();
        for (auto item = keyItem.begin(); item != keyItem.end(); ++item) {
            item->SetPressed(false);
        }
        keyEventReissue->SetKeyItem(keyItem);
        keyEventReissue->UpdateId();
        keyEventReissue->SetAction(KeyEvent::KEY_ACTION_CANCEL);
        keyEventReissue->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
        keyEventReissue->SetTargetWindowId(focusWindowId_);
        keyEventReissue->SetAgentWindowId(focusWindowId_);

        auto eventDispatchHandler = InputHandler->GetEventDispatchHandler();
        auto udServer = InputHandler->GetUDSServer();
        CHKPV(udServer);
        auto fd = udServer->GetClientFd(GetWindowAgentPid(focusWindowId_));
        MMI_HILOG_DISPATCHI("Out focus window:%{public}d is replaced by window:%{public}d",
            focusWindowId_, focusWindowId);
        if (eventDispatchHandler != nullptr && udServer != nullptr) {
            eventDispatchHandler->DispatchKeyEvent(fd, *udServer, keyEventReissue);
        }
    }
    focusWindowId_ = focusWindowId;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const
{
    CHKPR(inputEvent, RET_ERR);
    int32_t displayId = inputEvent->GetTargetDisplayId();
    if (displayId < 0) {
        MMI_HILOGD("Target display is -1");
        int32_t groupId = FindDisplayGroupId(displayId);
            const auto iter = displayGroupInfoMap_.find(groupId);
            if (iter != displayGroupInfoMap_.end()) {
                if (iter->second.displaysInfo.empty()) {
                    return displayId;
                }
                displayId = iter->second.displaysInfo[0].id;
            } else {
                if (displayGroupInfo_.displaysInfo.empty()) {
                    return displayId;
                }
                displayId = displayGroupInfo_.displaysInfo[0].id;
            }
        inputEvent->SetTargetDisplayId(displayId);
    }
    return displayId;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    CHKPR(udsServer_, INVALID_FD);
    CHKPR(pointerEvent, INVALID_FD);
    const WindowInfo* windowInfo = nullptr;
    std::vector<WindowInfo> windowInfos = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    for (const auto &item : windowInfos) {
        bool checkUIExtentionWindow = false;
        // Determine whether it is a safety sub window
        for (const auto &uiExtentionWindowInfo : item.uiExtentionWindowInfo) {
            if (uiExtentionWindowInfo.id == windowId) {
                MMI_HILOGD("Find windowInfo by window id %{public}d", uiExtentionWindowInfo.id);
                windowInfo = &uiExtentionWindowInfo;
                checkUIExtentionWindow = true;
                break;
            }
        }
        if (checkUIExtentionWindow) {
            break;
        }
        bool checkWindow = (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
            !IsValidZorderWindow(item, pointerEvent);
        if (checkWindow) {
            MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching,"
                "window:%{public}d, flags:%{public}d", item.id, item.flags);
            continue;
        }
        if (item.id == windowId) {
            MMI_HILOGD("Find windowInfo by window id %{public}d", item.id);
            windowInfo = &item;
            break;
        }
    }
    if (windowInfo == nullptr) {
        MMI_HILOGE("WindowInfo is nullptr, pointerAction:%{public}d", pointerEvent->GetPointerAction());
        return INVALID_FD;
    }
    MMI_HILOGD("Get agentPid:%{public}d from idxPidMap", windowInfo->agentPid);
    return udsServer_->GetClientFd(windowInfo->agentPid);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
std::vector<std::pair<int32_t, TargetInfo>> InputWindowsManager::GetPidAndUpdateTarget(
    std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    std::vector<std::pair<int32_t, TargetInfo>> secSubWindows;
    if (keyEvent == nullptr) {
        MMI_HILOG_DISPATCHE("keyEvent is nullptr");
        return secSubWindows;
    }
    int32_t groupId = FindDisplayGroupId(keyEvent->GetTargetDisplayId());
    const int32_t focusWindowId = GetFocusWindowId(groupId);
    UpdateKeyEventDisplayId(keyEvent, focusWindowId, groupId);
    WindowInfo* windowInfo = nullptr;
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(keyEvent->GetTargetDisplayId());
    bool isUIExtention = false;
    auto iter = windowsInfo.begin();
    for (; iter != windowsInfo.end(); ++iter) {
        if (iter->id == focusWindowId) {
            windowInfo = &(*iter);
            if (!iter->uiExtentionWindowInfo.empty() && !IsOnTheWhitelist(keyEvent)) {
                isUIExtention = true;
            }
            break;
        }
    }
    if (windowInfo == nullptr) {
        MMI_HILOG_DISPATCHE("windowInfo is nullptr");
        return secSubWindows;
    }
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (IsAncoWindowFocus(*windowInfo)) {
        MMI_HILOG_DISPATCHD("focusWindowId:%{public}d is anco window", focusWindowId);
        return secSubWindows;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    TargetInfo targetInfo = { windowInfo->privacyMode, windowInfo->id, windowInfo->agentWindowId };
    secSubWindows.emplace_back(std::make_pair(windowInfo->agentPid, targetInfo));
    if (isUIExtention) {
        for (const auto &item : iter->uiExtentionWindowInfo) {
            if (item.privacyUIFlag) {
                MMI_HILOG_DISPATCHD("security sub windowId:%{public}d,agentPid:%{public}d", item.id, item.agentPid);
                targetInfo.privacyMode = item.privacyMode;
                targetInfo.id = item.id;
                targetInfo.agentWindowId = item.agentWindowId;
                secSubWindows.emplace_back(std::make_pair(item.agentPid, targetInfo));
            }
        }
    }
    return secSubWindows;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetWindowPid(int32_t windowId) const
{
    CALL_DEBUG_ENTER;
    for (const auto &groupItem : displayGroupInfoMap_) {
        for (const auto &item : groupItem.second.windowsInfo) {
            MMI_HILOGD("Get windowId:%{public}d", item.id);
            if (item.id == windowId) {
                return item.pid;
            }
            for (const auto &uiExtentionWindow : item.uiExtentionWindowInfo) {
                CHKCC(uiExtentionWindow.id == windowId);
                return uiExtentionWindow.pid;
            }
        }
    }
    return INVALID_PID;
}

int32_t InputWindowsManager::GetWindowAgentPid(int32_t windowId) const
{
    CALL_DEBUG_ENTER;
    for (const auto &groupItem : displayGroupInfoMap_) {
        for (const auto &item : groupItem.second.windowsInfo) {
            MMI_HILOGD("Get windowId:%{public}d", item.id);
            if (item.id == windowId) {
                return item.agentPid;
            }
            for (const auto &uiExtentionWindow : item.uiExtentionWindowInfo) {
                CHKCC(uiExtentionWindow.id == windowId);
                return uiExtentionWindow.agentPid;
            }
        }
    }
    return INVALID_PID;
}

int32_t InputWindowsManager::GetWindowPid(int32_t windowId, const std::vector<WindowInfo> &windowsInfo) const
{
    int32_t windowPid = INVALID_PID;
    for (const auto &item : windowsInfo) {
        if (item.id == windowId) {
            windowPid = item.pid;
            break;
        }
    }
    return windowPid;
}

void InputWindowsManager::CheckFocusWindowChange(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    const int32_t oldFocusWindowId = GetFocusWindowId(displayGroupInfo.groupId);
    const int32_t newFocusWindowId = displayGroupInfo.focusWindowId;
    if (oldFocusWindowId == newFocusWindowId) {
        return;
    }
    const int32_t oldFocusWindowPid = GetWindowPid(oldFocusWindowId);
    const int32_t newFocusWindowPid = GetWindowPid(newFocusWindowId, displayGroupInfo.windowsInfo);
    DfxHisysevent::OnFocusWindowChanged(oldFocusWindowId, newFocusWindowId, oldFocusWindowPid, newFocusWindowPid);
}

void InputWindowsManager::CheckZorderWindowChange(const std::vector<WindowInfo> &oldWindowsInfo,
    const std::vector<WindowInfo> &newWindowsInfo)
{
    int32_t oldZorderFirstWindowId = -1;
    int32_t newZorderFirstWindowId = -1;
    if (!oldWindowsInfo.empty()) {
        oldZorderFirstWindowId = oldWindowsInfo[0].id;
    }
    if (!newWindowsInfo.empty()) {
        newZorderFirstWindowId = newWindowsInfo[0].id;
    }
    if (oldZorderFirstWindowId == newZorderFirstWindowId) {
        return;
    }
    const int32_t oldZorderFirstWindowPid = GetWindowPid(oldZorderFirstWindowId);
    const int32_t newZorderFirstWindowPid = GetWindowPid(newZorderFirstWindowId, newWindowsInfo);
    DfxHisysevent::OnZorderWindowChanged(oldZorderFirstWindowId, newZorderFirstWindowId,
        oldZorderFirstWindowPid, newZorderFirstWindowPid);
}

void InputWindowsManager::UpdateDisplayIdAndName()
{
    CALL_DEBUG_ENTER;
    using IdNames = std::set<std::pair<uint64_t, std::string>>;
    IdNames newInfo;
    auto &DisplaysInfo = GetAllUsersDisplays();
    for (const auto &item : DisplaysInfo) {
        newInfo.insert(std::make_pair(item.rsId, item.uniq));
    }
    auto oldInfo = bindInfo_.GetDisplayIdNames();
    if (newInfo == oldInfo) {
        return;
    }
    for (auto it = oldInfo.begin(); it != oldInfo.end();) {
        if (newInfo.find(*it) == newInfo.end()) {
            bindInfo_.RemoveDisplay(it->first);
            oldInfo.erase(it++);
        } else {
            ++it;
        }
    }
    for (const auto &item : newInfo) {
        if (item.first >= HICAR_MIN_DISPLAY_ID) {
            MMI_HILOGI("Displayinfo id:%{public}" PRIu64 ", name:%{public}s", item.first, item.second.c_str());
            continue;
        }
        if (!bindInfo_.IsDisplayAdd(item.first, item.second)) {
            bindInfo_.AddDisplay(item.first, item.second);
        }
    }
}

int32_t InputWindowsManager::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    CALL_DEBUG_ENTER;
    return bindInfo_.GetDisplayBindInfo(infos);
}

int32_t InputWindowsManager::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    CALL_DEBUG_ENTER;
    return bindInfo_.SetDisplayBind(deviceId, displayId, msg);
}

void InputWindowsManager::UpdateCaptureMode(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    auto &WindowInfo = GetWindowInfoVector(displayGroupInfo.groupId);
    int32_t focusWindowId = GetFocusWindowId(displayGroupInfo.groupId);
    if (displayGroupInfo.windowsInfo.empty()) {
        MMI_HILOGW("windowsInfo is empty");
        return;
    }
    if (WindowInfo.empty()) {
        MMI_HILOGW("windowsInfo is empty");
        return;
    }
    CaptureModeInfo captureModeInfo;
    auto itr = captureModeInfoMap_.find(displayGroupInfo.groupId);
    if (itr != captureModeInfoMap_.end()) {
        captureModeInfo = itr->second;
    }
    if (captureModeInfo.isCaptureMode && !WindowInfo.empty() &&
        ((focusWindowId != displayGroupInfo.focusWindowId) ||
        (WindowInfo[0].id != displayGroupInfo.windowsInfo[0].id))) {
        captureModeInfoMap_[displayGroupInfo.groupId].isCaptureMode = false;
    }
}

bool InputWindowsManager::IsFocusedSession(int32_t session) const
{
    if (session >= 0) {
        for (auto &curGroupInfo : displayGroupInfoMap_) {
            if (session == GetWindowPid(curGroupInfo.second.focusWindowId)) {
                return true;
            }
        }
    }
    return false;
}

void InputWindowsManager::UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo)
{
    CALL_DEBUG_ENTER;
    PrintWindowGroupInfo(windowGroupInfo);
    std::map<int32_t, std::vector<WindowInfo>> groupWindows;
    for (const auto &item : windowGroupInfo.windowsInfo) {
        groupWindows[item.groupId].emplace_back(item);
    }
    WindowGroupInfo windowGroupInfoTmp;
    windowGroupInfoTmp.focusWindowId = windowGroupInfo.focusWindowId;
    windowGroupInfoTmp.displayId = windowGroupInfo.displayId;
    int32_t focusWid = 0;
    for (const auto &it : groupWindows) {
        if (it.first != MAIN_GROUPID) {
            focusWid = GetFocusWindowId(it.first);
            windowGroupInfoTmp.focusWindowId = focusWid;
        }
        windowGroupInfoTmp.windowsInfo = it.second;
#ifdef OHOS_BUILD_ENABLE_ANCO
        if (windowGroupInfoTmp.windowsInfo.size() == SHELL_WINDOW_COUNT
            && IsAncoWindow(windowGroupInfoTmp.windowsInfo[0])) {
            return UpdateShellWindow(windowGroupInfoTmp.windowsInfo[0]);
        }
#endif // OHOS_BUILD_ENABLE_ANCO
        OLD::DisplayGroupInfo displayGroupInfo;
        const auto &iter = displayGroupInfoMapTmp_.find(it.first);
        displayGroupInfo = (iter != displayGroupInfoMapTmp_.end()) ? iter->second : GetDefaultDisplayGroupInfo();
        if (it.first != MAIN_GROUPID) {
            displayGroupInfo.focusWindowId = focusWid;
        }
        for (const auto &item : windowGroupInfoTmp.windowsInfo) {
            UpdateDisplayInfoByIncrementalInfo(item, displayGroupInfo);
        }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
        bool pointDrawFlag = NeedUpdatePointDrawFlag(windowGroupInfoTmp.windowsInfo);
        pointerDrawFlagMap_[displayGroupInfo.groupId] = pointDrawFlag;

#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_ANCO
        UpdateWindowInfoExt(windowGroupInfoTmp, displayGroupInfo);
#endif // OHOS_BUILD_ENABLE_ANCO
        UpdateDisplayInfoExtIfNeed(displayGroupInfo, false);
    }
}

void InputWindowsManager::UpdateDisplayInfoExtIfNeed(OLD::DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt)
{
    UpdateDisplayInfo(displayGroupInfo);
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (needUpdateDisplayExt) {
        UpdateDisplayInfoExt(displayGroupInfo);
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGE("displaysInfo is empty");
        return;
    }
    if (displayGroupInfo.groupId != DEFAULT_GROUP_ID) {
        MMI_HILOGD("groupId:%{public}d", displayGroupInfo.groupId);
        return;
    }
    auto physicDisplayInfo = GetPhysicalDisplay(displayGroupInfo.displaysInfo[0].id);
    CHKPV(physicDisplayInfo);
#ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
    TOUCH_DRAWING_MGR->UpdateDisplayInfo(*physicDisplayInfo);
    TOUCH_DRAWING_MGR->RotationScreen();
#endif // #ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
}

void InputWindowsManager::UpdateDisplayInfoByIncrementalInfo(const WindowInfo &window,
    OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    switch (window.action) {
        case WINDOW_UPDATE_ACTION::ADD:
        case WINDOW_UPDATE_ACTION::ADD_END: {
            auto id = window.id;
            auto pos = std::find_if(std::begin(displayGroupInfo.windowsInfo), std::end(displayGroupInfo.windowsInfo),
                [id](const auto& item) { return item.id == id; });
            if (pos == std::end(displayGroupInfo.windowsInfo)) {
                displayGroupInfo.windowsInfo.emplace_back(window);
            } else {
                *pos = window;
            }
            break;
        }
        case WINDOW_UPDATE_ACTION::DEL: {
            auto oldWindow = displayGroupInfo.windowsInfo.begin();
            while (oldWindow != displayGroupInfo.windowsInfo.end()) {
                if (oldWindow->id == window.id) {
                    oldWindow = displayGroupInfo.windowsInfo.erase(oldWindow);
                } else {
                    oldWindow++;
                }
            }
            break;
        }
        case WINDOW_UPDATE_ACTION::CHANGE: {
            auto id = window.id;
            auto pos = std::find_if(std::begin(displayGroupInfo.windowsInfo), std::end(displayGroupInfo.windowsInfo),
                [id](const auto& item) { return item.id == id; });
            if (pos != std::end(displayGroupInfo.windowsInfo)) {
                *pos = window;
            }
            break;
        }
        default: {
            MMI_HILOGI("WINDOW_UPDATE_ACTION is action:%{public}d", window.action);
            break;
        }
    }
}

void InputWindowsManager::UpdateWindowsInfoPerDisplay(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay;
    int32_t groupId = displayGroupInfo.groupId;
    for (const auto &window : displayGroupInfo.windowsInfo) {
        auto it = windowsPerDisplay.find(window.displayId);
        if (it == windowsPerDisplay.end()) {
            windowsPerDisplay[window.displayId] = WindowGroupInfo {-1, window.displayId, {window}};
        } else {
            it->second.windowsInfo.emplace_back(window);
        }
        if (displayGroupInfo.focusWindowId == window.id) {
            windowsPerDisplay[window.displayId].focusWindowId = window.id;
        }
    }
    for (auto iter : windowsPerDisplay) {
        std::sort(iter.second.windowsInfo.begin(), iter.second.windowsInfo.end(),
            [](const WindowInfo &lwindow, const WindowInfo &rwindow) -> bool {
            return lwindow.zOrder > rwindow.zOrder;
        });
    }
    std::map<int32_t, WindowGroupInfo>& windowsPerDisplayTmp = windowsPerDisplay_;

    const auto& iter = windowsPerDisplayMap_.find(groupId);
    windowsPerDisplayTmp = (iter != windowsPerDisplayMap_.end()) ? iter->second : windowsPerDisplay_;
    for (const auto &item : windowsPerDisplay) {
        int32_t displayId = item.first;
        if (windowsPerDisplayTmp.find(displayId) != windowsPerDisplayTmp.end()) {
            CheckZorderWindowChange(windowsPerDisplayTmp[displayId].windowsInfo, item.second.windowsInfo);
        }
    }

    windowsPerDisplayMap_[groupId] = windowsPerDisplay;
    windowsPerDisplay_ = windowsPerDisplay;
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    for (const auto &window : displayGroupInfo.windowsInfo) {
        if (window.windowType == static_cast<int32_t>(Rosen::WindowType::WINDOW_TYPE_TRANSPARENT_VIEW)) {
            MMI_HILOGI("Transparent window of UNI-CUBIC emerges, redirect touches");
            if (auto touchGestureMgr = touchGestureMgr_.lock(); touchGestureMgr != nullptr) {
                touchGestureMgr->HandleGestureWindowEmerged(window.id, lastPointerEventforGesture_);
            }
            break;
        }
    }
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
}

WINDOW_UPDATE_ACTION InputWindowsManager::UpdateWindowInfo(OLD::DisplayGroupInfo &displayGroupInfo)
{
    auto action = WINDOW_UPDATE_ACTION::ADD_END;
    if (!displayGroupInfo.windowsInfo.empty()) {
        action = displayGroupInfo.windowsInfo.back().action;
    }
    MMI_HILOGD("Current action is:%{public}d", action);
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    pointerDrawFlagMap_[displayGroupInfo.groupId] = NeedUpdatePointDrawFlag(displayGroupInfo.windowsInfo);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    std::sort(displayGroupInfo.windowsInfo.begin(), displayGroupInfo.windowsInfo.end(),
        [](const WindowInfo &lwindow, const WindowInfo &rwindow) -> bool {
        return lwindow.zOrder > rwindow.zOrder;
    });
    if (GetHardCursorEnabled()) {
        for (auto &windowInfo : displayGroupInfo.windowsInfo) {
            if (windowInfo.isDisplayCoord) {
                continue;
            }
            auto displayInfo = GetPhysicalDisplay(windowInfo.displayId, displayGroupInfo);
            CHKPR(displayInfo, action);
            ChangeWindowArea(displayInfo->x, displayInfo->y, windowInfo);
            if (!windowInfo.uiExtentionWindowInfo.empty()) {
                for (auto &item : windowInfo.uiExtentionWindowInfo) {
                    ChangeWindowArea(displayInfo->x, displayInfo->y, item);
                }
            }
            windowInfo.isDisplayCoord = true;
        }
    }
    return action;
}

void InputWindowsManager::ChangeWindowArea(int32_t x, int32_t y, WindowInfo &windowInfo)
{
    windowInfo.area.x += x;
    windowInfo.area.y += y;
    for (auto &area : windowInfo.defaultHotAreas) {
        area.x += x;
        area.y += y;
    }
    for (auto &area : windowInfo.pointerHotAreas) {
        area.x += x;
        area.y += y;
    }
}

int32_t InputWindowsManager::GetMainScreenDisplayInfo(const std::vector<OLD::DisplayInfo> &displaysInfo,
    OLD::DisplayInfo &mainScreenDisplayInfo) const
{
    CALL_DEBUG_ENTER;
    if (displaysInfo.empty()) {
        MMI_HILOGE("displaysInfo doesn't contain displayInfo");
        return RET_ERR;
    }
    for (const OLD::DisplayInfo& display : displaysInfo) {
        if (display.displaySourceMode == OHOS::MMI::DisplaySourceMode::SCREEN_MAIN) {
            mainScreenDisplayInfo = display;
            return RET_OK;
        }
    }
    MMI_HILOGD("displayGroupInfo has no main screen, get displayGroupInfo.displaysInfo[0] back");
    mainScreenDisplayInfo = displaysInfo[0];
    return RET_OK;
}

void InputWindowsManager::SendBackCenterPointerEevent(const CursorPosition &cursorPos)
{
    CALL_DEBUG_ENTER;
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    int32_t lastPointerAction = lastPointerEventCopy->GetPointerAction();
    std::shared_ptr<PointerEvent> pointerBackCenterEvent = std::make_shared<PointerEvent>(*lastPointerEventCopy);
    pointerBackCenterEvent->SetTargetDisplayId(cursorPos.displayId);
    int32_t mainDisplayInfoX = GetLogicalPositionX(cursorPos.displayId);
    int32_t mainDisplayInfoY = GetLogicalPositionY(cursorPos.displayId);
    int32_t logicalX = cursorPos.cursorPos.x + mainDisplayInfoX;
    int32_t logicalY = cursorPos.cursorPos.y + mainDisplayInfoY;
    auto touchWindow = SelectWindowInfo(logicalX, logicalY, pointerBackCenterEvent);
    if (touchWindow == std::nullopt) {
        MMI_HILOGD("Maybe just down left mouse button, the mouse did not on the window");
        return;
    }
    int32_t pointerId = pointerBackCenterEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerBackCenterEvent->GetPointerItem(pointerId, item);
    item.SetDisplayX(cursorPos.cursorPos.x);
    item.SetDisplayY(cursorPos.cursorPos.y);
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({cursorPos.cursorPos.x, cursorPos.cursorPos.y},
        cursorPos.displayId);
    item.SetGlobalX(globalCoords.x);
    item.SetGlobalY(globalCoords.y);
    item.SetDisplayXPos(cursorPos.cursorPos.x);
    item.SetDisplayYPos(cursorPos.cursorPos.y);
    item.SetCanceled(true);
    pointerBackCenterEvent->UpdatePointerItem(pointerId, item);
    pointerBackCenterEvent->SetTargetWindowId(touchWindow->id);
    pointerBackCenterEvent->SetAgentWindowId(touchWindow->id);
    UpdateWindowInfoFlag(touchWindow->flags, pointerBackCenterEvent);
    if (lastPointerAction == PointerEvent::POINTER_ACTION_MOVE) {
        pointerBackCenterEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    } else if (lastPointerAction == PointerEvent::POINTER_ACTION_PULL_MOVE) {
        pointerBackCenterEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_CANCEL);
    }
    MMI_HILOGD("pointerBackCenterEvent status: %{private}s", pointerBackCenterEvent->ToString().c_str());
    auto filter = InputHandler->GetFilterHandler();
    CHKPV(filter);
    filter->HandlePointerEvent(pointerBackCenterEvent);
}

CursorPosition InputWindowsManager::ResetCursorPos(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    int32_t groupId = displayGroupInfo.groupId;
    if (!displayGroupInfo.displaysInfo.empty()) {
        OLD::DisplayInfo displayInfo = displayGroupInfo.displaysInfo[0];
        int32_t x = displayInfo.validWidth * HALF_RATIO;
        int32_t y = displayInfo.validHeight * HALF_RATIO;
        if (GetHardCursorEnabled()) {
            (void)GetMainScreenDisplayInfo(displayGroupInfo.displaysInfo, displayInfo);
            x = displayInfo.validWidth * HALF_RATIO;
            y = displayInfo.validHeight * HALF_RATIO;
            Direction direction = GetDisplayDirection(&displayInfo);
            if (direction == DIRECTION90 || direction == DIRECTION270) {
                std::swap(x, y);
            }
        }
        cursorPosMap_[groupId].displayId = displayInfo.id;
        cursorPosMap_[groupId].cursorPos.x = x;
        cursorPosMap_[groupId].cursorPos.y = y;
    } else {
        cursorPosMap_[groupId].displayId = -1;
        cursorPosMap_[groupId].cursorPos.x = 0;
        cursorPosMap_[groupId].cursorPos.y = 0;
    }
    MMI_HILOGI("ResetCursorPos cursorPosMap_[groupId].displayId:%{public}d", cursorPosMap_[groupId].displayId);
    return cursorPosMap_[groupId];
}

GlobalCoords InputWindowsManager::DisplayCoords2GlobalCoords(const Coordinate2D &displayCoords, int32_t displayId)
{
    auto displayInfo = GetPhysicalDisplay(displayId);
    if (displayInfo == nullptr) {
        MMI_HILOGI("GetPhysicalDisplay failed");
        return { DBL_MAX, DBL_MAX };
    }
    GlobalCoords globalCoords {
        .x = displayInfo->x + displayCoords.x,
        .y = displayInfo->y + displayCoords.y
    };
    return globalCoords;
}

void InputWindowsManager::ResetPointerPosition(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    if (displayGroupInfo.displaysInfo.empty()) {
        return;
    }
    CursorPosition oldPtrPos = GetCursorPos();
    CursorPosition cursorPos;
    for (auto &currentDisplay : displayGroupInfo.displaysInfo) {
        if ((currentDisplay.displaySourceMode == OHOS::MMI::DisplaySourceMode::SCREEN_MAIN)) {
            auto displayInfo = GetPhysicalDisplay(oldPtrPos.displayId);
            CHKPV(displayInfo);
            MMI_HILOGI("CurDisplayId:%{public}" PRIu64 ", oldDisplayId:%{public}" PRIu64,
                currentDisplay.rsId, displayInfo->rsId);
            if ((displayInfo->rsId != currentDisplay.rsId) || (!IsPointerOnCenter(oldPtrPos, currentDisplay))) {
                cursorPos = ResetCursorPos(displayGroupInfo);
                UpdateAndAdjustMouseLocation(cursorPos.displayId, cursorPos.cursorPos.x, cursorPos.cursorPos.y);
            }
            break;
        }
    }

    auto lastPointerEventCopy = GetlastPointerEvent();
    if ((lastPointerEventCopy != nullptr) &&
        (!lastPointerEventCopy->IsButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT))) {
        MMI_HILOGD("Reset pointer position, left mouse button is not pressed");
        return;
    }
    (void)SendBackCenterPointerEevent(cursorPos);
}

bool InputWindowsManager::IsPointerOnCenter(const CursorPosition &currentPos, const OLD::DisplayInfo &currentDisplay)
{
    auto displayCenterX = currentDisplay.validWidth * HALF_RATIO;
    auto displayCenterY = currentDisplay.validHeight * HALF_RATIO;
    if ((currentPos.cursorPos.x == displayCenterX) &&
        (currentPos.cursorPos.y == displayCenterY)) {
        return true;
    }
    return false;
}

void InputWindowsManager::HandleValidDisplayChange(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    ResetPointerPositionIfOutValidDisplay(displayGroupInfo);
    CancelTouchScreenEventIfValidDisplayChange(displayGroupInfo);
}

CursorPosition InputWindowsManager::GetCursorPos(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CursorPosition cursorPosition;
    int32_t groupId = displayGroupInfo.groupId;
    const auto iter = cursorPosMap_.find(groupId);
    if (iter != cursorPosMap_.end()) {
        cursorPosition = iter->second;
        if ((cursorPosition.displayId < 0) && !displayGroupInfo.displaysInfo.empty()) {
            OLD::DisplayInfo displayInfo = displayGroupInfo.displaysInfo[0];
            if (GetHardCursorEnabled()) {
                (void)GetMainScreenDisplayInfo(displayGroupInfo.displaysInfo, displayInfo);
            }
            int32_t validW = displayInfo.validWidth;
            int32_t validH = displayInfo.validHeight;
            Direction direction = GetDisplayDirection(&displayInfo);
            if (direction == DIRECTION90 || direction == DIRECTION270) {
                std::swap(validW, validH);
            }
            cursorPosMap_[groupId].displayId = displayInfo.id;
            cursorPosMap_[groupId].cursorPos.x = validW * HALF_RATIO;
            cursorPosMap_[groupId].cursorPos.y = validH * HALF_RATIO;
            cursorPosMap_[groupId].direction = displayInfo.direction;
            cursorPosMap_[groupId].displayDirection = displayInfo.displayDirection;
            cursorPosition = cursorPosMap_[groupId];
        }
    }
    return cursorPosition;
}

void InputWindowsManager::ResetPointerPositionIfOutValidDisplay(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    if (displayGroupInfo.displaysInfo.empty()) {
        MMI_HILOGD("DisplayInfo empty");
        return;
    }
    CursorPosition cursorPos = GetCursorPos(displayGroupInfo);
    int32_t cursorDisplayId = cursorPos.displayId;
    int32_t groupId = displayGroupInfo.groupId;
    for (auto &currentDisplay : displayGroupInfo.displaysInfo) {
        if (cursorDisplayId == currentDisplay.id) {
            bool isOut = IsPositionOutValidDisplay(cursorPos.cursorPos, currentDisplay);
            bool isChange = IsValidDisplayChange(currentDisplay);
            MMI_HILOGD("CurDisplayId = %{public}d CurPos = {x:%{private}d, y:%{private}d}, isOut = %{public}d, "
                       "isChange = %{public}d",
                cursorDisplayId,
                static_cast<int32_t>(cursorPos.cursorPos.x),
                static_cast<int32_t>(cursorPos.cursorPos.y),
                static_cast<int32_t>(isOut),
                static_cast<int32_t>(isChange));
            int32_t validWidth = currentDisplay.validWidth;
            int32_t validHeight = currentDisplay.validHeight;
            bool pointerActiveRectValid = false;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
            MMI_HILOGD("Start checking vtp cursor active area");
            pointerActiveRectValid = IsPointerActiveRectValid(currentDisplay);
            if (pointerActiveRectValid) {
                validWidth = currentDisplay.pointerActiveWidth;
                validHeight = currentDisplay.pointerActiveHeight;
                MMI_HILOGD("vtp cursor active area w:%{private}d, h:%{private}d", validWidth, validHeight);
            }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
            if (isOut && (isChange || pointerActiveRectValid)) {
                double curX = validWidth * HALF_RATIO;
                double curY = validHeight * HALF_RATIO;
                UpdateAndAdjustMouseLocation(cursorDisplayId, curX, curY);

                int32_t displayId = -1;
                double cursorPosx = 0.0;
                double cursorPosy = 0.0;
                const auto iter = cursorPosMap_.find(groupId);
                if (iter != cursorPosMap_.end()) {
                    displayId = iter->second.displayId;
                    cursorPosx = iter->second.cursorPos.x;
                    cursorPosy = iter->second.cursorPos.y;
                }
                auto displayInfo = GetPhysicalDisplay(displayId);
                CHKPV(displayInfo);
                CursorDrawingComponent::GetInstance().SetPointerLocation(
                    static_cast<int32_t>(cursorPosx),
                    static_cast<int32_t>(cursorPosy), displayInfo->rsId);
            }
            if (isChange) {
                CancelMouseEvent();
            }
            return;
        }
    }
    MMI_HILOGE("Can't find displayInfo by displayId:%{public}d", cursorDisplayId);
}

bool InputWindowsManager::IsPositionOutValidDisplay(
    Coordinate2D &position, const OLD::DisplayInfo &currentDisplay, bool isPhysicalPos, bool hasValidAreaDowned)
{
    double posX = position.x;
    double posY = position.y;
    double posWidth = currentDisplay.width;
    double posHeight = currentDisplay.height;
    double rotateX = posX;
    double rotateY = posY;
    double validW = currentDisplay.validWidth;
    double validH = currentDisplay.validHeight;
    double offsetX = 0;
    double offsetY = 0;

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    MMI_HILOGD("Start checking vtp cursor active area");
    if (IsPointerActiveRectValid(currentDisplay) && !isPhysicalPos) {
        validW = currentDisplay.pointerActiveWidth;
        validH = currentDisplay.pointerActiveHeight;
        MMI_HILOGD("vtp cursor active area w:%{private}f, h:%{private}f", validW, validH);
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    if (isPhysicalPos) {
        Direction displayDirection = static_cast<Direction>((
        ((currentDisplay.direction - currentDisplay.fixedDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        if (displayDirection == DIRECTION90 || displayDirection == DIRECTION270) {
            std::swap(validW, validH);
            std::swap(posWidth, posHeight);
        }
        if (currentDisplay.fixedDirection == DIRECTION0) {
            rotateX = posX;
            rotateY = posY;
        } else if (currentDisplay.fixedDirection == DIRECTION90) {
            rotateX = posWidth - posY;
            rotateY = posX;
        } else if (currentDisplay.fixedDirection == DIRECTION180) {
            rotateX = posWidth - posX;
            rotateY = posHeight - posY;
        } else if (currentDisplay.fixedDirection == DIRECTION270) {
            rotateX = posY;
            rotateY = posHeight - posX;
        } else {
            MMI_HILOGD("Invalid fixedDirection:%{public}d", currentDisplay.fixedDirection);
        }
        offsetX = currentDisplay.offsetX;
        offsetY = currentDisplay.offsetY;
    }
    bool isOut = (rotateX < offsetX) || (rotateX > offsetX + validW) ||
                 (rotateY < offsetY) || (rotateY > offsetY + validH);
#ifdef OHOS_BUILD_EXTERNAL_SCREEN
    if (hasValidAreaDowned) {
        isOut = false;
    }
#endif // OHOS_BUILD_EXTERNAL_SCREEN
    PrintDisplayInfo(currentDisplay);
    MMI_HILOGD("isOut=%{public}d,isPhysicalPos=%{public}d Position={%{private}f %{private}f}"
               "->{%{private}f %{private}f} RealValidWH={w:%{private}f h:%{private}f}",
        static_cast<int32_t>(isOut),
        static_cast<int32_t>(isPhysicalPos),
        posX,
        posY,
        rotateX,
        rotateY,
        validW,
        validH);

    if (!isOut && isPhysicalPos) {
        double rotateX1 = rotateX - currentDisplay.offsetX;
        double rotateY1 = rotateY - currentDisplay.offsetY;

        if (currentDisplay.fixedDirection == DIRECTION0) {
            position.x = rotateX1;
            position.y = rotateY1;
        } else if (currentDisplay.fixedDirection == DIRECTION90) {
            position.x = rotateY1;
            position.y = posWidth - rotateX1;
        } else if (currentDisplay.fixedDirection == DIRECTION180) {
            position.x = posWidth - rotateX1;
            position.y = posHeight - rotateY1;
        } else if (currentDisplay.fixedDirection == DIRECTION270) {
            position.x = posHeight - rotateY1;
            position.y = rotateX1;
        } else {
            MMI_HILOGD("Invalid fixedDirection:%{public}d", currentDisplay.fixedDirection);
        }
        MMI_HILOGD("rerotate={%{private}f %{private}f}->{%{private}f %{private}f} RealValidWH = "
                   "{w:%{private}f h:%{private}f} RealWH{w:%{private}f h:%{private}f}",
            rotateX1,
            rotateY1,
            position.x,
            position.y,
            validW,
            validH,
            posWidth,
            posHeight);
    }

    return isOut;
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
bool InputWindowsManager::IsPointerActiveRectValid(const OLD::DisplayInfo &currentDisplay)
{
    return currentDisplay.pointerActiveWidth > 0 && currentDisplay.pointerActiveHeight > 0;
}

bool InputWindowsManager::IsPointInsideWindowArea(int x, int y, const WindowInfo& windowItem) const {
    return (x >= windowItem.area.x && x <= (windowItem.area.x + windowItem.area.width)) &&
            (y >= windowItem.area.y && y <= (windowItem.area.y + windowItem.area.height));
}

bool InputWindowsManager::IsPointInsideSpecialWindow(double pointX, double pointY)
{
    auto &WindowsInfo = GetWindowInfoVector();
    for (const auto& windowItem : WindowsInfo) {
        int32_t x = static_cast<int32_t>(pointX);
        int32_t y = static_cast<int32_t>(pointY);
        if (windowItem.windowType == GUIDE_WINDOW_TYPE && !windowItem.defaultHotAreas.empty()) {
            const auto &win = windowItem.defaultHotAreas[0];
            return (x >= win.x && x <= (win.x + win.width)) &&
                (y >= win.y && y <= (win.y + win.height));
        }
        if (windowItem.windowNameType == WINDOW_NAME_TYPE_VOICEINPUT) {
            return IsPointInsideWindowArea(x, y, windowItem);
        }
    }
    return false;
}

bool InputWindowsManager::IsMouseInCastWindow()
{
    auto &WindowsInfo = GetWindowInfoVector();
    for (const auto& windowItem : WindowsInfo) {
        if (windowItem.windowType == CAST_WINDOW_TYPE) {
            const auto &mouseInfo = GetMouseInfo();
            int32_t x = mouseInfo.physicalX;
            int32_t y = mouseInfo.physicalY;
            return IsPointInsideWindowArea(x, y, windowItem);
        }
    }

    return false;
}

bool InputWindowsManager::IsCaptureMode()
{
    auto &WindowsInfo = GetWindowInfoVector();
    for (const auto& window : WindowsInfo) {
        if (window.windowNameType == WINDOW_NAME_TYPE_SCREENSHOT) {
            return false;
        }
        if (window.zOrder == SCREEN_CAPTURE_WINDOW_ZORDER) {
            return (window.area.width > SCREEN_RECORD_WINDOW_WIDTH ||
                    window.area.height > SCREEN_RECORD_WINDOW_HEIGHT);
        }
    }

    return false;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
bool InputWindowsManager::IsMouseDragging() const
{
    return (extraData_.appended && (extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE));
}

void InputWindowsManager::EnsureMouseEventCycle(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE) {
        return;
    }
    if (IsMouseDragging()) {
        return;
    }
    if (!event->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
        return;
    }
    if ((event->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) &&
        (mouseDownInfo_.id >= 0) &&
        (mouseDownInfo_.id != event->GetTargetWindowId())) {
        MMI_HILOGD("Target window shift from %{private}d to %{private}d at button-up",
            mouseDownInfo_.id, event->GetTargetWindowId());
        event->SetTargetDisplayId(mouseDownInfo_.displayId);
        event->SetTargetWindowId(mouseDownInfo_.id);
        event->SetAgentWindowId(mouseDownInfo_.agentWindowId);
    }
}

void InputWindowsManager::CleanMouseEventCycle(std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    if (event->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE) {
        return;
    }
    if ((event->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) ||
        (event->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL)) {
        InitMouseDownInfo();
        MMI_HILOGD("Clear button-down record at button-up");
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER

void InputWindowsManager::CancelTouchScreenEventIfValidDisplayChange(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    if (lastPointerEventforGesture_ == nullptr) {
        MMI_HILOGD("lastPointerEventforGesture_ is null");
        return;
    }
    if (lastPointerEventforGesture_->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        MMI_HILOGD("source type:[%{public}d] is not touchscreen", lastPointerEventforGesture_->GetSourceType());
        return;
    }
    int32_t touchDisplayId = lastPointerEventforGesture_->GetTargetDisplayId();
    for (auto &currentDisplay : displayGroupInfo.displaysInfo) {
        MMI_HILOGD("touchDisplayId=%{public}d currentDisplay.id=%{public}d", touchDisplayId, currentDisplay.id);
        if (touchDisplayId == currentDisplay.id && IsValidDisplayChange(currentDisplay)) {
            CancelAllTouches(lastPointerEventforGesture_, true);
            return;
        }
    }
}

void InputWindowsManager::CancelMouseEvent()
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    if (lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL ||
        lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_CANCEL) {
        MMI_HILOGE("lastPointerEventCopy has canceled");
        return;
    }
    int32_t action = PointerEvent::POINTER_ACTION_CANCEL;
    if (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        action = PointerEvent::POINTER_ACTION_PULL_CANCEL;
    }
    if (lastPointerEventCopy->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE &&
        !lastPointerEventCopy->GetPressedButtons().empty()) {
        int32_t pointerId = lastPointerEventCopy->GetPointerId();
        int32_t originAction = lastPointerEventCopy->GetPointerAction();
        PointerEvent::PointerItem item;
        auto isItemExist = lastPointerEventCopy->GetPointerItem(pointerId, item);
        if (isItemExist) {
            item.SetCanceled(true);
            lastPointerEventCopy->UpdatePointerItem(pointerId, item);
        }
        MMI_HILOGI("Cancel mouse event for valid display change,pointerId:%{public}d action:%{public}d->%{public}d "
            "isItemExist=%{public}d",
            pointerId,
            originAction,
            action,
            static_cast<uint32_t>(isItemExist));
        auto lastPointerEvent = std::make_shared<PointerEvent>(*lastPointerEventCopy);
        lastPointerEvent->SetPointerAction(action);
        lastPointerEvent->SetOriginPointerAction(originAction);
        lastPointerEvent->SetPointerId(pointerId);
        auto filter = InputHandler->GetFilterHandler();
        CHKPV(filter);
        filter->HandlePointerEvent(lastPointerEvent);
        {
            std::lock_guard<std::mutex> guard(mtx_);
            lastPointerEvent_->SetPointerAction(action);
            lastPointerEvent_->DeleteReleaseButton(lastPointerEvent_->GetButtonId());
        }
    }
}

bool InputWindowsManager::IsValidDisplayChange(const OLD::DisplayInfo &displayInfo)
{
    int32_t touchDisplayId = displayInfo.id;
    int32_t groupId = FindDisplayGroupId(touchDisplayId);
    auto &DisplaysInfo = GetDisplayInfoVector(groupId);
    for (auto &currentDisplay : DisplaysInfo) {
        if (touchDisplayId == currentDisplay.id) {
            auto currentDirection = currentDisplay.direction;
            auto currentValidWH =
                RotateRect<int32_t>(currentDirection, {currentDisplay.validWidth, currentDisplay.validHeight});
            auto newDirection = displayInfo.direction;
            auto newValidWH = RotateRect<int32_t>(newDirection, {displayInfo.validWidth, displayInfo.validHeight});
            bool isChange =
                !(displayInfo.offsetX == currentDisplay.offsetX && displayInfo.offsetY == currentDisplay.offsetY &&
                    newValidWH.x == currentValidWH.x && newValidWH.y == currentValidWH.y);
            MMI_HILOGD("isChange=%{private}d CurDisplayId=%{private}d "
                       "oldDisplayInfo={{w:%{private}d h:%{private}d} validWH:{%{private}d %{private}d} "
                       "offsetXY:{%{private}d %{private}d} direction:{%{private}d %{private}d %{private}d}} "
                       "newDisplayInfo={{w:%{private}d h:%{private}d} validWH:{%{private}d %{private}d}} "
                       "offsetXY:{%{private}d %{private}d} direction:{%{private}d %{private}d %{private}d}}"
                       "useDirection:{old:%{private}d new:%{private}d}}",
                static_cast<int32_t>(isChange),
                touchDisplayId,
                currentDisplay.width,
                currentDisplay.height,
                currentDisplay.validWidth,
                currentDisplay.validHeight,
                currentDisplay.offsetX,
                currentDisplay.offsetY,
                currentDisplay.direction,
                currentDisplay.displayDirection,
                currentDisplay.fixedDirection,
                displayInfo.width,
                displayInfo.height,
                displayInfo.validWidth,
                displayInfo.validHeight,
                displayInfo.offsetX,
                displayInfo.offsetY,
                displayInfo.direction,
                displayInfo.displayDirection,
                displayInfo.fixedDirection,
                currentDirection,
                newDirection);
            return isChange;
        }
    }
    return false;
}

void InputWindowsManager::HandleWindowPositionChange(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    int32_t groupId = displayGroupInfo.groupId;
    PrintWindowNavbar(groupId);

    auto WindowInfo = GetWindowInfoVector(groupId);
    for (auto it = touchItemDownInfosMap_[groupId].begin(); it != touchItemDownInfosMap_[groupId].end(); ++it) {
        int32_t pointerId = it->first;
        int32_t windowId = it->second.window.id;
        auto iter = std::find_if(WindowInfo.begin(), WindowInfo.end(),
            [windowId](const auto& windowInfo) {
            return windowId == windowInfo.id && windowInfo.rectChangeBySystem;
        });
        if (iter != WindowInfo.end()) {
            MMI_HILOGI("Dispatch cancel event pointerId:%{public}d", pointerId);
            CHKPV(lastPointerEventforWindowChangeMap_[groupId]);
            PointerEvent::PointerItem pointerItem;
            if (!lastPointerEventforWindowChangeMap_[groupId]->GetPointerItem(pointerId, pointerItem)) {
                MMI_HILOGE("Can not find pointer item pointerid:%{public}d", pointerId);
                return;
            }
            auto tmpEvent = std::make_shared<PointerEvent>(*lastPointerEventforWindowChangeMap_[groupId]);
            tmpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            tmpEvent->SetPointerId(pointerId);
            auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
            CHKPV(inputEventNormalizeHandler);
            inputEventNormalizeHandler->HandleTouchEvent(tmpEvent);
            it->second.flag = true;
            iter->rectChangeBySystem = false;
        }
    }
}

void InputWindowsManager::SendCancelEventWhenWindowChange(int32_t pointerId, int32_t groupId)
{
    MMI_HILOGD("Dispatch cancel event pointerId:%{public}d", pointerId);
    std::shared_ptr<PointerEvent> lastPointerEventforWindowChangeTmp = lastPointerEventforWindowChange_;

    const auto iter = lastPointerEventforWindowChangeMap_.find(groupId);
    if (iter != lastPointerEventforWindowChangeMap_.end()) {
        lastPointerEventforWindowChangeTmp = iter->second;
    }
    CHKPV(lastPointerEventforWindowChangeTmp);
    PointerEvent::PointerItem pointerItem;
    if (!lastPointerEventforWindowChangeTmp->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can not find pointer item pointerid:%{public}d", pointerId);
        return;
    }
    auto tmpEvent = std::make_shared<PointerEvent>(*(lastPointerEventforWindowChangeTmp));
    tmpEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportPointerEventExitTimes(PointerEventStatistics::TRANSFORM_CANCEL);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    tmpEvent->SetPointerId(pointerId);
    auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPV(inputEventNormalizeHandler);
    inputEventNormalizeHandler->HandleTouchEvent(tmpEvent);
}

void InputWindowsManager::PrintWindowNavbar(int32_t groupId)
{
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (auto &item : WindowsInfo) {
        if (item.windowInputType == WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE ||
            item.windowInputType == WindowInputType::DUALTRIGGER_TOUCH) {
            std::string dump;
            dump += StringPrintf("%d|%d|%d|%d|%d|%zu(", item.id, item.area.x, item.area.y, item.area.width,
                item.area.height, item.defaultHotAreas.size());
            for (const auto &win : item.defaultHotAreas) {
                dump += StringPrintf(" %d|%d|%d|%d ", win.x, win.y, win.width, win.height);
            }
            dump += StringPrintf(")\n");
            for (auto it : item.transform) {
                dump += StringPrintf("%f,", it);
            }
            dump += StringPrintf("]\n");
            MMI_HILOGI("%{public}s", dump.c_str());
        }
    }
}

bool InputWindowsManager::JudgeCameraInFore()
{
    CALL_DEBUG_ENTER;
    int32_t focWid = GetFocusWindowId(MAIN_GROUPID);
    int mainDisplayId = GetMainDisplayId(MAIN_GROUPID);
    int32_t focPid = GetPidByDisplayIdAndWindowId(mainDisplayId, focWid);
    if (udsServer_ == nullptr) {
        MMI_HILOGW("The udsServer is nullptr");
        return false;
    }
    SessionPtr sess = udsServer_->GetSessionByPid(focPid);
    if (sess == nullptr) {
        MMI_HILOGW("The sess is nullptr");
        return false;
    }
    std::string programName = sess->GetProgramName();
    return programName.find(".camera") != std::string::npos;
}

void InputWindowsManager::InitDisplayGroupInfo(OLD::DisplayGroupInfo &displayGroupInfo)
{
    int32_t groupId = displayGroupInfo.groupId;
    if (displayGroupInfo.type == GroupType::GROUP_DEFAULT) {
        if (groupId != MAIN_GROUPID) {
            MMI_HILOGE("The groupId is incorrect, groupId:%{public}d", groupId);
            return;
        }
    }
    displayGroupInfoMap_[groupId] = displayGroupInfo;
}

void InputWindowsManager::UpdateDisplayInfo(OLD::DisplayGroupInfo &displayGroupInfo)
{
    InitDisplayGroupInfo(displayGroupInfo);
    if (!mainGroupExisted_ && displayGroupInfo.type == GroupType::GROUP_DEFAULT) {
        mainGroupExisted_ = true;
    }
    int32_t groupId = displayGroupInfo.groupId;
    bool bFlag = false;
#ifdef OHOS_BUILD_ENABLE_ANCO
    bFlag = displayGroupInfo.type == GroupType::GROUP_DEFAULT && !displayGroupInfo.displaysInfo.empty();
    if (bFlag) {
        const auto &displayInfo = displayGroupInfo.displaysInfo.front();
        std::lock_guard<std::mutex> lock(oneHandMtx_);
        if (scalePercent_ != displayInfo.scalePercent) {
            MMI_HILOGD("Send one hand data to anco, scalePercent:%{public}d", displayInfo.scalePercent);
            UpdateOneHandDataExt(displayInfo);
            scalePercent_ = displayInfo.scalePercent;
        }
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    MMI_HILOGD("Displays Info size:%{public}zu, focusWindowId:%{public}d",
        displayGroupInfo.displaysInfo.size(), displayGroupInfo.focusWindowId);
    auto action = UpdateWindowInfo(displayGroupInfo);
    CheckFocusWindowChange(displayGroupInfo);
    UpdateCaptureMode(displayGroupInfo);
    bool isDisplayChanged = false;
    if (GetHardCursorEnabled()) {
        isDisplayChanged = OnDisplayRemovedOrCombinationChanged(displayGroupInfo);
    }
    OLD::DisplayGroupInfo displayGroupInfoTemp;
    if (displayGroupInfo.userState == UserState::USER_ACTIVE) {
        displayGroupInfoMapTmp_[displayGroupInfo.groupId] = displayGroupInfo;
    }
    bFlag = (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled() || action == WINDOW_UPDATE_ACTION::ADD_END)
        && (displayGroupInfo.userState == UserState::USER_ACTIVE);
    if (bFlag) {
        if (GetHardCursorEnabled()) {
            bool isDisplayUpdate = OnDisplayRemovedOrCombinationChanged(displayGroupInfo);
            if (isDisplayUpdate) {
                ResetPointerPosition(displayGroupInfo);
            }
        }
        PrintChangedWindowBySync(displayGroupInfo);
        CleanInvalidPiexMap(groupId);
        HandleValidDisplayChange(displayGroupInfo);
        displayGroupInfoMap_[groupId] = displayGroupInfo;
        displayGroupInfo_ = displayGroupInfo;
        UpdateWindowsInfoPerDisplay(displayGroupInfo);
        HandleWindowPositionChange(displayGroupInfo);
        const auto iter = displayGroupInfoMap_.find(groupId);
        if (iter != displayGroupInfoMap_.end()) {
            displayGroupInfoTemp = iter->second;
        }
    }
    PrintDisplayGroupInfo(displayGroupInfoTemp);
    if (!displayGroupInfoTemp.displaysInfo.empty()) {
        UpdateDisplayIdAndName();
    }
    UpdateDisplayMode(displayGroupInfo.groupId);
#ifdef OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() &&
       (INPUT_DEV_MGR->HasPointerDevice() || INPUT_DEV_MGR->HasVirtualPointerDevice())) {
#else
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
        UpdatePointerChangeAreas(displayGroupInfo);
    }
    InitPointerStyle(displayGroupInfo.groupId);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING

    const auto iter = pointerDrawFlagMap_.find(groupId);
    bFlag = (iter != pointerDrawFlagMap_.end()) ? true : false;
    if (!displayGroupInfo.displaysInfo.empty() && bFlag) {
        AdjustDisplayRotation(groupId);
        if (GetHardCursorEnabled()) {
            PointerDrawingManagerOnDisplayInfo(displayGroupInfo, isDisplayChanged);
        } else {
            PointerDrawingManagerOnDisplayInfo(displayGroupInfo);
        }
    }

    lastDpiMap_[groupId] = displayGroupInfoTemp.displaysInfo.empty() ? DEFAULT_DPI :
    displayGroupInfoTemp.displaysInfo[0].dpi;
    if (INPUT_DEV_MGR->HasPointerDevice() && bFlag) {
        NotifyPointerToWindow(groupId);
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif // OHOS_BUILD_ENABLE_POINTER
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
void InputWindowsManager::AdjustDisplayRotation(int32_t groupId)
{
    CursorPosition cursorPosCur;

    const auto iter = cursorPosMap_.find(groupId);
    if (iter == cursorPosMap_.end()) {
        cursorPosMap_[groupId]  = cursorPosCur;
    }
    PhysicalCoordinate coord {
        .x = cursorPosCur.cursorPos.x,
        .y = cursorPosCur.cursorPos.y,
    };
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(cursorPosCur.displayId);
    CHKPV(displayInfo);
    if (cursorPosCur.displayDirection != displayInfo->displayDirection ||
        cursorPosCur.direction != displayInfo->direction) {
        MMI_HILOGI("displayId:%{public}d, cursorPosX:%{private}.2f, cursorPosY:%{private}.2f, direction:%{public}d, "
            "physicalDisplay id:%{public}d, x:%{private}d, y:%{private}d, width:%{public}d, height:%{public}d, "
            "dpi:%{public}d, name:%{public}s, uniq:%{public}s, direction:%{public}d, displayDirection:%{public}d",
            cursorPosCur.displayId, cursorPosCur.cursorPos.x,
            cursorPosCur.cursorPos.y, cursorPosCur.direction,
            displayInfo->id, displayInfo->x, displayInfo->y, displayInfo->width, displayInfo->height,
            displayInfo->dpi, displayInfo->name.c_str(), displayInfo->uniq.c_str(), displayInfo->direction,
            displayInfo->displayDirection);
        if (!GetHardCursorEnabled() && cursorPosCur.displayDirection != displayInfo->displayDirection) {
            ScreenRotateAdjustDisplayXY(*displayInfo, coord);
        }

        const auto iter = cursorPosMap_.find(groupId);
        if (iter != cursorPosMap_.end()) {
            cursorPosMap_[groupId].direction = displayInfo->direction;
            cursorPosMap_[groupId].displayDirection = displayInfo->displayDirection;
        }
        UpdateAndAdjustMouseLocation(cursorPosCur.displayId, coord.x, coord.y);
        if (GetHardCursorEnabled() && extraData_.appended &&
            (extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE)) {
            AdjustDragPosition(groupId);
        }
        CursorDrawingComponent::GetInstance().UpdateDisplayInfo(*displayInfo);
        int32_t displayId = -1;

        if (iter != cursorPosMap_.end()) {
            displayId = iter->second.displayId;
        }
        auto displayInfoTmp = GetPhysicalDisplay(displayId);
        CHKPV(displayInfoTmp);
        CursorDrawingComponent::GetInstance().SetPointerLocation(
            static_cast<int32_t>(coord.x), static_cast<int32_t>(coord.y), displayInfoTmp->rsId);
    }
}

void InputWindowsManager::AdjustDragPosition(int32_t groupId)
{
    auto lastPointerEvent = GetlastPointerEvent();
    CHKPV(lastPointerEvent);
    int32_t displayId = -1;
    int32_t physicalX = 0;
    int32_t physicalY = 0;

    auto iter = mouseLocationMap_.find(groupId);
    if (iter != mouseLocationMap_.end()) {
        displayId = iter->second.displayId;
        physicalX = iter->second.physicalX;
        physicalY = iter->second.physicalY;
    }
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(*lastPointerEvent);
    pointerEvent->SetTargetDisplayId(displayId);
    auto touchWindow = SelectWindowInfo(physicalX, physicalY, pointerEvent);
    if (touchWindow == std::nullopt) {
        MMI_HILOGE("SelectWindowInfo failed");
        return;
    }
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(pointerId, item);
    item.SetDisplayX(physicalX);
    item.SetDisplayY(physicalY);
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({physicalX, physicalY}, displayId);
    item.SetGlobalX(globalCoords.x);
    item.SetGlobalY(globalCoords.y);
    item.SetDisplayXPos(physicalX);
    item.SetDisplayYPos(physicalY);
    pointerEvent->UpdatePointerItem(pointerId, item);
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->id);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    auto now = GetSysClockTime();
    pointerEvent->SetActionTime(now);
    pointerEvent->UpdateId();
    auto filterHandler = InputHandler->GetFilterHandler();
    CHKPV(filterHandler);
    filterHandler->HandlePointerEvent(pointerEvent);
    MMI_HILOGI("pointerEvent: %{private}s", pointerEvent->ToString().c_str());
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

DisplayMode InputWindowsManager::GetDisplayMode() const
{
    const auto iter = displayModeMap_.find(MAIN_GROUPID);
    if (iter != displayModeMap_.end()) {
        return iter->second;
    }
    return displayMode_;
}

void InputWindowsManager::UpdateDisplayMode(int32_t groupId)
{
    CALL_DEBUG_ENTER;
    DisplayMode mode;
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        if (iter->second.displaysInfo.empty()) {
            MMI_HILOGE("DisplaysInfo is empty");
            return;
        }
        mode = iter->second.displaysInfo[0].displayMode;
    } else {
        if (displayGroupInfo_.displaysInfo.empty()) {
            MMI_HILOGE("DisplaysInfo is empty");
            return;
        }
        mode = displayGroupInfo_.displaysInfo[0].displayMode;
    }
    const auto tempMode = displayModeMap_.find(groupId);
    if (tempMode == displayModeMap_.end()) {
        return;
    }
    DisplayMode& displayMode = tempMode->second;
    if (mode == displayMode) {
        MMI_HILOGD("Displaymode not change, mode:%{public}d, diaplayMode_:%{public}d", mode, displayMode);
        return;
    }
    displayMode_ = mode;
    displayModeMap_[groupId] = mode;
    displayMode = mode;
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_ == nullptr) {
        MMI_HILOGD("Send fingersense display mode is nullptr");
        return;
    }
    MMI_HILOGI("Update fingersense display mode, displayMode:%{public}d", displayMode);
    BytraceAdapter::StartUpdateDisplayMode("display mode change");
    FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_(static_cast<int32_t>(displayMode));
    BytraceAdapter::StopUpdateDisplayMode();
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
void InputWindowsManager::DrawPointer(bool isDisplayRemoved)
{
    if (DISPLAY_MONITOR->GetScreenStatus() != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        if (!isDisplayRemoved) {
            CursorDrawingComponent::GetInstance().DrawPointerStyle(dragPointerStyle_);
        } else {
            CursorDrawingComponent::GetInstance().DrawScreenCenterPointer(dragPointerStyle_);
        }
    }
}

void InputWindowsManager::PointerDrawingManagerOnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo,
    bool isDisplayRemoved)
{
    auto currentDisplayInfo = CursorDrawingComponent::GetInstance().GetCurrentDisplayInfo();
    CursorDrawingComponent::GetInstance().OnDisplayInfo(displayGroupInfo);
    int32_t groupId = displayGroupInfo.groupId;
    int32_t newId = 0;
    int32_t &lastDpiTmp = lastDpi_;

    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        if (iter->second.displaysInfo.empty()) {
            MMI_HILOGE("DisplayGroup is empty.");
            return;
        }
        newId = iter->second.displaysInfo[0].id;
    } else {
        if (displayGroupInfo_.displaysInfo.empty()) {
            MMI_HILOGE("DisplayGroup is empty.");
            return;
        }
        newId = displayGroupInfo_.displaysInfo[0].id;
    }
    if (lastDpiMap_.find(groupId) == lastDpiMap_.end()) {
        lastDpiMap_[groupId]  = lastDpiTmp;
    }
    for (auto displayInfo : displayGroupInfo.displaysInfo) {
        if (displayInfo.rsId == currentDisplayInfo.rsId && displayInfo.dpi != currentDisplayInfo.dpi) {
            MMI_HILOGD("dpi changed, current rsId: %{public}" PRIu64 ", dpi: %{public}d, "
            "latest rsId: %{public}" PRIu64 ", dpi: %{public}d",
            currentDisplayInfo.rsId, currentDisplayInfo.dpi, displayInfo.rsId, displayInfo.dpi);
            auto drawNewDpiRes = CursorDrawingComponent::GetInstance().DrawNewDpiPointer();
            if (drawNewDpiRes != RET_OK) {
                MMI_HILOGE("Draw New Dpi pointer failed.");
            }
            break;
        }
    }
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    if (INPUT_DEV_MGR->HasPointerDevice() || INPUT_DEV_MGR->HasVirtualPointerDevice()) {
        MouseLocation mouseLocation = GetMouseInfo();
        int32_t displayId = MouseEventHdr->GetDisplayId();
        displayId = displayId < 0 ? newId : displayId;
        auto displayInfo = GetPhysicalDisplay(displayId);
        CHKPV(displayInfo);
        int32_t displayInfoX = GetLogicalPositionX(displayId);
        int32_t displayInfoY = GetLogicalPositionY(displayId);
        Direction DirectionCopy = GetLogicalPositionDirection(displayId);
        Direction DisplayDirection = GetPositionDisplayDirection(displayId);
        DispatchPointerCancel(displayId);
        int32_t logicX = mouseLocation.physicalX + displayInfoX;
        int32_t logicY = mouseLocation.physicalY + displayInfoY;
        lastLogicX_ = logicX;
        lastLogicY_ = logicY;
        std::optional<WindowInfo> windowInfo;
        if (lastPointerEventCopy->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
        lastPointerEventCopy->GetPressedButtons().empty()) {
            PhysicalCoordinate coord {
                .x = logicX,
                .y = logicY,
            };
            CursorPosition cursorPosRef;
            double cursorPosx = 0.0;
            double cursorPosy = 0.0;
            Direction direction = Direction::DIRECTION0;
            Direction displayDirection = Direction::DIRECTION0;
            const auto iter = cursorPosMap_.find(groupId);
            if (iter == cursorPosMap_.end()) {
                cursorPosMap_[groupId] = cursorPosRef;
            }
            else {
                direction = iter->second.direction;
                displayDirection = iter->second.displayDirection;
                cursorPosx = iter->second.cursorPos.x;;
                cursorPosy = iter->second.cursorPos.y;
            }
            if (direction != DirectionCopy &&
                displayDirection == DisplayDirection) {
                coord.x = cursorPosx;
                coord.y = cursorPosy;
                RotateDisplayScreen(*displayInfo, coord);
            }
            windowInfo = GetWindowInfo(coord.x, coord.y, groupId);
        } else {
            windowInfo = SelectWindowInfo(logicX, logicY, lastPointerEventCopy);
        }
        if (windowInfo == std::nullopt) {
            MMI_HILOGE("The windowInfo is nullptr");
            DrawPointer(isDisplayRemoved);
            return;
        }
        int32_t windowPid = GetWindowPid(windowInfo->id);
        WinInfo info = { .windowPid = windowPid, .windowId = windowInfo->id };
        CursorDrawingComponent::GetInstance().OnWindowInfo(info);
        PointerStyle pointerStyle;
        GetPointerStyle(info.windowPid, info.windowId, pointerStyle);
        MMI_HILOGD("Get pointer style, pid:%{public}d, windowid:%{public}d, style:%{public}d",
            info.windowPid, info.windowId, pointerStyle.id);
        if (!dragFlag_) {
            SetMouseFlag(lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP);
            isDragBorder_ = SelectPointerChangeArea(*windowInfo, pointerStyle, logicX, logicY);
            dragPointerStyle_ = pointerStyle;
            MMI_HILOGD("Not in drag SelectPointerStyle, pointerStyle is:%{public}d", dragPointerStyle_.id);
        }
        JudgMouseIsDownOrUp(dragFlag_);
        if (lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
            dragFlag_ = true;
            MMI_HILOGD("Is in drag scene");
        }
        if (lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
            dragFlag_ = false;
            isDragBorder_ = false;
        }
        int32_t focusWindowId = GetFocusWindowId(groupId);
        bool isCursopRestoredFlag = (firstBtnDownWindowInfo_.first != focusWindowId) &&
            (PRODUCT_TYPE == PRODUCT_TYPE_PC) && isDragBorder_;
        if (isCursopRestoredFlag) {
            dragPointerStyle_ = pointerStyle;
            MMI_HILOGI("Window is changed, pointerStyle is:%{public}d", dragPointerStyle_.id);
        }
        DrawPointer(isDisplayRemoved);
    }
}

void InputWindowsManager::DispatchPointerCancel(int32_t displayId)
{
    if (mouseDownInfo_.id < 0 || (extraData_.appended && (extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE))) {
        return;
    }
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    std::optional<WindowInfo> windowInfo;
    std::vector<WindowInfo> windowInfos = GetWindowGroupInfoByDisplayId(displayId);
    for (const auto &item : windowInfos) {
        if (item.id == mouseDownInfo_.id) {
            windowInfo = std::make_optional(item);
            break;
        }
    }
    if (windowInfo == std::nullopt && displayId != firstBtnDownWindowInfo_.second) {
        std::vector<WindowInfo> firstBtnDownWindowsInfo =
            GetWindowGroupInfoByDisplayId(firstBtnDownWindowInfo_.second);
        for (const auto &item : firstBtnDownWindowsInfo) {
            if (item.id == mouseDownInfo_.id) {
                windowInfo = std::make_optional(item);
                break;
            }
        }
    }
    if (windowInfo != std::nullopt) {
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), PointerEvent::POINTER_ACTION_CANCEL);
    SetPointerEvent(PointerEvent::POINTER_ACTION_CANCEL, pointerEvent);
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_FREEZE);
    auto filter = InputHandler->GetFilterHandler();
    CHKPV(filter);
    filter->HandlePointerEvent(pointerEvent);
}

void InputWindowsManager::UpdatePointerDrawingManagerWindowInfo()
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    MouseLocation mouseLocation = GetMouseInfo();
    int32_t displayId = MouseEventHdr->GetDisplayId();
    int32_t groupId = FindDisplayGroupId(displayId);
    int32_t newId = 0;

    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        if (iter->second.displaysInfo.empty()) {
            MMI_HILOGW("DisplaysInfo is empty");
            return;
        }
        newId = iter->second.displaysInfo[0].id;
    } else {
        if (displayGroupInfo_.displaysInfo.empty()) {
            MMI_HILOGW("DisplaysInfo is empty");
            return;
        }
        newId = displayGroupInfo_.displaysInfo[0].id;
    }
    displayId = displayId < 0 ? newId : displayId;
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPV(displayInfo);
    int32_t displayInfoX = GetLogicalPositionX(displayId);
    int32_t displayInfoY = GetLogicalPositionY(displayId);
    Direction DirectionCopy = GetLogicalPositionDirection(displayId);
    Direction DisplayDirection = GetPositionDisplayDirection(displayId);
    DispatchPointerCancel(displayId);
    int32_t logicX = mouseLocation.physicalX + displayInfoX;
    int32_t logicY = mouseLocation.physicalY + displayInfoY;
    lastLogicX_ = logicX;
    lastLogicY_ = logicY;
    std::optional<WindowInfo> windowInfo;
    if (lastPointerEventCopy->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
    lastPointerEventCopy->GetPressedButtons().empty()) {
        PhysicalCoordinate coord {
            .x = logicX,
            .y = logicY,
        };
        Direction direction = Direction::DIRECTION0;
        Direction displayDirection = Direction::DIRECTION0;
        double cursorPosx = 0.0;
        double cursorPosy = 0.0;

        const auto iter = cursorPosMap_.find(groupId);
        if (iter != cursorPosMap_.end()) {
            direction = iter->second.direction;
            displayDirection = iter->second.displayDirection;
            cursorPosx = iter->second.cursorPos.x;
            cursorPosy = iter->second.cursorPos.y;
        }
        if (direction != DirectionCopy &&
            displayDirection == DisplayDirection) {
            coord.x = cursorPosx;
            coord.y = cursorPosy;
            RotateDisplayScreen(*displayInfo, coord);
        }
        windowInfo = GetWindowInfo(coord.x, coord.y, groupId);
    } else {
        windowInfo = SelectWindowInfo(logicX, logicY, lastPointerEventCopy);
    }
    CHKFRV(windowInfo, "The windowInfo is nullptr");
    int32_t windowPid = GetWindowPid(windowInfo->id);
    WinInfo info = { .windowPid = windowPid, .windowId = windowInfo->id };
    CursorDrawingComponent::GetInstance().OnWindowInfo(info);
}

void InputWindowsManager::SetPointerEvent(int32_t pointerAction, std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    PointerEvent::PointerItem lastPointerItem;
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    int32_t lastPointerId = lastPointerEventCopy->GetPointerId();
    if (!lastPointerEventCopy->GetPointerItem(lastPointerId, lastPointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", lastPointerId);
        return;
    }
    bool checkFlag = lastPointerItem.IsPressed() && lastWindowInfo_.id != mouseDownInfo_.id;
    int32_t id = lastWindowInfo_.id;
    if (checkFlag) {
        id = mouseDownInfo_.id;
    }
    PointerEvent::PointerItem currentPointerItem;
    currentPointerItem.SetWindowX(lastLogicX_- lastWindowInfo_.area.x);
    currentPointerItem.SetWindowY(lastLogicY_- lastWindowInfo_.area.y);
    currentPointerItem.SetWindowXPos(lastLogicX_- lastWindowInfo_.area.x);
    currentPointerItem.SetWindowYPos(lastLogicY_- lastWindowInfo_.area.y);
    currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
    currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({currentPointerItem.GetDisplayX(),
        currentPointerItem.GetDisplayY()}, lastPointerEventCopy->GetTargetDisplayId());
    currentPointerItem.SetGlobalX(globalCoords.x);
    currentPointerItem.SetGlobalY(globalCoords.y);
    currentPointerItem.SetDisplayXPos(lastPointerItem.GetDisplayXPos());
    currentPointerItem.SetDisplayYPos(lastPointerItem.GetDisplayYPos());
    currentPointerItem.SetPointerId(0);
    pointerEvent->SetTargetDisplayId(lastPointerEventCopy->GetTargetDisplayId());
    SetPrivacyModeFlag(lastWindowInfo_.privacyMode, pointerEvent);
    pointerEvent->SetTargetWindowId(id);
    pointerEvent->SetAgentWindowId(id);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetButtonPressed(lastPointerEventCopy->GetButtonId());
    pointerEvent->SetButtonId(lastPointerEventCopy->GetButtonId());
    pointerEvent->AddPointerItem(currentPointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetOriginPointerAction(lastPointerEventCopy->GetPointerAction());
    pointerEvent->SetSourceType(lastPointerEventCopy->GetSourceType());
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetDeviceId(lastPointerEventCopy->GetDeviceId());
}

bool InputWindowsManager::NeedUpdatePointDrawFlag(const std::vector<WindowInfo> &windows)
{
    CALL_DEBUG_ENTER;
    return !windows.empty() && windows.back().action == WINDOW_UPDATE_ACTION::ADD_END;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::SendPointerEvent(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerAction);
    MouseLocation mouseLocation = GetMouseInfo();
    int32_t displayInfoX = GetLogicalPositionX(mouseLocation.displayId);
    int32_t displayInfoY = GetLogicalPositionY(mouseLocation.displayId);
    lastLogicX_ = mouseLocation.physicalX + displayInfoX;
    lastLogicY_ = mouseLocation.physicalY + displayInfoY;
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW ||
        Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto touchWindow = GetWindowInfo(lastLogicX_, lastLogicY_, MAIN_GROUPID);
        if (!touchWindow) {
            MMI_HILOGE("TouchWindow is nullptr");
            return;
        }
        lastWindowInfo_ = *touchWindow;
    }
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetWindowX(lastLogicX_ - lastWindowInfo_.area.x);
    pointerItem.SetWindowY(lastLogicY_ - lastWindowInfo_.area.y);
    pointerItem.SetWindowXPos(lastLogicX_ - lastWindowInfo_.area.x);
    pointerItem.SetWindowYPos(lastLogicY_ - lastWindowInfo_.area.y);
    pointerItem.SetDisplayX(mouseLocation.physicalX);
    pointerItem.SetDisplayY(mouseLocation.physicalY);
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({mouseLocation.physicalX, mouseLocation.physicalY},
        mouseLocation.displayId);
    pointerItem.SetGlobalX(globalCoords.x);
    pointerItem.SetGlobalY(globalCoords.y);
    pointerItem.SetDisplayXPos(mouseLocation.physicalX);
    pointerItem.SetDisplayYPos(mouseLocation.physicalY);
    pointerItem.SetPointerId(0);

    pointerEvent->SetTargetDisplayId(-1);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display:%{public}d is not existent", displayId);
        return;
    }
    pointerEvent->SetTargetDisplayId(displayId);
    SetPrivacyModeFlag(lastWindowInfo_.privacyMode, pointerEvent);
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
    UpdateWindowInfoFlag(lastWindowInfo_.flags, pointerEvent);
    LogTracer lt1(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    if (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        pointerEvent->SetBuffer(extraData_.buffer);
        pointerEvent->SetPullId(extraData_.pullId);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    auto filter = InputHandler->GetFilterHandler();
    CHKPV(filter);
    filter->HandlePointerEvent(pointerEvent);
}

void InputWindowsManager::DispatchPointer(int32_t pointerAction, int32_t windowId)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState() && !HasMouseHideFlag()) {
        MMI_HILOGI("The mouse is hide");
        return;
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    auto lastPointerEventCopy = GetlastPointerEvent();
    if (lastPointerEventCopy == nullptr) {
        SendPointerEvent(pointerAction);
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerAction);
    PointerEvent::PointerItem lastPointerItem;
    int32_t lastPointerId = lastPointerEventCopy->GetPointerId();
    if (!lastPointerEventCopy->GetPointerItem(lastPointerId, lastPointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", lastPointerId);
        return;
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW && windowId <= 0) {
        std::optional<WindowInfo> windowInfo;
        int32_t eventAction = lastPointerEventCopy->GetPointerAction();
        bool checkFlag = (eventAction == PointerEvent::POINTER_ACTION_MOVE &&
            lastPointerEventCopy->GetPressedButtons().empty()) ||
            (eventAction >= PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
            eventAction <= PointerEvent::POINTER_ACTION_AXIS_END);
        if (checkFlag) {
            windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_, MAIN_GROUPID);
        } else {
            windowInfo = SelectWindowInfo(lastLogicX_, lastLogicY_, lastPointerEventCopy);
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
    currentPointerItem.SetWindowXPos(lastLogicX_ - lastWindowInfo_.area.x);
    currentPointerItem.SetWindowYPos(lastLogicY_ - lastWindowInfo_.area.y);
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW && windowId > 0) {
        auto displayGroupInfo = GetDefaultDisplayGroupInfo();
        int32_t displayId = 0;
        double cursorPosx = 0.0;
        double cursorPosy = 0.0;

        const auto iter = mouseLocationMap_.find(MAIN_GROUPID);
        if (iter != mouseLocationMap_.end()) {
            displayId = iter->second.displayId;
            cursorPosx = iter->second.physicalX;
            cursorPosy = iter->second.physicalY;
        }
        currentPointerItem.SetDisplayX(cursorPosx);
        currentPointerItem.SetDisplayY(cursorPosy);
        auto mouseLocationTmp = iter->second;
        GlobalCoords globalCoords = DisplayCoords2GlobalCoords({mouseLocationTmp.physicalX, mouseLocationTmp.physicalY},
           mouseLocationTmp.displayId);
        currentPointerItem.SetGlobalX(globalCoords.x);
        currentPointerItem.SetGlobalY(globalCoords.y);
        currentPointerItem.SetDisplayXPos(cursorPosx);
        currentPointerItem.SetDisplayYPos(cursorPosy);
        pointerEvent->SetTargetDisplayId(displayId);
        if (IsMouseSimulate()) {
            currentPointerItem.SetWindowX(lastPointerItem.GetWindowX());
            currentPointerItem.SetWindowY(lastPointerItem.GetWindowY());
            currentPointerItem.SetWindowXPos(lastPointerItem.GetWindowXPos());
            currentPointerItem.SetWindowYPos(lastPointerItem.GetWindowYPos());
            currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
            currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
            GlobalCoords globalCoords = DisplayCoords2GlobalCoords({lastPointerItem.GetDisplayX(),
                lastPointerItem.GetDisplayY()}, lastPointerEventCopy->GetTargetDisplayId());
            currentPointerItem.SetGlobalX(globalCoords.x);
            currentPointerItem.SetGlobalY(globalCoords.y);
            currentPointerItem.SetDisplayXPos(lastPointerItem.GetDisplayXPos());
            currentPointerItem.SetDisplayYPos(lastPointerItem.GetDisplayYPos());
            pointerEvent->SetTargetDisplayId(lastPointerEventCopy->GetTargetDisplayId());
        }
    } else {
        if (IsMouseSimulate()) {
            currentPointerItem.SetWindowX(lastPointerItem.GetWindowX());
            currentPointerItem.SetWindowY(lastPointerItem.GetWindowY());
            currentPointerItem.SetWindowXPos(lastPointerItem.GetWindowXPos());
            currentPointerItem.SetWindowYPos(lastPointerItem.GetWindowYPos());
        }
        currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
        currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
        GlobalCoords globalCoords = DisplayCoords2GlobalCoords({lastPointerItem.GetDisplayX(),
            lastPointerItem.GetDisplayY()}, lastPointerEventCopy->GetTargetDisplayId());
        currentPointerItem.SetGlobalX(globalCoords.x);
        currentPointerItem.SetGlobalY(globalCoords.y);
        currentPointerItem.SetDisplayXPos(lastPointerItem.GetDisplayXPos());
        currentPointerItem.SetDisplayYPos(lastPointerItem.GetDisplayYPos());
        pointerEvent->SetTargetDisplayId(lastPointerEventCopy->GetTargetDisplayId());
    }
    currentPointerItem.SetPointerId(0);

    SetPrivacyModeFlag(lastWindowInfo_.privacyMode, pointerEvent);
    currentPointerItem.SetPressed(lastPointerItem.IsPressed());
    currentPointerItem.SetTargetWindowId(lastWindowInfo_.id);
    pointerEvent->SetTargetWindowId(lastWindowInfo_.id);
    pointerEvent->SetAgentWindowId(lastWindowInfo_.agentWindowId);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(currentPointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetSourceType(lastPointerEventCopy->GetSourceType());
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetDeviceId(lastPointerEventCopy->GetDeviceId());
    UpdateWindowInfoFlag(lastWindowInfo_.flags, pointerEvent);
    if (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        pointerEvent->SetBuffer(extraData_.buffer);
        pointerEvent->SetPullId(extraData_.pullId);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_LEAVE_WINDOW) {
        pointerEvent->SetAgentWindowId(lastWindowInfo_.id);
    }
    PrintEnterEventInfo(pointerEvent);
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_FREEZE);
#ifdef OHOS_BUILD_ENABLE_POINTER
    auto filter = InputHandler->GetFilterHandler();
    CHKPV(filter);
    filter->HandlePointerEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
}

void InputWindowsManager::PrintEnterEventInfo(std::shared_ptr<PointerEvent> pointerEvent)
{
    int32_t pointerAc = pointerEvent->GetPointerAction();
    if (pointerAc == PointerEvent::POINTER_ACTION_LEAVE_WINDOW &&
        pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_MOUSE) {
        auto device = INPUT_DEV_MGR->GetInputDevice(pointerEvent->GetDeviceId());
        CHKPV(device);
        MMI_HILOGE("leave-window type:%{public}d, id:%{public}d, pointerid:%{public}d, action:%{public}d by:%{public}s",
            pointerEvent->GetSourceType(), pointerEvent->GetId(), pointerEvent->GetPointerId(),
            pointerAc, device->GetName().c_str());
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::NotifyPointerToWindow(int32_t groupId)
{
    CALL_DEBUG_ENTER;
    std::optional<WindowInfo> windowInfo;
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    if ((lastPointerEventCopy->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) &&
        (!lastPointerEventCopy->GetPressedButtons().empty())) {
        MMI_HILOGD("No need to respond to new interface layouts, btnCounts:%{public}d",
            static_cast<int32_t>(lastPointerEventCopy->GetPressedButtons().size()));
        return;
    }
    if (IsMouseSimulate()) {
        int32_t pointerId = lastPointerEventCopy->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        if (!lastPointerEventCopy->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Get pointer item failed, pointerId:%{public}d", pointerId);
            return;
        }
        windowInfo = GetWindowInfo(pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), groupId);
    } else {
        windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_, groupId);
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
    if (MMI_GNE(lastWindowInfo_.zOrder, windowInfo->zOrder)) {
        std::string windowPrint;
        windowPrint += StringPrintf("highZorder");
        PrintZorderInfo(*windowInfo, windowPrint);
        MMI_HILOGD("%{public}s", windowPrint.c_str());
    }
    bool isFindLastWindow = false;
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (const auto &item : WindowsInfo) {
        if (item.id == lastWindowInfo_.id) {
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
            isFindLastWindow = true;
            break;
        }
    }
    if (!isFindLastWindow) {
        if (udsServer_ != nullptr && udsServer_->GetClientFd(lastWindowInfo_.agentPid) != INVALID_FD) {
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        }
    }
    lastWindowInfo_ = *windowInfo;
    DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
}
#endif // OHOS_BUILD_ENABLE_POINTER

void InputWindowsManager::PrintHighZorder(const std::vector<WindowInfo> &windowsInfo, int32_t pointerAction,
    int32_t targetWindowId, int32_t logicalX, int32_t logicalY)
{
    std::optional<WindowInfo> info = GetWindowInfoById(targetWindowId);
    if (!info) {
        return;
    }
    WindowInfo targetWindow = *info;
    bool isPrint = false;
    std::string windowPrint;
    windowPrint += StringPrintf("highZorder");
    for (const auto &windowInfo : windowsInfo) {
        if (MMI_GNE(windowInfo.zOrder, targetWindow.zOrder) && !windowInfo.flags &&
            pointerAction == PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
            windowInfo.windowInputType != WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE &&
            windowInfo.windowInputType != WindowInputType::DUALTRIGGER_TOUCH &&
            windowInfo.windowInputType != WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE &&
            windowInfo.windowInputType != WindowInputType::TRANSMIT_ALL) {
            if (IsInHotArea(logicalX, logicalY, windowInfo.pointerHotAreas, windowInfo)) {
                PrintZorderInfo(windowInfo, windowPrint);
                isPrint = true;
            }
        }
    }
    if (isPrint) {
        MMI_HILOGW("%{public}s", windowPrint.c_str());
    }
}

void InputWindowsManager::PrintZorderInfo(const WindowInfo &windowInfo, std::string &windowPrint)
{
    windowPrint += StringPrintf("|");
    windowPrint += StringPrintf("%d", windowInfo.id);
    windowPrint += StringPrintf("|");
    windowPrint += StringPrintf("%d", windowInfo.pid);
    windowPrint += StringPrintf("|");
    windowPrint += StringPrintf("%.2f", windowInfo.zOrder);
    windowPrint += StringPrintf("|");
    for (const auto &win : windowInfo.defaultHotAreas) {
        windowPrint += StringPrintf("%d ", win.x);
        windowPrint += StringPrintf("%d ", win.y);
        windowPrint += StringPrintf("%d ", win.width);
        windowPrint += StringPrintf("%d,", win.height);
    }
    windowPrint += StringPrintf("|");
    for (auto it : windowInfo.transform) {
        windowPrint += StringPrintf("%.2f,", it);
    }
    windowPrint += StringPrintf("|");
}

void InputWindowsManager::PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo)
{
    std::string window;
    window += StringPrintf("windowId:[");
    for (const auto &item : windowsInfo) {
        MMI_HILOGD("windowsInfos, id:%{public}d, pid:%{public}d, agentPid:%{public}d, uid:%{public}d, "
            "area.x:%d, area.y:%d, area.width:%{public}d, area.height:%{public}d, "
            "defaultHotAreas.size:%{public}zu, pointerHotAreas.size:%{public}zu, "
            "agentWindowId:%{public}d, flags:%{public}d, action:%{public}d, displayId:%{public}d, "
            "zOrder:%{public}f, privacyMode:%{public}d, privacyProtect:%{public}d, windowType:%{public}d",
            item.id, item.pid, item.agentPid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder, item.privacyMode,
            item.isSkipSelfWhenShowOnVirtualScreen, static_cast<int32_t>(item.windowInputType));
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGD("defaultHotAreas:x:%d, y:%d, width:%{public}d, height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas:x:%d, y:%d, width:%{public}d, height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }

        window += StringPrintf("%d,", item.id);
        std::string dump;
        dump += StringPrintf("pointChangeAreas:[");
        for (const auto &it : item.pointerChangeAreas) {
            dump += StringPrintf("%d,", it);
        }
        dump += StringPrintf("]\n");

        dump += StringPrintf("transform:[");
        for (const auto &it : item.transform) {
            dump += StringPrintf("%f,", it);
        }
        dump += StringPrintf("]\n");
        std::istringstream stream(dump);
        std::string line;
        while (std::getline(stream, line, '\n')) {
            MMI_HILOGD("%{public}s", line.c_str());
        }
        if (!item.uiExtentionWindowInfo.empty()) {
            PrintWindowInfo(item.uiExtentionWindowInfo);
        }
    }
    window += StringPrintf("]\n");
    MMI_HILOGI("%{public}s", window.c_str());
}

void InputWindowsManager::PrintWindowGroupInfo(const WindowGroupInfo &windowGroupInfo)
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("windowsGroupInfo,focusWindowId:%{public}d, displayId:%{public}d",
        windowGroupInfo.focusWindowId, windowGroupInfo.displayId);
    PrintWindowInfo(windowGroupInfo.windowsInfo);
}

void InputWindowsManager::PrintDisplayGroupInfo(const OLD::DisplayGroupInfo displayGroupInfo)
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("logicalInfo,focusWindowId:%{public}d,"
               "windowsInfosNum:%{public}zu,displayInfosNum:%{public}zu",
        displayGroupInfo.focusWindowId,
        displayGroupInfo.windowsInfo.size(),
        displayGroupInfo.displaysInfo.size());
    PrintWindowInfo(displayGroupInfo.windowsInfo);
    for (const auto &item : displayGroupInfo.displaysInfo) {
        PrintDisplayInfo(item);
    }
}

void InputWindowsManager::PrintDisplayInfo(const OLD::DisplayInfo displayInfo)
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("displayInfo{id:%{public}d, name:%{public}s, uniq:%{public}s "
        "XY:{%{private}d %{private}d} offsetXY:{%{private}d %{private}d} "
        "WH:{%{private}d %{private}d} validWH:{%{private}d %{private}d} "
        "direction:%{public}d, displayDirection:%{public}d, fixedDirection:%{public}d} "
        "oneHandXY:{%{private}d %{private}d},"
        "pointerActiveWidth:%{private}d, pointerActiveHeight:%{private}d",
        displayInfo.id,
        displayInfo.name.c_str(),
        displayInfo.uniq.c_str(),
        displayInfo.x,
        displayInfo.y,
        displayInfo.offsetX,
        displayInfo.offsetY,
        displayInfo.width,
        displayInfo.height,
        displayInfo.validWidth,
        displayInfo.validHeight,
        displayInfo.direction,
        displayInfo.displayDirection,
        displayInfo.fixedDirection,
        displayInfo.oneHandX,
        displayInfo.oneHandY,
        displayInfo.pointerActiveWidth,
        displayInfo.pointerActiveHeight);
}

const OLD::DisplayInfo *InputWindowsManager::GetPhysicalDisplay(int32_t id) const
{
    int32_t groupId = FindDisplayGroupId(id);
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        for (auto &it : iter->second.displaysInfo) {
            if (it.id == id) {
                return &it;
            }
        }
    } else {
        for (auto &it : displayGroupInfo_.displaysInfo) {
            if (it.id == id) {
                return &it;
            }
        }
    }
    MMI_HILOGW("Failed to obtain physical(%{public}d) display", id);
    return nullptr;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
const OLD::DisplayInfo *InputWindowsManager::FindPhysicalDisplayInfo(const std::string& uniq) const
{
    for (const auto &item : displayGroupInfoMap_) {
        for (const auto &it : item.second.displaysInfo) {
            if (it.uniq == uniq) {
                return &it;
            }
        }
    }
    MMI_HILOGD("Failed to search for Physical,uniq:%{public}s", uniq.c_str());
    OLD::DisplayGroupInfo displayGroupInfo;
    auto iter = displayGroupInfoMap_.find(MAIN_GROUPID);
    if (iter != displayGroupInfoMap_.end()) {
        if (iter->second.displaysInfo.size() > 0) {
            return &iter->second.displaysInfo[0];
        }
    }
    return nullptr;
}

const OLD::DisplayInfo *InputWindowsManager::GetDefaultDisplayInfo() const
{
    return FindPhysicalDisplayInfo("default0");
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::ScreenRotateAdjustDisplayXY(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const
{
    int32_t groupId = FindDisplayGroupId(info.id);
    Direction rotation = info.direction;
    auto it = cursorPosMap_.find(groupId);
    Direction lastRotation = (it != cursorPosMap_.end()) ? it->second.direction : cursorPos_.direction;
    int32_t width = info.validWidth;
    int32_t height = info.validHeight;
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled() &&
        (rotation == DIRECTION90 || rotation == DIRECTION270)) {
        height = info.validWidth;
        width = info.validHeight;
    }
    if ((static_cast<int32_t>(lastRotation) + 1) % 4 == static_cast<int32_t>(rotation)) {
        double temp = coord.x;
        coord.x = width - coord.y;
        coord.y = temp;
    } else if ((static_cast<int32_t>(lastRotation) + 2) % 4 == static_cast<int32_t>(rotation)) {
        coord.x = width - coord.x;
        coord.y = height - coord.y;
    } else {
        double temp = coord.y;
        coord.y = height -coord.x;
        coord.x = temp;
    }
}

void InputWindowsManager::RotateScreen90(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const
{
    double oldX = coord.x;
    double oldY = coord.y;
    double temp = coord.x;
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        coord.x = info.validHeight - 1 - coord.y;
    } else {
        coord.x = info.validWidth - 1 - coord.y;
    }
    coord.y = temp;
    MMI_HILOGD("DIRECTION90, physicalXY:{%f %f}->{%f %f}", oldX, oldY, coord.x, coord.y);
    return;
}

void InputWindowsManager::RotateScreen(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const
{
    double oldX = coord.x;
    double oldY = coord.y;
    const Direction direction = info.direction;
    int32_t groupId = FindDisplayGroupId(info.id);
    if (direction == DIRECTION0) {
        MMI_HILOGD("DIRECTION0, physicalXY:{%f %f}->{%f %f}", oldX, oldY, coord.x, coord.y);
        return;
    }
    if (direction == DIRECTION90) {
        RotateScreen90(info, coord);
        return;
    }
    if (direction == DIRECTION180) {
        coord.x = info.validWidth - 1 - coord.x;
        coord.y = info.validHeight - 1 - coord.y;
        MMI_HILOGD("DIRECTION180, physicalXY:{%f %f}->{%f %f}", oldX, oldY, coord.x, coord.y);
        return;
    }
    if (direction == DIRECTION270) {
        double temp = coord.y;
        if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
            coord.y = info.validWidth - 1 - coord.x;
        } else {
            coord.y = info.validHeight - 1 - coord.x;
        }
        coord.x = temp;
        MMI_HILOGD("DIRECTION270, physicalXY:{%f %f}->{%f %f}", oldX, oldY, coord.x, coord.y);
    }
}

void InputWindowsManager::RotateDisplayScreen(const OLD::DisplayInfo& info, PhysicalCoordinate& coord)
{
    Direction displayDirection = GetDisplayDirection(&info);
    bool isEnable = Rosen::SceneBoardJudgement::IsSceneBoardEnabled();
    double oldX = coord.x;
    double oldY = coord.y;
    if (displayDirection == DIRECTION0) {
        MMI_HILOGD("DIRECTION0, IsSceneBoardEnabled:%d physicalXY:{%f,%f}", isEnable, oldX, oldY);
        return;
    }
    if (displayDirection == DIRECTION90) {
        double temp = coord.x;
        if (!isEnable) {
            coord.x = info.validHeight - 1 - coord.y;
        } else {
            coord.x = info.validWidth - 1 - coord.y;
        }
        coord.y = temp;
        MMI_HILOGD(
            "DIRECTION90, IsSceneBoardEnabled:%d physicalXY:{%f,%f}->{%f,%f}", isEnable, oldX, oldY, coord.x, coord.y);
        return;
    }
    if (displayDirection == DIRECTION180) {
        coord.x = info.validWidth - 1 - coord.x;
        coord.y = info.validHeight - 1 - coord.y;
        MMI_HILOGD(
            "DIRECTION180, IsSceneBoardEnabled:%d physicalXY:{%f,%f}->{%f,%f}", isEnable, oldX, oldY, coord.x, coord.y);
        return;
    }
    if (displayDirection == DIRECTION270) {
        double temp = coord.y;
        if (!isEnable) {
            coord.y = info.validWidth - 1 - coord.x;
        } else {
            coord.y = info.validHeight - 1 - coord.x;
        }
        coord.x = temp;
        MMI_HILOGD(
            "DIRECTION270, IsSceneBoardEnabled:%d physicalXY:{%f,%f}->{%f,%f}", isEnable, oldX, oldY, coord.x, coord.y);
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
bool InputWindowsManager::GetPhysicalDisplayCoord(int32_t deviceId, struct libinput_event_touch* touch,
    const OLD::DisplayInfo& info, EventTouch& touchInfo, bool isNeedClear, bool hasValidAreaDowned)
{
    PrintDisplayInfo(info);
    auto width = info.width;
    auto height = info.height;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        if (info.direction == DIRECTION90 || info.direction == DIRECTION270) {
            width = info.height;
            height = info.width;
        }
    }

    PhysicalCoordinate coord {
        .x = libinput_event_touch_get_x_transformed(touch, width),
        .y = libinput_event_touch_get_y_transformed(touch, height - info.expandHeight),
    };
    MMI_HILOGD("width:%{private}d, height:%{private}d, physicalX:%{private}f, physicalY:%{private}f",
        width, height, coord.x, coord.y);
    Coordinate2D pos = { .x = coord.x, .y = coord.y };
    if (IsPositionOutValidDisplay(pos, info, true, hasValidAreaDowned)) {
        if (INPUT_DEV_MGR->GetVendorConfig(deviceId).enableOutScreen != ENABLE_OUT_SCREEN_TOUCH) {
            MMI_HILOGW("Position out valid display width:%{private}d, height:%{private}d, "
                "physicalX:%{private}f, physicalY:%{private}f", width, height, pos.x, pos.y);
            if (isNeedClear) {
                int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
                TriggerTouchUpOnInvalidAreaEntry(seatSlot);
            }
            return false;
        }
    }
    MMI_HILOGD("IsPositionOutValidDisplay physicalXY:{%{private}f %{private}f}->{%{private}f %{private}f}",
        coord.x, coord.y, pos.x, pos.y);
    coord.x = pos.x;
    coord.y = pos.y;
    RotateScreen(info, coord);
    touchInfo.coordF = coord;
    touchInfo.point.x = static_cast<int32_t>(coord.x);
    touchInfo.point.y = static_cast<int32_t>(coord.y);

    touchInfo.globalCoord.x =  info.x + touchInfo.point.x;
    touchInfo.globalCoord.y =  info.y + touchInfo.point.y;

    touchInfo.toolRect.point.x = static_cast<int32_t>(libinput_event_touch_get_tool_x_transformed(touch, width));
    touchInfo.toolRect.point.y =
        static_cast<int32_t>(libinput_event_touch_get_tool_y_transformed(touch, height - info.expandHeight));
    touchInfo.toolRect.width = static_cast<int32_t>(
        libinput_event_touch_get_tool_width_transformed(touch, width));
    touchInfo.toolRect.height = static_cast<int32_t>(
        libinput_event_touch_get_tool_height_transformed(touch, height));
    return true;
}

// When the finger moves out of the active area, the touch up event is triggered
void InputWindowsManager::TriggerTouchUpOnInvalidAreaEntry(int32_t pointerId)
{
    if (lastPointerEventforGesture_ == nullptr) {
        MMI_HILOGE("lastPointerEventforGesture_ is null");
        return;
    }
    PointerEvent::PointerItem item;
    if (!(lastPointerEventforGesture_->GetPointerItem(pointerId, item))) {
        MMI_HILOGE("Get pointer item failed, pointerId:%{public}d", pointerId);
        return;
    }
    // Make sure to trigger touch up the first time out of the valid area
    if ((!item.IsCanceled()) && item.IsPressed()) {
        auto pointerEvent = std::make_shared<PointerEvent>(*lastPointerEventforGesture_);
        int32_t originAction = pointerEvent->GetPointerAction();
        pointerEvent->SetOriginPointerAction(originAction);
        int32_t action = PointerEvent::POINTER_ACTION_UP;
        bool isDragging = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
                          (item.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId);
        if (isDragging) {
            action = PointerEvent::POINTER_ACTION_PULL_UP;
        }
        pointerEvent->SetPointerAction(action);
        pointerEvent->SetPointerId(pointerId);
        auto now = GetSysClockTime();
        pointerEvent->SetActionTime(now);
        pointerEvent->SetTargetWindowId(item.GetTargetWindowId());
        auto winOpt = GetWindowAndDisplayInfo(item.GetTargetWindowId(), pointerEvent->GetTargetDisplayId());
        if (winOpt) {
            pointerEvent->SetAgentWindowId(winOpt->agentWindowId);
        }
        pointerEvent->UpdateId();
        auto eventDispatchHandler = InputHandler->GetEventDispatchHandler();
        CHKPV(eventDispatchHandler);
        eventDispatchHandler->HandleTouchEvent(pointerEvent);
        MMI_HILOGI("Trigger touch up, pointerId:%{public}d, pointerAction:%{public}d", pointerId, action);

        // Flag event have been cleaned up
        item.SetCanceled(true);
        lastPointerEventforGesture_->UpdatePointerItem(pointerId, item);
    }
}

void InputWindowsManager::SetAntiMisTake(bool state)
{
    antiMistake_.isOpen = state;
}

void InputWindowsManager::SetAntiMisTakeStatus(bool state)
{
    isOpenAntiMisTakeObserver_ = state;
}

bool InputWindowsManager::TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
    EventTouch& touchInfo, int32_t& physicalDisplayId, bool isNeedClear, bool hasValidAreaDowned)
{
    CHKPF(touch);
    std::string screenId = bindInfo_.GetBindDisplayNameByInputDevice(deviceId);
    if (screenId.empty() || (PRODUCT_TYPE == PRODUCT_TYPE_PC)) {
        screenId = "default0";
    }
    auto info = FindPhysicalDisplayInfo(screenId);
    CHKPF(info);
    physicalDisplayId = info->id;
    if ((info->width <= 0) || (info->height <= 0)) {
        MMI_HILOGE("Get OLD::DisplayInfo is error");
        return false;
    }
    return GetPhysicalDisplayCoord(deviceId, touch, *info, touchInfo, isNeedClear, hasValidAreaDowned);
}

bool InputWindowsManager::TransformTipPoint(struct libinput_event_tablet_tool* tip,
    PhysicalCoordinate& coord, int32_t& displayId, PointerEvent::PointerItem& pointerItem)
{
    CHKPF(tip);
    auto displayInfo = FindPhysicalDisplayInfo("default0");
    CHKPF(displayInfo);
    MMI_HILOGD("PhysicalDisplay.width:%{public}d, PhysicalDisplay.height:%{public}d, "
               "PhysicalDisplay.topLeftX:%{private}d, PhysicalDisplay.topLeftY:%{private}d",
               displayInfo->width, displayInfo->height, displayInfo->x, displayInfo->y);
    displayId = displayInfo->id;
    auto width = displayInfo->width;
    auto height = displayInfo->height;
    if (displayInfo->direction == DIRECTION90 || displayInfo->direction == DIRECTION270) {
        width = displayInfo->height;
        height = displayInfo->width;
    }
    PhysicalCoordinate phys {
        .x = libinput_event_tablet_tool_get_x_transformed(tip, width),
        .y = libinput_event_tablet_tool_get_y_transformed(tip, height),
    };
    MMI_HILOGD("width:%{private}d, height:%{private}d, physicalX:%{private}f, physicalY:%{private}f",
        width, height, phys.x, phys.y);
    Coordinate2D pos = { .x = phys.x, .y = phys.y };
    if (IsPositionOutValidDisplay(pos, *displayInfo, true)) {
        MMI_HILOGD("The position is out of the valid display");
        return false;
    }
    MMI_HILOGD("IsPositionOutValidDisplay physicalXY:{%{private}f %{private}f}->{%{private}f %{private}f}",
        phys.x, phys.y, pos.x, pos.y);
    coord.x = pos.x;
    coord.y = pos.y;
    if (IsWritePen(pointerItem)) {
        RotateScreen(*displayInfo, coord);
    }
    MMI_HILOGD("physicalX:%{private}f, physicalY:%{private}f, displayId:%{public}d", pos.x, pos.y, displayId);
    return true;
}

bool InputWindowsManager::CalculateTipPoint(struct libinput_event_tablet_tool* tip,
    int32_t& targetDisplayId, PhysicalCoordinate& coord, PointerEvent::PointerItem& pointerItem)
{
    CHKPF(tip);
    return TransformTipPoint(tip, coord, targetDisplayId, pointerItem);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
const OLD::DisplayGroupInfo InputWindowsManager::GetDisplayGroupInfo(int32_t groupId)
{
    auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        return iter->second;
    }
    return displayGroupInfo_;
}

const std::vector<OLD::DisplayInfo>& InputWindowsManager::GetDisplayInfoVector(int32_t groupId) const
{
    const auto &groupInfo = displayGroupInfoMap_.find(groupId);
    if (groupInfo != displayGroupInfoMap_.end()) {
        const auto &displaysInfo = groupInfo->second.displaysInfo;
        return displaysInfo;
    }
    const auto &mainGroupInfo = displayGroupInfoMap_.find(MAIN_GROUPID);
    if (mainGroupInfo != displayGroupInfoMap_.end()) {
        const auto &displaysInfo = mainGroupInfo->second.displaysInfo;
        return displaysInfo;
    }
    return displayGroupInfo_.displaysInfo;
}

const std::vector<OLD::DisplayInfo> InputWindowsManager::GetAllUsersDisplays() const
{
    std::vector<OLD::DisplayInfo> displayInfos;
    for (auto &groupInfo : displayGroupInfoMap_) {
        displayInfos.insert(displayInfos.end(), groupInfo.second.displaysInfo.begin(),
        groupInfo.second.displaysInfo.end());
    }
    return displayInfos;
}

const std::vector<WindowInfo>& InputWindowsManager::GetWindowInfoVector(int32_t groupId) const
{
    const auto &groupInfo = displayGroupInfoMap_.find(groupId);
    if (groupInfo != displayGroupInfoMap_.end()) {
        const auto &windowsInfo = groupInfo->second.windowsInfo;
        return windowsInfo;
    }
    const auto &mainGroupInfo = displayGroupInfoMap_.find(MAIN_GROUPID);
    if (mainGroupInfo != displayGroupInfoMap_.end()) {
        const auto &windowsInfo = mainGroupInfo->second.windowsInfo;
        return windowsInfo;
    }
    return displayGroupInfo_.windowsInfo;
}

int32_t InputWindowsManager::GetFocusWindowId(int32_t groupId) const
{
    auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        return iter->second.focusWindowId;
    }
    iter = displayGroupInfoMap_.find(MAIN_GROUPID);
    if (iter != displayGroupInfoMap_.end()) {
        return iter->second.focusWindowId;
    }
    return 0;
}

int32_t InputWindowsManager::GetMainDisplayId(int32_t groupId) const
{
    auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        return iter->second.mainDisplayId;
    }
    return 0;
}

int32_t InputWindowsManager::GetLogicalPositionX(int32_t id)
{
    int32_t groupId = FindDisplayGroupId(id);
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        for (auto &it : iter->second.displaysInfo) {
            if (it.id == id) {
                return it.x;
            }
        }
    } else {
        for (auto &it : displayGroupInfo_.displaysInfo) {
            if (it.id == id) {
                return it.x;
            }
        }
    }
    MMI_HILOGW("Failed to LogicalPosition");
    return DEFAULT_POSITION;
}

int32_t InputWindowsManager::GetLogicalPositionY(int32_t id)
{
    int32_t groupId = FindDisplayGroupId(id);
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        for (auto &it : iter->second.displaysInfo) {
            if (it.id == id) {
                return it.y;
            }
        }
    } else {
        for (auto &it : displayGroupInfo_.displaysInfo) {
            if (it.id == id) {
                return it.y;
            }
        }
    }
    MMI_HILOGW("Failed to LogicalPosition");
    return DEFAULT_POSITION;
}

Direction InputWindowsManager::GetLogicalPositionDirection(int32_t id)
{
    int32_t groupId = FindDisplayGroupId(id);
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        for (auto &it : iter->second.displaysInfo) {
            if (it.id == id) {
                return it.direction;
            }
        }
    } else {
        for (auto &it : displayGroupInfo_.displaysInfo) {
            if (it.id == id) {
                return it.direction;
            }
        }
    }
    MMI_HILOGW("Failed to get direction");
    return Direction::DIRECTION0;
}

Direction InputWindowsManager::GetPositionDisplayDirection(int32_t id)
{
    int32_t groupId = FindDisplayGroupId(id);
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        for (auto &it : iter->second.displaysInfo) {
            if (it.id == id) {
                return it.displayDirection;
            }
        }
    } else {
        for (auto &it : displayGroupInfo_.displaysInfo) {
            if (it.id == id) {
                return it.displayDirection;
            }
        }
    }
    MMI_HILOGW("Failed to get direction");
    return Direction::DIRECTION0;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputWindowsManager::IsNeedRefreshLayer(int32_t windowId)
{
    CALL_DEBUG_ENTER;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return true;
    }
    MouseLocation mouseLocation = GetMouseInfo();
    int32_t displayId = MouseEventHdr->GetDisplayId();
    int32_t groupId = FindDisplayGroupId(displayId);
    int32_t newId = 0;
    const auto iter = displayGroupInfoMap_.find(groupId);
    if (iter != displayGroupInfoMap_.end()) {
        if (iter->second.displaysInfo.empty()) {
            MMI_HILOGW("DisplaysInfo is empty");
            return false;
        }
        newId = iter->second.displaysInfo[0].id;
    } else {
        if (displayGroupInfo_.displaysInfo.empty()) {
            MMI_HILOGW("DisplaysInfo is empty");
            return false;
        }
        newId = displayGroupInfo_.displaysInfo[0].id;
    }
    if (displayId < 0) {
        displayId = newId;
    }
    int32_t displayInfoX = GetLogicalPositionX(displayId);
    int32_t displayInfoY = GetLogicalPositionY(displayId);
    int32_t logicX = mouseLocation.physicalX + displayInfoX;
    int32_t logicY = mouseLocation.physicalY + displayInfoY;
    std::optional<WindowInfo> touchWindow = GetWindowInfo(logicX, logicY, groupId);
    if (!touchWindow) {
        MMI_HILOGE("TouchWindow is nullptr");
        return false;
    }
    if (touchWindow->id == windowId || windowId == GLOBAL_WINDOW_ID) {
        MMI_HILOGD("Need refresh pointer style, focusWindow type:%{public}d, window type:%{public}d",
            touchWindow->id, windowId);
        return true;
    }
    MMI_HILOGD("Not need refresh pointer style, focusWindow type:%{public}d, window type:%{public}d",
        touchWindow->id, windowId);
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void InputWindowsManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    int32_t pid = session->GetPid();
    CursorDrawingComponent::GetInstance().OnSessionLost(pid);
    auto it = pointerStyle_.find(pid);
    if (it != pointerStyle_.end()) {
        pointerStyle_.erase(it);
        MMI_HILOGD("Clear the pointer style map, pd:%{public}d", pid);
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputWindowsManager::UpdatePoinerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle)
{
    CALL_DEBUG_ENTER;
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        MMI_HILOG_CURSORE("The pointer style map is not include param pd:%{public}d", pid);
        return COMMON_PARAMETER_ERROR;
    }
    auto iter = it->second.find(windowId);
    if (iter != it->second.end()) {
        iter->second = pointerStyle;
        return RET_OK;
    }

    auto [iterator, sign] = it->second.insert(std::make_pair(windowId, pointerStyle));
    if (!sign) {
        MMI_HILOG_CURSORW("The window type is duplicated");
        return COMMON_PARAMETER_ERROR;
    }
    return RET_OK;
}

int32_t InputWindowsManager::UpdateSceneBoardPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    auto scenePid = pid;
    auto sceneWinId = windowId;
    if (isUiExtension) {
        auto iter = uiExtensionPointerStyle_.find(scenePid);
        if (iter == uiExtensionPointerStyle_.end() || iter->second.find(sceneWinId) == iter->second.end()) {
            uiExtensionPointerStyle_[scenePid] = {};
            MMI_HILOG_CURSORE("SceneBoardPid %{public}d or windowId:%{public}d does not exist on"
                "uiExtensionPointerStyle_", scenePid, sceneWinId);
        }
        uiExtensionPointerStyle_[scenePid][sceneWinId] = pointerStyle;
        MMI_HILOG_CURSORI("set uiextension pointer success. pid:%{public}d, windowid:%{public}d, pointerid:%{public}d",
            scenePid, sceneWinId, pointerStyle.id);
        return RET_OK;
    }
    auto sceneIter = pointerStyle_.find(scenePid);
    if (sceneIter == pointerStyle_.end()) {
        pointerStyle_[scenePid] = {};
    } else if (sceneIter->second.find(sceneWinId) == sceneIter->second.end()) {
        if (sceneIter->second.size() > POINTER_STYLE_WINDOW_NUM) {
            pointerStyle_[scenePid] = {};
            MMI_HILOG_CURSORE("SceneBoardPid %{public}d windowId:%{public}d exceed",
                scenePid, sceneWinId);
        }
    }
    pointerStyle_[scenePid][sceneWinId] = pointerStyle;
    MMI_HILOG_CURSORD("Sceneboard pid:%{public}d windowId:%{public}d is set to %{public}d",
        scenePid, sceneWinId, pointerStyle.id);
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        MMI_HILOG_CURSORE("Pid:%{public}d does not exist in mmi,", pid);
        std::map<int32_t, PointerStyle> tmpPointerStyle = {{windowId, pointerStyle}};
        auto res = pointerStyle_.insert(std::make_pair(pid, tmpPointerStyle));
        if (!res.second) return RET_ERR;
        return RET_OK;
    }
    auto iter = it->second.find(windowId);
    if (iter == it->second.end()) {
        auto res = it->second.insert(std::make_pair(windowId, pointerStyle));
        if (!res.second) return RET_ERR;
        return RET_OK;
    }
    iter->second = pointerStyle;
    SetMouseFlag(pointerActionFlag_ == PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    UpdateCustomStyle(windowId, pointerStyle);
    return RET_OK;
}

void InputWindowsManager::UpdateCustomStyle(int32_t windowId, PointerStyle pointerStyle)
{
    if (pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
        return;
    }
    for (auto &item : pointerStyle_) {
        for (auto &innerIt : item.second) {
            if (innerIt.first != windowId && innerIt.second.id == MOUSE_ICON::DEVELOPER_DEFINED_ICON) {
                innerIt.second.id = MOUSE_ICON::DEFAULT;
            }
        }
    }
}

void InputWindowsManager::SetUiExtensionInfo(bool isUiExtension, int32_t uiExtensionPid, int32_t uiExtensionWindoId)
{
    MMI_HILOGI("SetUiExtensionInfo. pid:%{public}d, windowid:%{public}d", uiExtensionPid, uiExtensionWindoId);
    isUiExtension_ = isUiExtension;
    uiExtensionPid_ = uiExtensionPid;
    uiExtensionWindowId_ = uiExtensionWindoId;
}

void InputWindowsManager::SetGlobalDefaultPointerStyle()
{
    for (auto &iter : pointerStyle_) {
        for (auto &item : iter.second) {
            if (item.second.id == CURSOR_CIRCLE_STYLE || item.second.id == AECH_DEVELOPER_DEFINED_STYLE) {
                item.second.id = globalStyle_.id;
            } else if (item.second.id == LASER_CURSOR || item.second.id == LASER_CURSOR_DOT ||
                item.second.id == LASER_CURSOR_DOT_RED) {
                item.second.id = globalStyle_.id;
            }
            item.second.options = globalStyle_.options;
        }
    }
}

int32_t InputWindowsManager::SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    CALL_DEBUG_ENTER;
    if (windowId == GLOBAL_WINDOW_ID) {
        globalStyle_.id = pointerStyle.id;
        globalStyle_.options = pointerStyle.options;
        SetGlobalDefaultPointerStyle();
        MMI_HILOG_CURSORD("Setting global pointer style");
        return RET_OK;
    }
    MMI_HILOG_CURSORD("Start to get pid by window %{public}d", windowId);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return UpdatePoinerStyle(pid, windowId, pointerStyle);
    }
    if (!isUiExtension && uiExtensionPointerStyle_.count(pid) != 0) {
        MMI_HILOG_CURSORI("Clear the uiextension mouse style for pid %{public}d", pid);
        uiExtensionPointerStyle_.erase(pid);
    }
    SetUiExtensionInfo(isUiExtension, pid, windowId);
    return UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle, isUiExtension);
}

bool InputWindowsManager::IsMouseSimulate()
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPF(lastPointerEventCopy);
    return lastPointerEventCopy->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE &&
    lastPointerEventCopy->HasFlag(InputEvent::EVENT_FLAG_SIMULATE);
}

bool InputWindowsManager::HasMouseHideFlag()
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPF(lastPointerEventCopy);
    int32_t pointerId = lastPointerEventCopy->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!lastPointerEventCopy->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return false;
    }
    return (lastPointerEventCopy->HasFlag(InputEvent::EVENT_FLAG_HIDE_POINTER) ||
        pointerItem.GetMoveFlag() == POINTER_MOVEFLAG);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t InputWindowsManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        MMI_HILOG_CURSORE("Pid:%{public}d does not exist in mmi", pid);
        return RET_OK;
    }
    auto windowIt = it->second.find(windowId);
    if (windowIt == it->second.end()) {
        MMI_HILOG_CURSORE("windowId %{public}d does not exist in pid%{public}d", windowId, pid);
        return RET_OK;
    }

    it->second.erase(windowIt);
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputWindowsManager::GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
    bool isUiExtension) const
{
    CALL_DEBUG_ENTER;
    if (isUiExtension) {
        auto it = uiExtensionPointerStyle_.find(pid);
        if (it == uiExtensionPointerStyle_.end()) {
            MMI_HILOG_CURSORE("The uiextension pointer style map is not include pid:%{public}d", pid);
            pointerStyle.id = globalStyle_.id;
            return RET_OK;
        }
        auto iter = it->second.find(windowId);
        if (iter == it->second.end()) {
            pointerStyle.id = globalStyle_.id;
            return RET_OK;
        }
        MMI_HILOG_CURSORI("window type:%{public}d, get pointer style:%{public}d success", windowId, iter->second.id);
        pointerStyle = iter->second;
        return RET_OK;
    }
    if (windowId == GLOBAL_WINDOW_ID) {
        MMI_HILOG_CURSORD("Getting global pointer style");
        pointerStyle.id = globalStyle_.id;
        pointerStyle.options = globalStyle_.options;
        return RET_OK;
    }
    auto it = pointerStyle_.find(pid);
    if (it == pointerStyle_.end()) {
        if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
            pointerStyle.id = globalStyle_.id;
            return RET_OK;
        }
        MMI_HILOG_CURSORE("The pointer style map is not include param pd, %{public}d", pid);
        return RET_OK;
    }
    auto iter = it->second.find(windowId);
    if (iter == it->second.end()) {
        pointerStyle.id = globalStyle_.id;
        return RET_OK;
    }
    if (iter->second.id == DEFAULT_POINTER_STYLE) {
        pointerStyle.id = globalStyle_.id;
    } else {
        pointerStyle = iter->second;
    }
    MMI_HILOG_CURSORD("Window type:%{public}d get pointer style:%{public}d success", windowId, pointerStyle.id);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::InitPointerStyle(int32_t groupId)
{
    CALL_DEBUG_ENTER;
    PointerStyle pointerStyle;
    pointerStyle.id = DEFAULT_POINTER_STYLE;
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (const auto& windowItem : WindowsInfo) {
        int32_t pid = windowItem.pid;
        auto it = pointerStyle_.find(pid);
        if (it == pointerStyle_.end()) {
            std::map<int32_t, PointerStyle> tmpPointerStyle = {};
            auto iter = pointerStyle_.insert(std::make_pair(pid, tmpPointerStyle));
            if (!iter.second) {
                MMI_HILOGW("The pd is duplicated");
            }
            continue;
        }
    }
    MMI_HILOGD("Number of pointer style:%{public}zu", pointerStyle_.size());
}

#endif // OHOS_BUILD_ENABLE_POINTER

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputWindowsManager::IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects,
    const WindowInfo &window) const
{
    auto windowXY = TransformWindowXY(window, x, y);
    auto windowX = static_cast<int32_t>(windowXY.first);
    auto windowY = static_cast<int32_t>(windowXY.second);
    for (const auto &item : rects) {
        int32_t displayMaxX = 0;
        int32_t displayMaxY = 0;
        if (!AddInt32(item.x - currentDisplayXY_.first, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return false;
        }
        if (!AddInt32(item.y - currentDisplayXY_.second, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return false;
        }
        if (((windowX >= (item.x - currentDisplayXY_.first)) && (windowX < displayMaxX)) &&
            (windowY >= (item.y - currentDisplayXY_.second)) && (windowY < displayMaxY)) {
            lastWinX_ = windowX;
            lastWinY_ = windowY;
            return true;
        }
    }
    return false;
}

bool InputWindowsManager::InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects,
    PointerStyle &pointerStyle) const
{
    int32_t areaNum = 0;
    bool findFlag = false;
    for (const auto &item : rects) {
        if (item.width == 0 || item.height == 0) {
            MMI_HILOGD("The width or height of hotArea is 0, width: %{public}d, height: %{public}d, "
                "areaNum: %{public}d", item.width, item.height, areaNum);
            areaNum++;
            continue;
        }
        int32_t displayMaxX = 0;
        int32_t displayMaxY = 0;
        if (!AddInt32(item.x, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return findFlag;
        }
        if (!AddInt32(item.y, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return findFlag;
        }
        if (((x >= item.x) && (x <= displayMaxX)) && (y >= item.y) && (y <= displayMaxY)) {
            findFlag = true;
            pointerStyle.id = areaNum;
        }
        areaNum++;
    }
    if (!findFlag) {
        MMI_HILOGD("pointer not match any area");
        return findFlag;
    }
    switch (pointerStyle.id) {
        case PointerHotArea::TOP:
        case PointerHotArea::BOTTOM:
            pointerStyle.id = MOUSE_ICON::NORTH_SOUTH;
            break;
        case PointerHotArea::LEFT:
        case PointerHotArea::RIGHT:
            pointerStyle.id = MOUSE_ICON::WEST_EAST;
            break;
        case PointerHotArea::TOP_LEFT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST_SOUTH_EAST;
            break;
        case PointerHotArea::TOP_RIGHT:
            pointerStyle.id = MOUSE_ICON::NORTH_EAST_SOUTH_WEST;
            break;
        case PointerHotArea::BOTTOM_LEFT:
            pointerStyle.id = MOUSE_ICON::NORTH_EAST_SOUTH_WEST;
            break;
        case PointerHotArea::BOTTOM_RIGHT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST_SOUTH_EAST;
            break;
        default:
            MMI_HILOGD("pointerStyle in default is:%{public}d", pointerStyle.id);
            break;
    }
    MMI_HILOGD("pointerStyle after switch ID is :%{public}d", pointerStyle.id);
    return findFlag;
}

bool InputWindowsManager::InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects) const
{
    bool findFlag = false;
    for (const auto &item : rects) {
        int32_t displayMaxX = 0;
        int32_t displayMaxY = 0;
        if (!AddInt32(item.x, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return findFlag;
        }
        if (!AddInt32(item.y, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return findFlag;
        }
        if (((x > item.x) && (x <= displayMaxX)) && (y > item.y) && (y <= displayMaxY)) {
            findFlag = true;
            break;
        }
    }
    return findFlag;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputWindowsManager::AdjustDisplayCoordinate(
    const OLD::DisplayInfo& displayInfo, double& physicalX, double& physicalY) const
{
    int32_t width = displayInfo.validWidth;
    int32_t height = displayInfo.validHeight;
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        if (displayInfo.direction == DIRECTION90 || displayInfo.direction == DIRECTION270) {
            width = displayInfo.height;
            height = displayInfo.width;
        }
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
    int32_t groupId = FindDisplayGroupId(displayId);
    auto &DisplaysInfo = GetDisplayInfoVector(groupId);
    if (DisplaysInfo.empty()) {
        MMI_HILOGE("DisplaysInfo is empty");
        return false;
    }
    if (displayId < 0) {
        displayId = DisplaysInfo[0].id;
        return true;
    }
    for (const auto &item : DisplaysInfo) {
        if (item.id == displayId) {
            return true;
        }
    }
    return false;
}

void InputWindowsManager::UpdateCurrentDisplay(int32_t displayId) const
{
    auto physicalDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPV(physicalDisplayInfo);
    currentDisplayXY_ =  std::make_pair(physicalDisplayInfo->x, physicalDisplayInfo->y);
}

std::optional<WindowInfo> InputWindowsManager::SelectWindowInfo(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t action = pointerEvent->GetPointerAction();
    bool checkFlag = (firstBtnDownWindowInfo_.first == -1) ||
        ((action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) && (pointerEvent->GetPressedButtons().size() <= 1)) ||
        ((action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty())) ||
        (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) ||
        (action == PointerEvent::POINTER_ACTION_PULL_UP) ||
        ((action == PointerEvent::POINTER_ACTION_AXIS_BEGIN || action == PointerEvent::POINTER_ACTION_ROTATE_BEGIN) &&
        (pointerEvent->GetPressedButtons().empty())) || (action == PointerEvent::POINTER_ACTION_TOUCHPAD_ACTIVE);
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    if (checkFlag) {
        int32_t targetWindowId = pointerEvent->GetTargetWindowId();
        static std::unordered_map<int32_t, int32_t> winId2ZorderMap;
        bool isHotArea = false;
        if (targetWindowId <= 1) {
            targetMouseWinIds_.clear();
        }
        for (const auto &item : windowsInfo) {
            if (transparentWins_.find(item.id) != transparentWins_.end()) {
                if (IsTransparentWin(transparentWins_[item.id], logicalX - item.area.x, logicalY - item.area.y)) {
                    winId2ZorderMap.insert({item.id, item.zOrder});
                    MMI_HILOG_DISPATCHE("It's an abnormal window and pointer find the next window, window:%{public}d",
                        item.id);
                    continue;
                }
            }
            if (item.windowInputType == WindowInputType::TRANSMIT_ANTI_AXIS_MOVE) {
                MMI_HILOG_DISPATCHD("Pointer enents do not respond to the window, window:%{public}d, "
                    "windowInputType%{public}d", item.id, static_cast<int32_t>(item.windowInputType));
                continue;
            }
            if (SkipPrivacyProtectionWindow(pointerEvent, item.isSkipSelfWhenShowOnVirtualScreen)) {
                winId2ZorderMap.insert({item.id, item.zOrder});
                continue;
            }
            if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
                !IsValidZorderWindow(item, pointerEvent)) {
                winId2ZorderMap.insert({item.id, item.zOrder});
                MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching, "
                    "window:%{public}d, flags:%{public}d, pid:%{public}d", item.id, item.flags, item.pid);
                continue;
            }
            if (IsAccessibilityEventWithZorderInjected(pointerEvent) && pointerEvent->GetZOrder() <= item.zOrder) {
                winId2ZorderMap.insert({item.id, item.zOrder});
                continue;
            } else if ((extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) ||
                (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP)) {
                if (IsInHotArea(logicalX, logicalY, item.pointerHotAreas, item)) {
                    if (item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) {
                        winId2ZorderMap.insert({item.id, item.zOrder});
                        continue;
                    }
                    firstBtnDownWindowInfo_.first = item.id;
                    firstBtnDownWindowInfo_.second = item.displayId;
                    MMI_HILOG_DISPATCHD("Mouse event select pull window, window:%{public}d, pid:%{public}d",
                        firstBtnDownWindowInfo_.first, item.pid);
                    break;
                } else {
                    winId2ZorderMap.insert({item.id, item.zOrder});
                    continue;
                }
            } else if ((targetWindowId < 0) && (IsInHotArea(logicalX, logicalY, item.pointerHotAreas, item))) {
                if ((item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE ||
                    item.windowInputType == WindowInputType::DUALTRIGGER_TOUCH ||
                    item.windowInputType == WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE) &&
                    ((pointerEvent->GetPressedButtons().empty()) ||
                    (action == PointerEvent::POINTER_ACTION_PULL_UP) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_UPDATE) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_END)||
                    (PointerEvent::MOUSE_BUTTON_LEFT != pointerEvent->GetButtonId()))) {
                    MMI_HILOG_DISPATCHD("Mouse event transparent, action:%{public}d, ButtonId:%{public}d",
                        action, pointerEvent->GetButtonId());
                    continue;
                }
                firstBtnDownWindowInfo_.first = item.id;
                firstBtnDownWindowInfo_.second = item.displayId;
                if (!item.uiExtentionWindowInfo.empty()) {
                    // Determine whether the landing point as a safety sub window
                    CheckUIExtentionWindowPointerHotArea(logicalX, logicalY,
                        item.uiExtentionWindowInfo, firstBtnDownWindowInfo_.first);
                }
                MMI_HILOG_DISPATCHD("Find out the dispatch window of this pointer event when the targetWindowId "
                    "hasn't been set up yet, window:%{public}d, pid:%{public}d",
                    firstBtnDownWindowInfo_.first, item.pid);
                bool isSpecialWindow = HandleWindowInputType(item, pointerEvent);
                if (isSpecialWindow) {
                    AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id,
                        pointerEvent->GetDeviceId());
                    isHotArea = true;
                    continue;
                } else if (isHotArea) {
                    AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id,
                        pointerEvent->GetDeviceId());
                    break;
                } else {
                    break;
                }

            } else if ((targetWindowId >= 0) && (targetWindowId == item.id)) {
                firstBtnDownWindowInfo_.first = targetWindowId;
                firstBtnDownWindowInfo_.second = item.displayId;
                MMI_HILOG_DISPATCHD("Find out the dispatch window of this pointer event when the targetWindowId "
                    "has been set up already, window:%{public}d, pid:%{public}d",
                    firstBtnDownWindowInfo_.first, item.pid);
                break;
            } else {
                winId2ZorderMap.insert({item.id, item.zOrder});
                MMI_HILOG_DISPATCHD("Continue searching for the dispatch window of this pointer event");
            }
        }
        if ((firstBtnDownWindowInfo_.first < 0) && (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) &&
            (pointerEvent->GetPressedButtons().size() == 1)) {
            for (const auto &iter : winId2ZorderMap) {
                MMI_HILOG_DISPATCHI("%{public}d, %{public}d", iter.first, iter.second);
            }
        }
        winId2ZorderMap.clear();
    }
    if (axisBeginWindowInfo_ &&
        (action == PointerEvent::POINTER_ACTION_AXIS_UPDATE || action == PointerEvent::POINTER_ACTION_AXIS_END)) {
        firstBtnDownWindowInfo_ = { axisBeginWindowInfo_->id, axisBeginWindowInfo_->displayId };
    }
    MMI_HILOG_DISPATCHD("firstBtnDownWindowInfo_.first:%{public}d", firstBtnDownWindowInfo_.first);
#ifdef OHOS_BUILD_PC_PRIORITY
    PrintHighZorder(windowsInfo, pointerEvent->GetPointerAction(), firstBtnDownWindowInfo_.first, logicalX, logicalY);
#endif // OHOS_BUILD_PC_PRIORITY
    for (const auto &item : windowsInfo) {
        for (const auto &windowInfo : item.uiExtentionWindowInfo) {
            if (windowInfo.id == firstBtnDownWindowInfo_.first) {
                firstBtnDownWindowInfo_.second = pointerEvent->GetTargetDisplayId();
                return std::make_optional(windowInfo);
            }
        }
        if (item.id == firstBtnDownWindowInfo_.first) {
            firstBtnDownWindowInfo_.second = pointerEvent->GetTargetDisplayId();
            return std::make_optional(item);
        }
    }
    if (pointerEvent->GetTargetDisplayId() != firstBtnDownWindowInfo_.second) {
        std::vector<WindowInfo> firstBtnDownWindowsInfo =
            GetWindowGroupInfoByDisplayId(firstBtnDownWindowInfo_.second);
        for (const auto &item : firstBtnDownWindowsInfo) {
            for (const auto &windowInfo : item.uiExtentionWindowInfo) {
                if (windowInfo.id == firstBtnDownWindowInfo_.first) {
                    return std::make_optional(windowInfo);
                }
            }
            if (item.id == firstBtnDownWindowInfo_.first) {
                return std::make_optional(item);
            }
        }
    }
    return std::nullopt;
}

void InputWindowsManager::CheckUIExtentionWindowPointerHotArea(int32_t logicalX, int32_t logicalY,
    const std::vector<WindowInfo>& windowInfos, int32_t& windowId)
{
    for (const auto &it : windowInfos) {
        if (IsInHotArea(logicalX, logicalY, it.pointerHotAreas, it)) {
            windowId = it.id;
            break;
        }
    }
}

std::optional<WindowInfo> InputWindowsManager::GetWindowInfo(int32_t logicalX, int32_t logicalY, int32_t groupId)
{
    CALL_DEBUG_ENTER;
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (const auto& item : WindowsInfo) {
        if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
            MMI_HILOGD("Skip the untouchable window to continue searching, "
                "window:%{public}d, flags:%{public}d", item.id, item.flags);
            continue;
        } else if (IsInHotArea(logicalX, logicalY, item.pointerHotAreas, item)) {
            return std::make_optional(item);
        } else {
            MMI_HILOGD("Continue searching for the dispatch window");
        }
    }
    return std::nullopt;
}

bool InputWindowsManager::SelectPointerChangeArea(const WindowInfo &windowInfo, PointerStyle &pointerStyle,
    int32_t logicalX, int32_t logicalY)
{
    CALL_DEBUG_ENTER;
    int32_t windowId = windowInfo.id;
    bool findFlag = false;
    if (windowsHotAreas_.find(windowId) != windowsHotAreas_.end()) {
        std::vector<Rect> windowHotAreas = windowsHotAreas_[windowId];
        MMI_HILOG_CURSORD("windowHotAreas size:%{public}zu, windowId:%{public}d, pid:%{public}d",
            windowHotAreas.size(), windowId, windowInfo.pid);
        findFlag = InWhichHotArea(logicalX, logicalY, windowHotAreas, pointerStyle);
    }
    return findFlag;
}

bool InputWindowsManager::SelectPointerChangeArea(int32_t windowId, int32_t logicalX, int32_t logicalY)
{
    CALL_DEBUG_ENTER;
    bool findFlag = false;
    if (windowsHotAreas_.find(windowId) != windowsHotAreas_.end()) {
        std::vector<Rect> windowHotAreas = windowsHotAreas_[windowId];
        MMI_HILOGE("windowHotAreas size:%{public}zu, windowId:%{public}d",
            windowHotAreas.size(), windowId);
        findFlag = InWhichHotArea(logicalX, logicalY, windowHotAreas);
    }
    return findFlag;
}

void InputWindowsManager::UpdatePointerChangeAreas(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::map<int32_t, std::vector<Rect>> &winHotAreasTmp = windowsHotAreasMap_[displayGroupInfo.groupId];
    for (const auto &windowInfo : displayGroupInfo.windowsInfo) {
        std::vector<Rect> windowHotAreas;
        int32_t windowId = windowInfo.id;
        Rect windowArea = windowInfo.area;
        if (windowInfo.transform.size() <= 0) {
            continue;
        }
        windowArea.width = windowInfo.transform[SCALE_X] != 0 ? windowInfo.area.width / windowInfo.transform[SCALE_X]
            : windowInfo.area.width;
        windowArea.height = windowInfo.transform[SCALE_Y] != 0 ? windowInfo.area.height / windowInfo.transform[SCALE_Y]
            : windowInfo.area.height;
        std::vector<int32_t> pointerChangeAreas = windowInfo.pointerChangeAreas;
        if (!pointerChangeAreas.empty()) {
            UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
            UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
            UpdateInnerAngleArea(windowArea, pointerChangeAreas, windowHotAreas);
        }
        if (winHotAreasTmp.find(windowId) == winHotAreasTmp.end()) {
            winHotAreasTmp.emplace(windowId, windowHotAreas);
        } else {
            winHotAreasTmp[windowId] = windowHotAreas;
        }
    }
}

void InputWindowsManager::UpdatePointerChangeAreas()
{
    CALL_DEBUG_ENTER;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        const auto iter = displayGroupInfoMapTmp_.find(MAIN_GROUPID);
        if(iter == displayGroupInfoMapTmp_.end()) {
            return;
        }
        UpdatePointerChangeAreas(iter->second);
    }
}

void InputWindowsManager::UpdateTopBottomArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
    std::vector<Rect> &windowHotAreas)
{
    CALL_DEBUG_ENTER;
    Rect newTopRect;
    newTopRect.x = windowArea.x + pointerChangeAreas[TOP_LEFT_AREA];
    newTopRect.y = windowArea.y - OUTWINDOW_HOT_AREA;
    newTopRect.width = windowArea.width - pointerChangeAreas[TOP_LEFT_AREA] - pointerChangeAreas[TOP_RIGHT_AREA];
    newTopRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[TOP_AREA];
    Rect newBottomRect;
    newBottomRect.x = windowArea.x + pointerChangeAreas[BOTTOM_LEFT_AREA];
    newBottomRect.y = windowArea.y + windowArea.height - pointerChangeAreas[BOTTOM_AREA];
    newBottomRect.width = windowArea.width - pointerChangeAreas[BOTTOM_LEFT_AREA] -
        pointerChangeAreas[BOTTOM_RIGHT_AREA];
    newBottomRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[BOTTOM_AREA];
    if (pointerChangeAreas[TOP_AREA] == 0) {
        newTopRect.width = 0;
        newTopRect.height = 0;
    }
    if (pointerChangeAreas[BOTTOM_AREA] == 0) {
        newBottomRect.width = 0;
        newBottomRect.height = 0;
    }
    windowHotAreas.push_back(newTopRect);
    windowHotAreas.push_back(newBottomRect);
}

void InputWindowsManager::UpdateLeftRightArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
    std::vector<Rect> &windowHotAreas)
{
    CALL_DEBUG_ENTER;
    Rect newLeftRect;
    newLeftRect.x = windowArea.x - OUTWINDOW_HOT_AREA;
    newLeftRect.y = windowArea.y + pointerChangeAreas[TOP_LEFT_AREA];
    newLeftRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[LEFT_AREA];
    newLeftRect.height = windowArea.height - pointerChangeAreas[TOP_LEFT_AREA] - pointerChangeAreas[BOTTOM_LEFT_AREA];
    Rect newRightRect;
    newRightRect.x = windowArea.x + windowArea.width - pointerChangeAreas[RIGHT_AREA];
    newRightRect.y = windowArea.y + pointerChangeAreas[TOP_RIGHT_AREA];
    newRightRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[RIGHT_AREA];
    newRightRect.height = windowArea.height - pointerChangeAreas[TOP_RIGHT_AREA] -
        pointerChangeAreas[BOTTOM_RIGHT_AREA];
    if (pointerChangeAreas[LEFT_AREA] == 0) {
        newLeftRect.width = 0;
        newLeftRect.height = 0;
    }
    if (pointerChangeAreas[RIGHT_AREA] == 0) {
        newRightRect.width = 0;
        newRightRect.height = 0;
    }
    windowHotAreas.push_back(newLeftRect);
    windowHotAreas.push_back(newRightRect);
}

void InputWindowsManager::UpdateInnerAngleArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
    std::vector<Rect> &windowHotAreas)
{
    CALL_DEBUG_ENTER;
    Rect newTopLeftRect;
    newTopLeftRect.x = windowArea.x - OUTWINDOW_HOT_AREA;
    newTopLeftRect.y = windowArea.y - OUTWINDOW_HOT_AREA;
    newTopLeftRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[TOP_LEFT_AREA];
    newTopLeftRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[TOP_LEFT_AREA];
    Rect newTopRightRect;
    newTopRightRect.x = windowArea.x + windowArea.width - pointerChangeAreas[TOP_RIGHT_AREA];
    newTopRightRect.y = windowArea.y - OUTWINDOW_HOT_AREA;
    newTopRightRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[TOP_RIGHT_AREA];
    newTopRightRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[TOP_RIGHT_AREA];
    Rect newBottomLeftRect;
    newBottomLeftRect.x = windowArea.x - OUTWINDOW_HOT_AREA;
    newBottomLeftRect.y = windowArea.y + windowArea.height - pointerChangeAreas[BOTTOM_LEFT_AREA];
    newBottomLeftRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[BOTTOM_LEFT_AREA];
    newBottomLeftRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[BOTTOM_LEFT_AREA];
    Rect newBottomRightRect;
    newBottomRightRect.x = windowArea.x + windowArea.width - pointerChangeAreas[BOTTOM_RIGHT_AREA];
    newBottomRightRect.y = windowArea.y + windowArea.height - pointerChangeAreas[BOTTOM_RIGHT_AREA];
    newBottomRightRect.width = OUTWINDOW_HOT_AREA + pointerChangeAreas[BOTTOM_RIGHT_AREA];
    newBottomRightRect.height = OUTWINDOW_HOT_AREA + pointerChangeAreas[BOTTOM_RIGHT_AREA];
    if (pointerChangeAreas[TOP_LEFT_AREA] == 0) {
        newTopLeftRect.width = 0;
        newTopLeftRect.height = 0;
    }
    if (pointerChangeAreas[TOP_RIGHT_AREA] == 0) {
        newTopRightRect.width = 0;
        newTopRightRect.height = 0;
    }
    if (pointerChangeAreas[BOTTOM_LEFT_AREA] == 0) {
        newBottomLeftRect.width = 0;
        newBottomLeftRect.height = 0;
    }
    if (pointerChangeAreas[BOTTOM_RIGHT_AREA] == 0) {
        newBottomRightRect.width = 0;
        newBottomRightRect.height = 0;
    }

    windowHotAreas.push_back(newTopLeftRect);
    windowHotAreas.push_back(newTopRightRect);
    windowHotAreas.push_back(newBottomLeftRect);
    windowHotAreas.push_back(newBottomRightRect);
}

void InputWindowsManager::HandlePullEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    auto action = pointerEvent->GetPointerAction();
    if (action != PointerEvent::POINTER_ACTION_PULL_CANCEL &&
        action != PointerEvent::POINTER_ACTION_PULL_MOVE &&
        action != PointerEvent::POINTER_ACTION_PULL_UP) {
        return;
    }
    int32_t pullId = pointerEvent->GetPullId();
    static int32_t originPullId { -1 };
    if (action == PointerEvent::POINTER_ACTION_PULL_CANCEL) {
        originPullId = pullId;
        MMI_HILOGI("Set originPullId:%{public}d", originPullId);
        if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            MMI_HILOGI("Convert PULL_CANCEL to CANCEL When in accessibility");
        }
        return;
    }
    if (originPullId != pullId || originPullId == -1) {
        MMI_HILOGD("Not the same drag instance, originPullId:%{public}d, pullId:%{public}d", originPullId, pullId);
        return;
    }
    auto pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("GetPointerItem of pointerId:%{public}d failed", pointerId);
        return;
    }
    pointerItem.SetCanceled(true);
    pointerItem.SetPressed(false);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    MMI_HILOGI("SetCanceled true, SetPressed false, pointerId:%{public}d, originPullId:%{public}d",
        pointerId, originPullId);
    originPullId = -1;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow)
{
    CHKPV(pointerEvent);
    MMI_HILOG_DISPATCHD("LastWindowInfo:%{public}d, touchWindow:%{public}d", lastWindowInfo_.id, touchWindow.id);
    if (lastWindowInfo_.id != touchWindow.id) {
        DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        lastLogicX_ = logicalX;
        lastLogicY_ = logicalY;
        {
            std::lock_guard<std::mutex> guard(mtx_);
            lastPointerEvent_ = pointerEvent;
        }
        lastWindowInfo_ = touchWindow;
        DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
        return;
    }
    lastLogicX_ = logicalX;
    lastLogicY_ = logicalY;
    {
        std::lock_guard<std::mutex> guard(mtx_);
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHPAD) {
            std::vector<int32_t> pointerIds{ pointerEvent->GetPointerIds() };
            std::string isSimulate = pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) ? "true" : "false";
            auto device = INPUT_DEV_MGR->GetInputDevice(pointerEvent->GetDeviceId());
            std::string deviceName { "Null" };
            if (device != nullptr) {
                deviceName = device->GetName();
            }
            MMI_HILOGE("Not mouse event id:%{public}d, PI:%{public}d, AC:%{public}d, wid:%{public}d by:%{public}s,"
                " SI:%{public}s, PC:%{public}zu, LastEvent id:%{public}d, PI:%{public}d, AC:%{public}d, wid:%{public}d",
                pointerEvent->GetId(), pointerEvent->GetPointerId(), pointerEvent->GetPointerAction(),
                pointerEvent->GetTargetWindowId(), deviceName.c_str(), isSimulate.c_str(), pointerIds.size(),
                lastPointerEvent_->GetId(), lastPointerEvent_->GetPointerId(), lastPointerEvent_->GetPointerAction(),
                lastPointerEvent_->GetTargetWindowId());
        }
        lastPointerEvent_ = pointerEvent;
    }
    lastWindowInfo_ = touchWindow;
}

int32_t InputWindowsManager::SetHoverScrollState(bool state)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Set mouse hover scroll state:%{public}d", state);
    std::string name = "isEnableHoverScroll";
    return PREFERENCES_MGR->SetBoolValue(name, MOUSE_FILE_NAME, state);
}

bool InputWindowsManager::GetHoverScrollState() const
{
    CALL_DEBUG_ENTER;
    std::string name = "isEnableHoverScroll";
    bool state = PREFERENCES_MGR->GetBoolValue(name, true);
    MMI_HILOGD("Get mouse hover scroll state:%{public}d", state);
    return state;
}

void InputWindowsManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{
    MMI_HILOGD("direction:%{public}d", direction);
    switch (direction) {
        case DIRECTION0: {
            break;
        }
        case DIRECTION90: {
            int32_t temp = physicalY;
            physicalY = width - physicalX;
            physicalX = temp;
            break;
        }
        case DIRECTION180: {
            physicalX = width - physicalX;
            physicalY = height - physicalY;
            break;
        }
        case DIRECTION270: {
            int32_t temp = physicalX;
            physicalX = height - physicalY;
            physicalY = temp;
            break;
        }
        default: {
            break;
        }
    }
}

std::vector<int32_t> InputWindowsManager::HandleHardwareCursor(const OLD::DisplayInfo *physicalDisplayInfo,
    int32_t physicalX, int32_t physicalY)
{
    std::vector<int32_t> cursorPos = {DEFAULT_POSITION, DEFAULT_POSITION};
    if (physicalDisplayInfo == nullptr) {
        return cursorPos;
    }
    Direction direction = DIRECTION0;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = GetDisplayDirection(physicalDisplayInfo);
        GetOriginalTouchScreenCoordinates(direction, physicalDisplayInfo->validWidth,
            physicalDisplayInfo->validHeight, physicalX, physicalY);
    }
    cursorPos = {physicalX, physicalY};
    (void)direction;
    return cursorPos;
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
    int32_t groupId = FindDisplayGroupId(displayId);
    auto physicalDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPR(physicalDisplayInfo, ERROR_NULL_POINTER);
    int32_t displayInfoX = GetLogicalPositionX(displayId);
    int32_t displayInfoY = GetLogicalPositionY(displayId);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayY();
    if (!AddInt32(physicalX, displayInfoX, logicalX)) {
        MMI_HILOGE("The addition of logicalX overflows");
        return RET_ERR;
    }
    if (!AddInt32(physicalY, displayInfoY, logicalY)) {
        MMI_HILOGE("The addition of logicalY overflows");
        return RET_ERR;
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        ClearTargetWindowId(pointerId, pointerEvent->GetDeviceId());
    }
    auto touchWindow = SelectWindowInfo(logicalX, logicalY, pointerEvent);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN) {
        axisBeginWindowInfo_ = touchWindow;
    }
    if (!touchWindow) {
        MMI_HILOGI("UpdateMouseTarget rsId:%{public}" PRIu64 ", logicalX:%{private}d, logicalY:%{private}d,"
            "displayX:%{private}d, displayY:%{private}d", physicalDisplayInfo->rsId, logicalX, logicalY,
            physicalX, physicalY);
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN || (mouseDownInfo_.id == -1 &&
            axisBeginWindowInfo_ == std::nullopt)) {
            MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
            if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState() &&
                IsMouseDrawing(pointerEvent->GetPointerAction()) &&
                pointerItem.GetMoveFlag() != POINTER_MOVEFLAG) {
                    MMI_HILOGD("Turn the mouseDisplay from false to true");
                    CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
            }
            int64_t beginTime = GetSysClockTime();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
            if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_HIDE_POINTER) &&
            pointerItem.GetMoveFlag() == POINTER_MOVEFLAG) {
                CursorDrawingComponent::GetInstance().SetMouseDisplayState(false);
            } else {
                CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
            }
            if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
                if (GetHardCursorEnabled()) {
                    std::vector<int32_t> cursorPos = HandleHardwareCursor(physicalDisplayInfo, physicalX, physicalY);
                    CHKFR((cursorPos.size() >= CURSOR_POSITION_EXPECTED_SIZE), RET_ERR, "cursorPos is invalid");
                    CursorDrawingComponent::GetInstance().DrawMovePointer(physicalDisplayInfo->rsId,
                        cursorPos[0], cursorPos[1]);
                } else {
                    CursorDrawingComponent::GetInstance().DrawMovePointer(physicalDisplayInfo->rsId,
                        physicalX, physicalY);
                }
            }
            MMI_HILOGI("UpdateMouseTarget id:%{public}" PRIu64 ", logicalX:%{private}d, logicalY:%{private}d,"
                "displayX:%{private}d, displayY:%{private}d", physicalDisplayInfo->rsId, logicalX, logicalY,
                physicalX, physicalY);
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
            int64_t timeDT = GetTimeToMilli(GetSysClockTime() - pointerEvent->GetActionTime());
            if (timeDT > SIMULATE_EVENT_LATENCY) {
                MMI_HILOGI("Not touchWindow simulate event latency, pointerId:%{public}d, timeDT:%{public}" PRId64,
                    pointerEvent->GetId(), timeDT);
                DfxHisyseventDevice::ReportSimulateToRsLatecyBehavior(pointerEvent->GetId(), timeDT);
            }
#endif
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
            int64_t endTime = GetSysClockTime();
            if ((endTime - beginTime) > RS_PROCESS_TIMEOUT) {
                MMI_HILOGW("Rs process timeout");
            }
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
                dragFlag_ = false;
                isDragBorder_ = false;
            }
            return RET_ERR;
        }
        if (mouseDownInfo_.id != -1) {
            touchWindow = std::make_optional(mouseDownInfo_);
        } else if (axisBeginWindowInfo_) {
            touchWindow = axisBeginWindowInfo_;
        }
        int32_t pointerAction = pointerEvent->GetPointerAction();
        if (IsAccessibilityFocusEvent(pointerEvent)) {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_CANCEL);
        } else {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        }
        pointerEvent->SetOriginPointerAction(pointerAction);
        MMI_HILOGI("Mouse event send cancel, window:%{public}d, pid:%{public}d", touchWindow->id, touchWindow->pid);
    }

    bool checkFlag = pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_UPDATE ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END;
    if (checkFlag) {
        int32_t focusWindowId = GetFocusWindowId(groupId);
        if ((!GetHoverScrollState()) && (focusWindowId != touchWindow->id)) {
            MMI_HILOGD("disable mouse hover scroll in inactive window, targetWindowId:%{public}d", touchWindow->id);
            return RET_OK;
        }
    }
    PointerStyle pointerStyle;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        if (timerId_ != DEFAULT_VALUE) {
            TimerMgr->RemoveTimer(timerId_);
            timerId_ = DEFAULT_VALUE;
        }
        if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState() &&
            IsMouseDrawing(pointerEvent->GetPointerAction()) &&
            pointerItem.GetMoveFlag() != POINTER_MOVEFLAG) {
            MMI_HILOGD("Turn the mouseDisplay from false to true");
            CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
            DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
        }
        pointerStyle = CursorDrawingComponent::GetInstance().GetLastMouseStyle();
        MMI_HILOGD("showing the lastMouseStyle %{public}d, lastPointerStyle %{public}d",
            pointerStyle.id, lastPointerStyle_.id);
        CursorDrawingComponent::GetInstance().UpdateDisplayInfo(*physicalDisplayInfo);
        WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
        CursorDrawingComponent::GetInstance().OnWindowInfo(info);
    } else {
        if (timerId_ != DEFAULT_VALUE) {
            TimerMgr->RemoveTimer(timerId_);
            timerId_ = DEFAULT_VALUE;
        }
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
        if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState() &&
            pointerItem.GetMoveFlag() != POINTER_MOVEFLAG) {
            CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
            DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
        }
        CursorDrawingComponent::GetInstance().UpdateDisplayInfo(*physicalDisplayInfo);
        WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
        CursorDrawingComponent::GetInstance().OnWindowInfo(info);
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_EMULATOR
    if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState() &&
        pointerItem.GetMoveFlag() != POINTER_MOVEFLAG) {
        CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
    }
#endif
    GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
    if (isUiExtension_ && uiExtensionWindowId_ == touchWindow->id) {
        MMI_HILOGD("updatemouse target in uiextension");
        GetPointerStyle(uiExtensionPid_, uiExtensionWindowId_, pointerStyle, isUiExtension_);
        dragPointerStyle_ = pointerStyle;
    } else {
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
    }
    if (!isDragBorder_ && !isUiExtension_) {
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
        dragPointerStyle_ = pointerStyle;
    }
    WindowInfo window = *touchWindow;
    if (!dragFlag_) {
        isDragBorder_ = SelectPointerChangeArea(window, pointerStyle, logicalX, logicalY);
        dragPointerStyle_ = pointerStyle;
        MMI_HILOGD("pointerStyle is :%{public}d, windowId is :%{public}d, logicalX is :%{private}d,"
            "logicalY is :%{private}d", pointerStyle.id, window.id, logicalX, logicalY);
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        SetMouseFlag(true);
        dragFlag_ = true;
        MMI_HILOGD("Is in drag scene");
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
        SetMouseFlag(false);
        dragFlag_ = false;
        isDragBorder_ = false;
    }
    Direction direction = DIRECTION0;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = GetDisplayDirection(physicalDisplayInfo);
#ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
        TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(direction, physicalDisplayInfo->validWidth,
            physicalDisplayInfo->validHeight, physicalX, physicalY);
#endif // #ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_POINTER_VELOCITY_TRACKER->MonitorCursorMovement(pointerEvent);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    int64_t beginTime = GetSysClockTime();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (IsMouseDrawing(pointerEvent->GetPointerAction()) &&
        (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY))) {
        if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_HIDE_POINTER) ||
            pointerItem.GetMoveFlag() == POINTER_MOVEFLAG) {
            CursorDrawingComponent::GetInstance().SetMouseDisplayState(false);
        } else {
            CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
        }
        if (extraData_.drawCursor && pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_BUTTON_UP) {
            MMI_HILOGD("Cursor must be default, pointerStyle:%{public}d globalStyle:%{public}d",
                dragPointerStyle_.id, globalStyle_.id);
            dragPointerStyle_ = globalStyle_;
        }
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        int64_t timeDT = GetTimeToMilli(GetSysClockTime() - pointerEvent->GetActionTime());
        if (timeDT > SIMULATE_EVENT_LATENCY) {
            MMI_HILOGI("simulate event latency, pointerId:%{public}d, timeDT:%{public}" PRId64,
                pointerEvent->GetId(), timeDT);
            DfxHisyseventDevice::ReportSimulateToRsLatecyBehavior(pointerEvent->GetId(), timeDT);
        }
#endif
        CursorDrawingComponent::GetInstance().DrawPointer(physicalDisplayInfo->rsId, physicalX, physicalY,
            dragPointerStyle_, direction);
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

    auto iter = cursorPosMap_.find(groupId);
    if (iter != cursorPosMap_.end()) {
        cursorPosMap_[groupId].direction = physicalDisplayInfo->direction;
        cursorPosMap_[groupId].displayDirection = physicalDisplayInfo->displayDirection;
    }
    int64_t endTime = GetSysClockTime();
    if ((endTime - beginTime) > RS_PROCESS_TIMEOUT) {
        MMI_HILOGW("Rs process timeout");
    }

    auto itr = captureModeInfoMap_.find(groupId);
    if (itr != captureModeInfoMap_.end()) {
        if (itr->second.isCaptureMode&& (touchWindow->id != itr->second.windowId)) {
            captureModeInfoMap_[groupId].isCaptureMode = false;
        }
    }
    SetPrivacyModeFlag(touchWindow->privacyMode, pointerEvent);
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    UpdateWindowInfoFlag(touchWindow->flags, pointerEvent);
    DispatchUIExtentionPointerEvent(logicalX, logicalY, pointerEvent);
    double windowX = logicalX - touchWindow->area.x;
    double windowY = logicalY - touchWindow->area.y;
    if (!(touchWindow->transform.empty())) {
        auto windowXY = TransformWindowXY(*touchWindow, logicalX, logicalY);
    }
    pointerItem.SetWindowX(static_cast<int32_t>(windowX));
    pointerItem.SetWindowY(static_cast<int32_t>(windowY));
    pointerItem.SetWindowXPos(windowX);
    pointerItem.SetWindowYPos(windowY);
    pointerItem.SetGlobalX(logicalX);
    pointerItem.SetGlobalY(logicalY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    if ((extraData_.appended && (extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE)) ||
        (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP)) {
        pointerEvent->SetBuffer(extraData_.buffer);
        pointerEvent->SetPullId(extraData_.pullId);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    CHKPR(udsServer_, ERROR_NULL_POINTER);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    UpdatePointerEvent(logicalX, logicalY, pointerEvent, *touchWindow);
#elif defined(OHOS_BUILD_EMULATOR)
    if (CursorDrawingComponent::GetInstance().GetMouseDisplayState()) {
        UpdatePointerEvent(logicalX, logicalY, pointerEvent, *touchWindow);
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (touchWindow && IsInAncoWindow(*touchWindow, logicalX, logicalY)) {
        MMI_HILOGD("Process mouse event in Anco window, targetWindowId:%{public}d", touchWindow->id);
        pointerEvent->SetAncoDeal(true);
        SimulatePointerExt(pointerEvent);
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    int32_t action = pointerEvent->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        mouseDownInfo_ = *touchWindow;
        mouseDownEventId_ = pointerEvent->GetId();
    }
    if ((action == PointerEvent::POINTER_ACTION_MOVE && !pointerEvent->GetPressedButtons().empty()) ||
        (action == PointerEvent::POINTER_ACTION_BUTTON_UP)) {
        if (touchWindow->id != mouseDownInfo_.id) {
            MMI_HILOGE("Mouse from:%{public}d move to new window:%{public}d", mouseDownInfo_.id, touchWindow->id);
        }
    }
    if (action == PointerEvent::POINTER_ACTION_BUTTON_UP) {
        mouseDownEventId_ = -1;
        MMI_HILOGD("Mouse up, clear mouse down info");
    }
    if (action == PointerEvent::POINTER_ACTION_CANCEL && mouseDownEventId_ > 0) {
        mouseDownEventId_ = -1;
    }
    if (action == PointerEvent::POINTER_ACTION_AXIS_END) {
        axisBeginWindowInfo_ = std::nullopt;
        MMI_HILOGD("Axis end, clear axis begin info");
    }
    if (EventLogHelper::IsBetaVersion() && !pointerEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        MMI_HILOGD("pid:%{public}d, id:%{public}d, agentWindowId:%{public}d,"
            "logicalX:%{private}d, logicalY:%{private}d,"
            "displayX:%{private}d, displayY:%{private}d, windowX:%{private}d, windowY:%{private}d",
            isUiExtension_ ? uiExtensionPid_ : touchWindow->pid, isUiExtension_ ? uiExtensionWindowId_ :
            touchWindow->id, touchWindow->agentWindowId, logicalX, logicalY,
            pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), pointerItem.GetWindowX(), pointerItem.GetWindowY());
    } else {
        MMI_HILOGD("pid:%{public}d, id:%{public}d, agentWindowId:%{public}d,"
            "logicalX:%d, logicalY:%d,displayX:%d, displayY:%d, windowX:%d, windowY:%d",
            isUiExtension_ ? uiExtensionPid_ : touchWindow->pid, isUiExtension_ ? uiExtensionWindowId_ :
            touchWindow->id, touchWindow->agentWindowId, logicalX, logicalY,
            pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), pointerItem.GetWindowX(), pointerItem.GetWindowY());
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        MMI_HILOGD("Clear extra data");
        InitMouseDownInfo();
        mouseDownEventId_ = -1;
        ClearExtraData();
    }
    if (pointerItem.GetMoveFlag() == POINTER_MOVEFLAG) {
        CursorDrawingComponent::GetInstance().SetMouseDisplayState(false);
    }
    return ERR_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

bool InputWindowsManager::IsMouseDrawing(int32_t currentAction)
{
    if (currentAction != PointerEvent::POINTER_ACTION_LEAVE_WINDOW &&
        currentAction != PointerEvent::POINTER_ACTION_ENTER_WINDOW &&
        currentAction != PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW &&
        currentAction != PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) {
        return true;
    }
    return false;
}

void InputWindowsManager::SetMouseFlag(bool state)
{
    mouseFlag_ = state;
}

bool InputWindowsManager::GetMouseFlag()
{
    return mouseFlag_;
}

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::JudgMouseIsDownOrUp(bool dragState)
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    CHKPV(lastPointerEventCopy);
    if (!dragState && (lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP ||
        pointerActionFlag_ == PointerEvent::POINTER_ACTION_BUTTON_DOWN)) {
        SetMouseFlag(true);
        return;
    }
    if (lastPointerEventCopy->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        SetMouseFlag(true);
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t InputWindowsManager::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    CALL_DEBUG_ENTER;
    if (windowId < 0) {
        MMI_HILOGE("Windowid(%{public}d) is invalid", windowId);
        return RET_ERR;
    }
    auto itr = captureModeInfoMap_.find(MAIN_GROUPID);
    if (itr != captureModeInfoMap_.end()) {
        if (itr->second.isCaptureMode == isCaptureMode && !isCaptureMode) {
            MMI_HILOGE("Windowid:(%{public}d) is not capture mode", windowId);
            return RET_OK;
        }
        captureModeInfoMap_[MAIN_GROUPID].windowId = windowId;
        captureModeInfoMap_[MAIN_GROUPID].isCaptureMode = isCaptureMode;
    }
    MMI_HILOGI("Windowid:(%{public}d) is (%{public}d)", windowId, isCaptureMode);
    return RET_OK;
}

bool InputWindowsManager::GetMouseIsCaptureMode() const
{
    CALL_DEBUG_ENTER;
    auto itr = captureModeInfoMap_.find(MAIN_GROUPID);
    if (itr != captureModeInfoMap_.end()) {
        return itr->second.isCaptureMode;
    }
    return false;
}

bool InputWindowsManager::IsWritePen(PointerEvent::PointerItem &pointerItem) const
{
    if (pointerItem.GetToolType() != PointerEvent::TOOL_TYPE_PEN) {
        return false;
    }
    return !IsWriteTablet(pointerItem);
}

bool InputWindowsManager::IsWriteTablet(PointerEvent::PointerItem &pointerItem) const
{
    if (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN) {
        static int32_t lastDeviceId = -1;
        static std::shared_ptr<InputDevice> inputDevice = nullptr;
        auto nowId = pointerItem.GetDeviceId();
        if (lastDeviceId != nowId) {
            inputDevice = INPUT_DEV_MGR->GetInputDevice(nowId);
            CHKPF(inputDevice);
            lastDeviceId = nowId;
        }
        if (inputDevice != nullptr) {
            MMI_HILOGD("name:%{public}s type:%{public}d bus:%{public}d, "
                "version:%{public}d product:%{public}d vendor:%{public}d, "
                "phys:%{public}s uniq:%{public}s",
                inputDevice->GetName().c_str(), inputDevice->GetType(), inputDevice->GetBus(),
                inputDevice->GetVersion(), inputDevice->GetProduct(), inputDevice->GetVendor(),
                inputDevice->GetPhys().c_str(), inputDevice->GetUniq().c_str());
        }
        if (inputDevice != nullptr && inputDevice->GetBus() == BUS_USB) {
            return true;
        }
    }
    return false;
}

bool InputWindowsManager::IsNeedDrawPointer(PointerEvent::PointerItem &pointerItem) const
{
    return IsWriteTablet(pointerItem);
}

bool InputWindowsManager::SkipPrivacyProtectionWindow(const std::shared_ptr<PointerEvent>& pointerEvent,
    const bool &isSkip)
{
    CHKPF(pointerEvent);
    if (pointerEvent->GetDeviceId() == CAST_INPUT_DEVICEID ||
        pointerEvent->GetDeviceId() == CAST_SCREEN_DEVICEID) {
        if (!isOpenPrivacyProtectionserver_) {
            privacyProtection_.switchName = BUNDLE_NAME_PARSER.GetBundleName("PRIVACY_SWITCH_NAME");;
            CreatePrivacyProtectionObserver(privacyProtection_);
            isOpenPrivacyProtectionserver_ = true;
            SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(NAVIGATION_SWITCH_NAME,
                antiMistake_.isOpen);
            MMI_HILOGD("Get privacy protection switch end");
        }
        if (privacyProtection_.isOpen && isSkip) {
            MMI_HILOGD("It's a Privacy protection window and pointer find the next window");
            return true;
        }
    }
    return false;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
bool InputWindowsManager::SkipAnnotationWindow(uint32_t flag, int32_t toolType)
{
    return ((flag & WindowInfo::FLAG_BIT_HANDWRITING) == WindowInfo::FLAG_BIT_HANDWRITING &&
            toolType == PointerEvent::TOOL_TYPE_FINGER);
}

bool InputWindowsManager::SkipNavigationWindow(WindowInputType windowType, int32_t toolType)
{
    MMI_HILOGD("windowType:%{public}d, toolType:%{public}d", static_cast<int32_t>(windowType), toolType);
    if ((windowType != WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE &&
        windowType != WindowInputType::DUALTRIGGER_TOUCH &&
        windowType != WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE) || toolType != PointerEvent::TOOL_TYPE_PEN) {
        return false;
    }
    if (!isOpenAntiMisTakeObserver_) {
        antiMistake_.switchName = NAVIGATION_SWITCH_NAME;
        CreateAntiMisTakeObserver(antiMistake_);
        isOpenAntiMisTakeObserver_ = true;
        MMI_HILOGI("Get anti mistake touch switch start");
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(NAVIGATION_SWITCH_NAME,
            antiMistake_.isOpen);
        MMI_HILOGI("Get anti mistake touch switch end");
    }
    if (antiMistake_.isOpen) {
        MMI_HILOGI("Anti mistake switch is open");
        return true;
    }
    return false;
}

void InputWindowsManager::GetUIExtentionWindowInfo(std::vector<WindowInfo> &uiExtentionWindowInfo, int32_t windowId,
    WindowInfo **touchWindow, bool &isUiExtentionWindow)
{
    auto iter = std::find_if(uiExtentionWindowInfo.begin(), uiExtentionWindowInfo.end(),
        [windowId](const auto &windowInfo) {
            return windowId == windowInfo.id;
        }
    );
    if (iter != uiExtentionWindowInfo.end()) {
        *touchWindow = &(*iter);
        isUiExtentionWindow = true;
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool InputWindowsManager::IsValidNavigationWindow(const WindowInfo& touchWindow, double physicalX, double physicalY)
{
    return (touchWindow.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE ||
            touchWindow.windowInputType == WindowInputType::DUALTRIGGER_TOUCH ||
            touchWindow.windowInputType == WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE) &&
            IsInHotArea(static_cast<int32_t>(physicalX), static_cast<int32_t>(physicalY),
            touchWindow.defaultHotAreas, touchWindow);
}

bool InputWindowsManager::IsNavigationWindowInjectEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    return (pointerEvent->GetZOrder() > 0 && pointerEvent->GetTargetWindowId() == -1);
}

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
void InputWindowsManager::UpdateDisplayXYInOneHandMode(double &physicalX, double &physicalY,
    const OLD::DisplayInfo &displayInfo, float oneHandScale)
{
    double virtualY = physicalY - displayInfo.oneHandY;
    double virtualX = physicalX - displayInfo.oneHandX;

    if (oneHandScale == 0) {
        MMI_HILOGE("The divisor cannot be 0");
        return;
    }
    physicalX = virtualX / oneHandScale;
    physicalY = virtualY / oneHandScale;
}

void InputWindowsManager::HandleOneHandMode(const OLD::DisplayInfo &displayInfo,
    std::shared_ptr<PointerEvent> &pointerEvent, PointerEvent::PointerItem &pointerItem)
{
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    MMI_HILOG_DISPATCHD("displayInfo.oneHandX=%{private}d, displayInfo.oneHandY=%{private}d, "
        "expandHeight=%{public}d,scalePercent=%{public}d, fixedModeStr=%{public}s",
        displayInfo.oneHandX, displayInfo.oneHandY, displayInfo.expandHeight, displayInfo.scalePercent,
        pointerEvent->GetFixedModeStr().c_str());
    double fixedDisplayX = pointerItem.GetDisplayXPos();
    double fixedDisplayY = pointerItem.GetDisplayYPos();
    float oneHandScale = displayInfo.scalePercent * 1.0 / 100;
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        bool autoToVirtualScreen = pointerEvent->GetAutoToVirtualScreen();
        MMI_HILOG_DISPATCHD("autoToVirtualScreen=%{public}s", autoToVirtualScreen ? "true" : "false");
        if (autoToVirtualScreen) {
            UpdateDisplayXYInOneHandMode(fixedDisplayX, fixedDisplayY, displayInfo, oneHandScale);
        }
    } else {
        UpdateDisplayXYInOneHandMode(fixedDisplayX, fixedDisplayY, displayInfo, oneHandScale);
    }
    pointerItem.SetFixedDisplayXPos(fixedDisplayX);
    pointerItem.SetFixedDisplayYPos(fixedDisplayY);
}

void InputWindowsManager::UpdatePointerItemInOneHandMode(const OLD::DisplayInfo &displayInfo,
    std::shared_ptr<PointerEvent> &pointerEvent)
{
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    double physicalX = pointerItem.GetDisplayXPos();
    double physicalY = pointerItem.GetDisplayYPos();
    if (displayInfo.height == 0 || displayInfo.height == displayInfo.oneHandY) {
        MMI_HILOG_DISPATCHE("displayInfo.height=%{private}d, displayInfo.oneHandY=%{private}d is invalid",
            displayInfo.height, displayInfo.oneHandY);
        pointerEvent->SetFixedMode(PointerEvent::FixedMode::SCREEN_MODE_UNKNOWN);
        pointerItem.SetFixedDisplayXPos(physicalX);
        pointerItem.SetFixedDisplayYPos(physicalY);
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
        return;
    }
    if (displayInfo.scalePercent > 0 && displayInfo.scalePercent < 100) {
        HandleOneHandMode(displayInfo, pointerEvent, pointerItem);
    } else {
        pointerEvent->SetFixedMode(PointerEvent::FixedMode::NORMAL);
        pointerItem.SetFixedDisplayXPos(physicalX);
        pointerItem.SetFixedDisplayYPos(physicalY);
        MMI_HILOG_DISPATCHD("displayInfo.oneHandY=%{private}d, fixedModeStr=%{public}s",
            displayInfo.oneHandY, pointerEvent->GetFixedModeStr().c_str());
    }
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    MMI_HILOG_DISPATCHD("targetDisplayId:%{private}d, DXY:{%{private}d, %{private}d}, FDXY:{%{private}.5f, "
        "%{private}.5f}", pointerEvent->GetTargetDisplayId(), pointerItem.GetDisplayX(),
        pointerItem.GetDisplayY(), pointerItem.GetFixedDisplayXPos(), pointerItem.GetFixedDisplayYPos());
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

void InputWindowsManager::UpdateFixedXY(const OLD::DisplayInfo& displayInfo,
    std::shared_ptr<PointerEvent> &pointerEvent)
{
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
    UpdatePointerItemInOneHandMode(displayInfo, pointerEvent);
#else
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    pointerItem.SetFixedDisplayXPos(pointerItem.GetDisplayXPos());
    pointerItem.SetFixedDisplayYPos(pointerItem.GetDisplayYPos());
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE
}

void InputWindowsManager::UpdateTransformDisplayXY(std::shared_ptr<PointerEvent> pointerEvent,
    const std::vector<WindowInfo>& windowsInfo, const OLD::DisplayInfo& displayInfo)
{
    CHKPV(pointerEvent);
    bool isNavigationWindow = false;
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;

    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    double physicalX = pointerItem.GetDisplayXPos();
    double physicalY = pointerItem.GetDisplayYPos();

    for (auto &item : windowsInfo) {
        if (IsValidNavigationWindow(item, physicalX, physicalY) &&
            !pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE_NAVIGATION) && pointerEvent->GetZOrder() <= 0) {
            isNavigationWindow = true;
            break;
        }
    }
    if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY) ||
        pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE_NAVIGATION) ||
        IsNavigationWindowInjectEvent(pointerEvent)) {
        if (!displayInfo.transform.empty() &&
            ((pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_UP) ||
            pointerEvent->GetZOrder() > 0) && !isNavigationWindow) {
            auto displayXY = TransformDisplayXY(displayInfo, physicalX, physicalY);
            physicalX = displayXY.first;
            physicalY = displayXY.second;
        }
    }
    if (isNavigationWindow && pointerEvent->HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE_NAVIGATION);
    }

    pointerItem.SetDisplayX(static_cast<int32_t>(physicalX));
    pointerItem.SetDisplayY(static_cast<int32_t>(physicalY));
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({physicalX, physicalY}, pointerEvent->GetTargetDisplayId());
    pointerItem.SetGlobalX(globalCoords.x);
    pointerItem.SetGlobalY(globalCoords.y);
    pointerItem.SetDisplayXPos(physicalX);
    pointerItem.SetDisplayYPos(physicalY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    UpdateFixedXY(displayInfo, pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::SendUIExtentionPointerEvent(double logicalX, double logicalY,
    const WindowInfo& windowInfo, std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_HILOG_DISPATCHI("Dispatch uiExtention pointer Event,pid:%{public}d", windowInfo.pid);
    CHKPV(pointerEvent);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    double windowX = logicalX - windowInfo.area.x;
    double windowY = logicalY - windowInfo.area.y;
    if (!(windowInfo.transform.empty())) {
        auto windowXY = TransformWindowXY(windowInfo, logicalX, logicalY);
        windowX = windowXY.first;
        windowY = windowXY.second;
    }
    int32_t displayInfoX = GetLogicalPositionX(pointerEvent->GetTargetDisplayId());
    int32_t displayInfoY = GetLogicalPositionY(pointerEvent->GetTargetDisplayId());
    double physicalX = logicalX - displayInfoX;
    double physicalY = logicalY - displayInfoY;
    pointerItem.SetDisplayX(static_cast<int32_t>(physicalX));
    pointerItem.SetDisplayY(static_cast<int32_t>(physicalY));
    GlobalCoords globalCoords = DisplayCoords2GlobalCoords({physicalX, physicalY}, pointerEvent->GetTargetDisplayId());
    pointerItem.SetGlobalX(globalCoords.x);
    pointerItem.SetGlobalY(globalCoords.y);
    pointerItem.SetDisplayXPos(physicalX);
    pointerItem.SetDisplayYPos(physicalY);
    pointerItem.SetWindowX(static_cast<int32_t>(windowX));
    pointerItem.SetWindowY(static_cast<int32_t>(windowY));
    pointerItem.SetWindowXPos(windowX);
    pointerItem.SetWindowYPos(windowY);
    pointerItem.SetTargetWindowId(windowInfo.id);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    CHKPV(udsServer_);
    auto fd = udsServer_->GetClientFd(windowInfo.agentPid);
    auto sess = udsServer_->GetSession(fd);
    CHKPRV(sess, "The window has disappeared");
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void InputWindowsManager::DispatchUIExtentionPointerEvent(double logicalX, double logicalY,
    std::shared_ptr<PointerEvent> pointerEvent)
{
    auto displayId = pointerEvent->GetTargetDisplayId();
    const std::vector<WindowInfo> &windowsInfo = GetWindowGroupInfoByDisplayId(displayId);
    auto windowId = pointerEvent->GetTargetWindowId();
    for (const auto& item : windowsInfo) {
        if (windowId == item.id) {
            return;
        }
        for (const auto& windowInfo : item.uiExtentionWindowInfo) {
            if (windowInfo.id == windowId) {
                MMI_HILOG_DISPATCHI("Dispatch uiExtention pointer Event,windowId:%{public}d", item.id);
                // If the event is sent to the security sub window, then a copy needs to be sent to the host window
                pointerEvent->SetAgentWindowId(item.agentWindowId);
                pointerEvent->SetTargetWindowId(item.id);
                SendUIExtentionPointerEvent(logicalX, logicalY, item, pointerEvent);
                pointerEvent->SetAgentWindowId(windowInfo.agentWindowId);
                pointerEvent->SetTargetWindowId(windowInfo.id);
                return;
            }
        }
    }
}

#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputWindowsManager::HandleGestureInjection(bool gestureInject) {
    if (!gestureInject) {
        CursorDrawingComponent::GetInstance().SetMouseDisplayState(false);
    }
}

void InputWindowsManager::ProcessInjectEventGlobalXY(std::shared_ptr<PointerEvent> pointerEvent, int32_t useCoordinate)
{
    if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        return;
    }
    if (useCoordinate != PointerEvent::GLOBAL_COORDINATE) {
        return;
    }
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;

    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    double globalX = pointerItem.GetGlobalX();
    double globalY = pointerItem.GetGlobalY();
    if (globalX == DBL_MAX || globalY == DBL_MAX) {
        return;
    }
    const auto& mainGroup = GetDefaultDisplayGroupInfo();
    for (const auto& display : mainGroup.displaysInfo) {
        if (globalX >= display.x && globalX <= display.x + display.width &&
            globalY >= display.y && globalY <= display.y + display.height) {
            pointerEvent->SetTargetDisplayId(display.id);
            pointerItem.SetDisplayX(static_cast<int32_t>(globalX - display.x));
            pointerItem.SetDisplayY(static_cast<int32_t>(globalY - display.y));
            pointerItem.SetDisplayXPos(globalX - display.x);
            pointerItem.SetDisplayYPos(globalY - display.y);
            pointerEvent->UpdatePointerItem(pointerId, pointerItem);
            return;
        }
    }
}

int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    RemoveActiveWindow(pointerEvent);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
        MMI_HILOG_DISPATCHD("Abort UpdateTouchScreenTarget due to POINTER_ACTION_CANCEL");
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOG_DISPATCHE("This display is not existent");
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);
    int32_t groupId = FindDisplayGroupId(displayId);
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPR(physicDisplayInfo, ERROR_NULL_POINTER);
    const std::vector<WindowInfo> &windowsInfo = GetWindowGroupInfoByDisplayId(displayId);
    UpdateTransformDisplayXY(pointerEvent, windowsInfo, *physicDisplayInfo);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    double physicalX = pointerItem.GetDisplayXPos();
    double physicalY = pointerItem.GetDisplayYPos();

    if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) &&
        (INPUT_DEV_MGR->GetVendorConfig(pointerEvent->GetDeviceId()).enableOutScreen != ENABLE_OUT_SCREEN_TOUCH)) {
        AdjustDisplayCoordinate(*physicDisplayInfo, physicalX, physicalY);
    }
    int32_t logicalX1 = 0;
    int32_t logicalY1 = 0;

    int32_t displayInfoX = GetLogicalPositionX(displayId);
    int32_t displayInfoY = GetLogicalPositionY(displayId);
    if (!AddInt32(static_cast<int32_t>(physicalX), displayInfoX, logicalX1)) {
        MMI_HILOG_DISPATCHE("The addition of logicalX overflows");
        return RET_ERR;
    }
    if (!AddInt32(static_cast<int32_t>(physicalY), displayInfoY, logicalY1)) {
        MMI_HILOG_DISPATCHE("The addition of logicalY overflows");
        return RET_ERR;
    }
    double logicalX = physicalX + displayInfoX;
    double logicalY = physicalY + displayInfoY;
    const WindowInfo *touchWindow = nullptr;
    auto targetWindowId = (NeedTouchTracking(*pointerEvent)? GLOBAL_WINDOW_ID : pointerItem.GetTargetWindowId());
    bool isHotArea = false;
    bool isFirstSpecialWindow = false;
    static std::unordered_map<int32_t, WindowInfo> winMap;
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        ClearTargetWindowId(pointerId, pointerEvent->GetDeviceId());
        if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) && pointerEvent->GetPointerCount() == 1) {
            ClearActiveWindow();
        }
    }
    for (auto &item : windowsInfo) {
        bool checkWindow = (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
            !IsValidZorderWindow(item, pointerEvent);
        if (checkWindow) {
            MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching,"
                "window:%{public}d, flags:%{public}d", item.id, item.flags);
            winMap.insert({item.id, item});
            continue;
        }
        if (SkipPrivacyProtectionWindow(pointerEvent, item.isSkipSelfWhenShowOnVirtualScreen)) {
            winMap.insert({item.id, item});
            continue;
        }
        if (SkipAnnotationWindow(item.flags, pointerItem.GetToolType())) {
            winMap.insert({item.id, item});
            continue;
        }
        if (SkipNavigationWindow(item.windowInputType, pointerItem.GetToolType())) {
            winMap.insert({item.id, item});
            continue;
        }
        if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) && item.windowType == SCREEN_CONTROL_WINDOW_TYPE) {
            winMap.insert({item.id, item});
            continue;
        }
        if (IsAccessibilityEventWithZorderInjected(pointerEvent) && pointerEvent->GetZOrder() <= item.zOrder) {
            winMap.insert({item.id, item});
            continue;
        }

        bool checkToolType = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
            ((pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId) ||
            pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN);
        checkToolType = checkToolType || (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
        if (checkToolType) {
            MMI_HILOG_DISPATCHD("Enter checkToolType");
            if (transparentWins_.find(item.id) != transparentWins_.end()) {
                if (IsTransparentWin(transparentWins_[item.id], logicalX - item.area.x, logicalY - item.area.y)) {
                    MMI_HILOG_DISPATCHE("It's an abnormal window:%{public}d and touchscreen find the next window",
                        item.id);
                    winMap.insert({item.id, item});
                    continue;
                }
            }
            if (IsInHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
                item.defaultHotAreas, item)) {
                if (item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) {
                    continue;
                }
                UpdateTargetTouchWinIds(item, pointerItem, pointerEvent, pointerId, displayId,
                    pointerEvent->GetDeviceId());
                touchWindow = &item;
                break;
            } else {
                winMap.insert({item.id, item});
                continue;
            }
        }
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
        bool isSlidTouch = (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER  &&
            pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
            pointerEvent->GetAllPointerItems().size() == 1 && !checkToolType &&
            pointerEvent->GetFixedMode() == PointerEvent::FixedMode::AUTO) ||
            (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
        if (isSlidTouch && lockWindowInfo_.windowInputType == WindowInputType::SLID_TOUCH_WINDOW) {
            if (IsInHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
                item.defaultHotAreas, item)) {
                UpdateTargetTouchWinIds(item, pointerItem, pointerEvent, pointerId, displayId,
                    pointerEvent->GetDeviceId());
                touchWindow = &item;
                break;
            }
        }
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE
        if (targetWindowId >= 0 && pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
            (pointerItem.GetToolType() != PointerEvent::TOOL_TYPE_PEN || pointerItem.GetPressure() > 0)) {
            bool isUiExtentionWindow = false;
            for (auto &windowinfo : item.uiExtentionWindowInfo) {
                if (windowinfo.id == targetWindowId) {
                    touchWindow = &windowinfo;
                    isUiExtentionWindow = true;
                    break;
                }
            }
            if (isUiExtentionWindow) {
                break;
            }
            if (item.id == targetWindowId) {
                touchWindow = &item;
                break;
            }
        } else if (IsInHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
            item.defaultHotAreas, item)) {
            if (transparentWins_.find(item.id) != transparentWins_.end()) {
                if (IsTransparentWin(transparentWins_[item.id], logicalX - item.area.x, logicalY - item.area.y)) {
                    MMI_HILOG_DISPATCHE("It's an abnormal window:%{public}d and touchscreen find the next window",
                        item.id);
                    winMap.insert({item.id, item});
                    continue;
                }
            }
            touchWindow = &item;
            AddActiveWindow(touchWindow->id, pointerEvent->GetPointerId());
            bool isSpecialWindow = HandleWindowInputType(item, pointerEvent);
            if (!isFirstSpecialWindow) {
                isFirstSpecialWindow = isSpecialWindow;
                if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_PULL_MOVE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_HOVER_MOVE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
                    pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE) {
                    MMI_HILOG_DISPATCHD("the first special window status:%{public}d", isFirstSpecialWindow);
                }
            }
            std::pair<int32_t, int32_t> logicalXY(std::make_pair(static_cast<int32_t>(logicalX),
                static_cast<int32_t>(logicalY)));
            // Determine whether the landing point is a safety sub window
            CheckUIExtentionWindowDefaultHotArea(logicalXY, isHotArea, pointerEvent, item.uiExtentionWindowInfo,
                &touchWindow);
            if (isSpecialWindow) {
                AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id,
                    pointerEvent->GetDeviceId());
                isHotArea = true;
                continue;
            }
            break;
        } else {
            winMap.insert({item.id, item});
        }
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        std::ostringstream oss;
        for (auto iter = winMap.begin(); iter != winMap.end(); iter++) {
            oss << iter->first << "|" << iter->second.zOrder << "|";
            int32_t searchHotAreaCount = 0;
            int32_t searchHotAreaMaxCount = 4;
            for (auto &hotArea : iter->second.defaultHotAreas) {
                searchHotAreaCount++;
                oss << hotArea.x << "|" << hotArea.y << "|" << hotArea.width << "|" << hotArea.height << "|";
                if (searchHotAreaCount >= searchHotAreaMaxCount) {
                    break;
                }
            }
            oss << iter->second.pid << " ";
        }
        if (!oss.str().empty()) {
            MMI_HILOG_DISPATCHI("Pre search window %{public}d %{public}s", targetWindowId, oss.str().c_str());
        }
    }
    if (touchWindow == nullptr) {
        auto it = touchItemDownInfos_.find(pointerId);
        if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            if (it == touchItemDownInfos_.end() ||
                pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                int32_t originPointerAction = pointerEvent->GetPointerAction();
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
                pointerEvent->SetOriginPointerAction(originPointerAction);
                pointerItem.SetCanceled(true);
                pointerEvent->UpdatePointerItem(pointerId, pointerItem);
                MMI_HILOG_DISPATCHE("The touchWindow is nullptr, logicalX:%{private}f,"
                    "logicalY:%{private}f, pointerId:%{public}d", logicalX, logicalY, pointerId);
                return RET_ERR;
            }
        }
        touchWindow = &it->second.window;
        if (it->second.flag) {
            if (IsAccessibilityFocusEvent(pointerEvent)) {
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_CANCEL);
            } else {
                int32_t originPointerAction = pointerEvent->GetPointerAction();
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
                pointerEvent->SetOriginPointerAction(originPointerAction);
            }
            MMI_HILOG_DISPATCHI("Not found event down target window, maybe this window was untouchable,"
                "need send cancel event, windowId:%{public}d pointerId:%{public}d", touchWindow->id, pointerId);
        }
    }
    winMap.clear();
    UpdateWindowInfoFlag(touchWindow->flags, pointerEvent);
    ProcessTouchTracking(pointerEvent, *touchWindow);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
        lockWindowInfo_ = *touchWindow;
        MMI_HILOG_DISPATCHD("lockWid:%{public}d, lockPid:%{public}d", lockWindowInfo_.id, lockWindowInfo_.pid);
    }
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerItem.SetTargetWindowId(touchWindow->id);
#ifdef OHOS_BUILD_ENABLE_ANCO
    bool isInAnco = touchWindow && IsInAncoWindow(*touchWindow, logicalX, logicalY);
    if (isInAnco) {
        MMI_HILOG_DISPATCHD("Process touch screen event in Anco window, targetWindowId:%{public}d", touchWindow->id);
        std::set<int32_t> windowIds;
        GetTargetWindowIds(pointerId, pointerEvent->GetSourceType(), windowIds, pointerEvent->GetDeviceId());
        if (windowIds.size() <= 1) {
            pointerEvent->SetAncoDeal(true);
        } else {
            for (int32_t windowId : windowIds) {
                auto windowInfo = GetWindowAndDisplayInfo(windowId, pointerEvent->GetTargetDisplayId());
                if (!windowInfo) {
                    continue;
                }
                isFirstSpecialWindow = isFirstSpecialWindow || HandleWindowInputType(*windowInfo, pointerEvent);
            }
        }
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
        if (IsShouldSendToAnco(pointerEvent, isFirstSpecialWindow)) {
            SimulatePointerExt(pointerEvent);
            isFirstSpecialWindow = false;
        } else {
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                std::unordered_map<std::string, std::string> mapPayload;
                mapPayload["msg"] = "";
                constexpr int32_t touchDownBoost = 1006;
                auto begin = std::chrono::high_resolution_clock::now();
                OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
                    OHOS::ResourceSchedule::ResType::RES_TYPE_SOCPERF_CUST_ACTION, touchDownBoost, mapPayload);
                auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
                DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::RESOURCE_SCHEDULE_REPORT_DATA,
                    durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
            } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
                constexpr int32_t touchUpBoost = 1007;
                std::unordered_map<std::string, std::string> mapPayload;
                mapPayload["msg"] = "";
                auto begin = std::chrono::high_resolution_clock::now();
                OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
                    OHOS::ResourceSchedule::ResType::RES_TYPE_SOCPERF_CUST_ACTION, touchUpBoost, mapPayload);
                auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
                DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::RESOURCE_SCHEDULE_REPORT_DATA,
                    durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
            }
        }
        int32_t focusWindowId = GetFocusWindowId(groupId);
        if (focusWindowId == touchWindow->id) {
            pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
            return RET_OK;
        }
        pointerEvent->SetAncoDeal(false);
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    if (touchWindow->windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            lastTouchEventOnBackGesture_ = std::make_shared<PointerEvent>(*pointerEvent);
        }
        if (lastTouchEventOnBackGesture_ != nullptr &&
            lastTouchEventOnBackGesture_->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL) {
            lastTouchEventOnBackGesture_ = std::make_shared<PointerEvent>(*pointerEvent);
        }
    }
    double windowX = logicalX - touchWindow->area.x;
    double windowY = logicalY - touchWindow->area.y;
    if (!(touchWindow->transform.empty())) {
        auto windowXY = TransformWindowXY(*touchWindow, logicalX, logicalY);
        windowX = windowXY.first;
        windowY = windowXY.second;
    }
    SetPrivacyModeFlag(touchWindow->privacyMode, pointerEvent);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    DispatchUIExtentionPointerEvent(logicalX, logicalY, pointerEvent);
    pointerItem.SetDisplayX(static_cast<int32_t>(physicalX));
    pointerItem.SetDisplayY(static_cast<int32_t>(physicalY));
    pointerItem.SetGlobalX(physicalX + physicDisplayInfo->x);
    pointerItem.SetGlobalY(physicalY + physicDisplayInfo->y);
    pointerItem.SetWindowX(static_cast<int32_t>(windowX));
    pointerItem.SetWindowY(static_cast<int32_t>(windowY));
    pointerItem.SetDisplayXPos(physicalX);
    pointerItem.SetDisplayYPos(physicalY);
    pointerItem.SetWindowXPos(windowX);
    pointerItem.SetWindowYPos(windowY);
    pointerItem.SetToolWindowX(pointerItem.GetToolDisplayX() + physicDisplayInfo->x - touchWindow->area.x);
    pointerItem.SetToolWindowY(pointerItem.GetToolDisplayY() + physicDisplayInfo->y - touchWindow->area.y);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    if (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_THP_FEATURE) {
        return ERR_OK;
    }
    bool checkExtraData = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
        ((pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId) ||
        pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN);
    checkExtraData = checkExtraData || (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
    int32_t pointerAction = pointerEvent->GetPointerAction();
    if ((pointerAction == PointerEvent::POINTER_ACTION_DOWN) && !checkExtraData) {
        lastTouchLogicX_ = logicalX;
        lastTouchLogicY_ = logicalY;
        lastTouchEvent_ = pointerEvent;
        lastTouchWindowInfo_ = *touchWindow;
    }
    if (checkExtraData) {
        pointerEvent->SetBuffer(extraData_.buffer);
        pointerEvent->SetPullId(extraData_.pullId);
        UpdatePointerAction(pointerEvent);
        if (pointerAction != PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW &&
            pointerAction != PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) {
            PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, touchWindow);
        }
    }
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
    bool isSlidData = (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER  &&
        pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
        pointerEvent->GetAllPointerItems().size() == 1 && !checkExtraData &&
        pointerEvent->GetFixedMode() == PointerEvent::FixedMode::AUTO) ||
        (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
    if (isSlidData) {
        TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, touchWindow);
    }
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE
    isFoldPC_ = PRODUCT_TYPE_HYM == DEVICE_TYPE_FOLD_PC;
    if (isFoldPC_ && pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullUpEvent(pointerEvent);
    }
    // pointerAction:PA, targetWindowId:TWI, foucsWindowId:FWI, eventId:EID,
    // logicalX:LX, logicalY:LY, displayX:DX, displayX:DY, windowX:WX, windowY:WY,
    // width:W, height:H, area.x:AX, area.y:AY, displayId:DID, AgentWindowId: AWI
    if ((pointerAction != PointerEvent::POINTER_ACTION_MOVE &&
        pointerAction != PointerEvent::POINTER_ACTION_PULL_MOVE &&
        pointerAction != PointerEvent::POINTER_ACTION_HOVER_MOVE &&
        pointerAction != PointerEvent::POINTER_ACTION_AXIS_UPDATE &&
        pointerAction != PointerEvent::POINTER_ACTION_SWIPE_UPDATE &&
        pointerAction != PointerEvent::POINTER_ACTION_ROTATE_UPDATE &&
        pointerAction != PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE)) {
        int32_t focusWindowId = GetFocusWindowId(groupId);
        if (!EventLogHelper::IsBetaVersion()) {
            MMI_HILOG_FREEZEI("PA:%{public}s,Pid:%{public}d,TWI:%{public}d,"
                "FWI:%{public}d,EID:%{public}d, flags:%{public}d,DID:%{public}d"
                "AWI:%{public}d,zOrder:%{public}1f",
                pointerEvent->DumpPointerAction(), touchWindow->pid, touchWindow->id,
                focusWindowId, pointerEvent->GetId(), touchWindow->flags,
                displayId, pointerEvent->GetAgentWindowId(), touchWindow->zOrder);
        } else {
            MMI_HILOGD("PA:%{public}s,LX:%{private}1f,LY:%{private}1f,"
                "DX:%{private}1f,DY:%{private}1f,WX:%{private}1f,WY:%{private}1f,"
                "AX:%{private}d,AY:%{private}d,flags:%{public}d,",
                pointerEvent->DumpPointerAction(), logicalX, logicalY, physicalX, physicalY,
                windowX, windowY, touchWindow->area.x, touchWindow->area.y, touchWindow->flags);
            MMI_HILOG_FREEZEI("%{public}d|%{public}d|%{public}d|%{public}d|%{public}d|"
                "%{public}d|%{public}d|%{public}1f",
                touchWindow->pid, touchWindow->id, focusWindowId,
                touchWindow->area.width, touchWindow->area.height, displayId,
                pointerEvent->GetAgentWindowId(), touchWindow->zOrder);
        }
    }
    bool gestureInject = false;
    if ((pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) && MMI_GNE(pointerEvent->GetZOrder(), 0.0f)) {
        gestureInject = true;
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && (defined(OHOS_BUILD_ENABLE_POINTER_DRAWING) || defined(OHOS_BUILD_EMULATOR))
    if (IsNeedDrawPointer(pointerItem)) {
        if (!CursorDrawingComponent::GetInstance().GetMouseDisplayState()) {
            CursorDrawingComponent::GetInstance().SetMouseDisplayState(true);
            if (touchWindow->id != lastWindowInfo_.id) {
                lastWindowInfo_ = *touchWindow;
            }
            DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
        }
        PointerStyle pointerStyle;
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
        CursorDrawingComponent::GetInstance().UpdateDisplayInfo(*physicDisplayInfo);
        WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
        CursorDrawingComponent::GetInstance().OnWindowInfo(info);
        auto displayInfo = GetPhysicalDisplay(displayId);
        CHKPR(displayInfo, RET_ERR);
        Coordinate2D cursorPos = {};
        ReverseRotateDisplayScreen(*displayInfo,  pointerItem.GetDisplayXPos(), pointerItem.GetDisplayYPos(),
            cursorPos);
        CursorDrawingComponent::GetInstance().DrawPointer(physicDisplayInfo->rsId, static_cast<int32_t>(cursorPos.x),
            static_cast<int32_t>(cursorPos.y), pointerStyle, physicDisplayInfo->direction);
    } else if (CursorDrawingComponent::GetInstance().GetMouseDisplayState()) {
        if ((!checkExtraData) && (!(extraData_.appended &&
            extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE))) {
            MMI_HILOG_DISPATCHD("PointerAction is to leave the window");
            if (!pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SHOW_CUSOR_WITH_TOUCH) && timerId_ == DEFAULT_VALUE) {
                timerId_ = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE, [this, gestureInject]() {
                    DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
                    HandleGestureInjection(gestureInject);
                    timerId_ = DEFAULT_VALUE;
                }, "InputWindowsManager");
            }
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t curGroupId = FindDisplayGroupId(pointerEvent->GetTargetDisplayId());
    lastPointerEventforWindowChangeMap_[curGroupId] = pointerEvent;
    lastPointerEventforGesture_ = pointerEvent;
    pointerAction = pointerEvent->GetPointerAction();
    if (pointerAction == PointerEvent::POINTER_ACTION_DOWN ||
        pointerAction == PointerEvent::POINTER_ACTION_HOVER_ENTER) {
        WindowInfoEX windowInfoEX;
        windowInfoEX.window = *touchWindow;
        windowInfoEX.flag = true;
        touchItemDownInfos_[pointerId] = windowInfoEX;
        MMI_HILOGD("PointerId:%{public}d, touchWindow:%{public}d", pointerId, touchWindow->id);
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        MMI_HILOG_DISPATCHD("Clear extra data");
        pointerEvent->ClearBuffer();
        lastTouchEvent_ = nullptr;
        lastTouchWindowInfo_.id = -1;
        ClearExtraData();
    }
    return ERR_OK;
}

void InputWindowsManager::UpdateTargetTouchWinIds(const WindowInfo &item, PointerEvent::PointerItem &pointerItem,
    std::shared_ptr<PointerEvent> pointerEvent, int32_t pointerId, int32_t displayId, int32_t deviceId) {
    if (item.windowInputType != WindowInputType::TRANSMIT_ALL) {
        if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
            return;
        }
        WIN_MGR->GetTargetWindowIds(pointerItem.GetPointerId(), pointerEvent->GetSourceType(),
            targetTouchWinIds_[deviceId][pointerId], deviceId);
        if (!targetTouchWinIds_[deviceId][pointerId].empty()) {
            ClearMismatchTypeWinIds(pointerId, displayId, deviceId);
            targetTouchWinIds_[deviceId][pointerId].insert(item.id);
        }
    }
}

void InputWindowsManager::ClearMismatchTypeWinIds(int32_t pointerId, int32_t displayId, int32_t deviceId) {
    if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
        return;
    }
    if (targetTouchWinIds_[deviceId].find(pointerId) == targetTouchWinIds_[deviceId].end()) {
        return;
    }
    std::set<int32_t>& windowIds = targetTouchWinIds_[deviceId][pointerId];
    for (auto iter = windowIds.begin(); iter != windowIds.end();) {
        int32_t windowId = *iter;
        auto windowInfo = WIN_MGR->GetWindowAndDisplayInfo(windowId, displayId);
        CHKCC(windowInfo);
        if (windowInfo->windowInputType != WindowInputType::TRANSMIT_ALL) {
            iter = windowIds.erase(iter);
        } else {
            ++iter;
        }
    }
}

void InputWindowsManager::CheckUIExtentionWindowDefaultHotArea(std::pair<int32_t, int32_t> logicalXY,
    bool isHotArea, const std::shared_ptr<PointerEvent> pointerEvent, const std::vector<WindowInfo>& windowInfos,
    const WindowInfo** touchWindow)
{
    CHKPV(pointerEvent);
    CHKPV(touchWindow);
    CHKPV(*touchWindow);
    int32_t uiExtentionWindowId = 0;
    int32_t windowId = (*touchWindow)->id;
    int32_t logicalX = logicalXY.first;
    int32_t logicalY = logicalXY.second;
    for (const auto& it : windowInfos) {
        if (IsInHotArea(logicalX, logicalY, it.defaultHotAreas, it)) {
            uiExtentionWindowId = it.id;
            break;
        }
    }
    if (uiExtentionWindowId > 0) {
        for (auto &windowinfo : windowInfos) {
            if (windowinfo.id == uiExtentionWindowId) {
                *touchWindow = &windowinfo;
                MMI_HILOG_DISPATCHD("uiExtentionWindowid:%{public}d", uiExtentionWindowId);
                AddActiveWindow(windowinfo.id, pointerEvent->GetPointerId());
                AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), uiExtentionWindowId,
                    pointerEvent->GetDeviceId());
                break;
            }
        }
    }
    if (isHotArea) {
        AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), windowId,
            pointerEvent->GetDeviceId());
    }
}

void InputWindowsManager::PullEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow)
{
    CHKPV(pointerEvent);
    CHKPV(touchWindow);
    MMI_HILOG_DISPATCHD("LastTouchWindowInfo:%{public}d, touchWindow:%{public}d",
        lastTouchWindowInfo_.id, touchWindow->id);
    if (lastTouchWindowInfo_.id != touchWindow->id) {
        if (lastTouchWindowInfo_.id != -1) {
            DispatchTouch(PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW, pointerEvent->GetTargetDisplayId());
        }
        lastTouchLogicX_ = logicalX;
        lastTouchLogicY_ = logicalY;
        lastTouchEvent_ = pointerEvent;
        lastTouchWindowInfo_ = *touchWindow;
        DispatchTouch(PointerEvent::POINTER_ACTION_PULL_IN_WINDOW, pointerEvent->GetTargetDisplayId());
        return;
    }
    lastTouchLogicX_ = logicalX;
    lastTouchLogicY_ = logicalY;
    lastTouchEvent_ = pointerEvent;
    lastTouchWindowInfo_ = *touchWindow;
}

void InputWindowsManager::DispatchTouch(int32_t pointerAction, int32_t groupId)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    CHKPV(lastTouchEvent_);
    if (pointerAction == PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) {
        WindowInfo touchWindow;
        bool isChanged { false };
        auto &WindowsInfo = GetWindowInfoVector(groupId);
        for (const auto &item : WindowsInfo) {
            if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
                MMI_HILOGD("Skip the untouchable window to continue searching, "
                    "window:%{public}d, flags:%{public}d", item.id, item.flags);
                continue;
            }
            if (item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) {
                continue;
            }
            if (IsInHotArea(lastTouchLogicX_, lastTouchLogicY_, item.defaultHotAreas, item)) {
                touchWindow = item;
                isChanged = true;
                break;
            }
        }
        if (!isChanged) {
            MMI_HILOGE("touchWindow is not init");
            return;
        }
        if (touchWindow.id != lastTouchWindowInfo_.id) {
            lastTouchWindowInfo_ = touchWindow;
        }
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    PointerEvent::PointerItem lastPointerItem;
    int32_t lastPointerId = lastTouchEvent_->GetPointerId();
    if (!lastTouchEvent_->GetPointerItem(lastPointerId, lastPointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", lastPointerId);
        return;
    }
    PointerEvent::PointerItem currentPointerItem;
    bool isOneHand = lastTouchEvent_->GetFixedMode() == PointerEvent::FixedMode::AUTO;
    double windowX = isOneHand ? lastWinX_ : (lastTouchLogicX_ - lastTouchWindowInfo_.area.x);
    double windowY = isOneHand ? lastWinY_ : (lastTouchLogicY_ - lastTouchWindowInfo_.area.y);
    if (isOneHand) {
        WindowInputType windowInputType = lastTouchWindowInfo_.windowInputType;
        if (windowInputType != WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE &&
            windowInputType != WindowInputType::DUALTRIGGER_TOUCH &&
            windowInputType != WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE) {
            if (!(lastTouchWindowInfo_.transform.empty())) {
                auto windowXY = TransformWindowXY(lastTouchWindowInfo_, lastTouchLogicX_, lastTouchLogicY_);
                windowX = windowXY.first;
                windowY = windowXY.second;
            }
            currentPointerItem.SetFixedDisplayXPos(lastPointerItem.GetFixedDisplayXPos());
            currentPointerItem.SetFixedDisplayYPos(lastPointerItem.GetFixedDisplayYPos());
            pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
        }
    }
    currentPointerItem.SetWindowX(static_cast<int32_t>(windowX));
    currentPointerItem.SetWindowY(static_cast<int32_t>(windowY));
    currentPointerItem.SetWindowXPos(windowX);
    currentPointerItem.SetWindowYPos(windowY);
    currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
    currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
    currentPointerItem.SetGlobalX(lastPointerItem.GetGlobalX());
    currentPointerItem.SetGlobalY(lastPointerItem.GetGlobalY());
    currentPointerItem.SetDisplayXPos(lastPointerItem.GetDisplayXPos());
    currentPointerItem.SetDisplayYPos(lastPointerItem.GetDisplayYPos());
    currentPointerItem.SetPressed(lastPointerItem.IsPressed());
    currentPointerItem.SetPointerId(lastPointerId);

    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    pointerEvent->SetTargetDisplayId(lastTouchEvent_->GetTargetDisplayId());
    SetPrivacyModeFlag(lastTouchWindowInfo_.privacyMode, pointerEvent);
    pointerEvent->SetTargetWindowId(lastTouchWindowInfo_.id);
    pointerEvent->SetAgentWindowId(lastTouchWindowInfo_.agentWindowId);
    pointerEvent->SetPointerId(lastPointerId);
    pointerEvent->AddPointerItem(currentPointerItem);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetBuffer(extraData_.buffer);
    pointerEvent->SetPullId(extraData_.pullId);
    pointerEvent->SetSourceType(lastTouchEvent_->GetSourceType());
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetDeviceId(lastTouchEvent_->GetDeviceId());
    UpdateWindowInfoFlag(lastTouchWindowInfo_.flags, pointerEvent);
    if (lastTouchEvent_->HasFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT)) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }

    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_FREEZE);
    auto filter = InputHandler->GetFilterHandler();
    CHKPV(filter);
    filter->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t pointerAction = pointerEvent->GetPointerAction();
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
        case PointerEvent::POINTER_ACTION_MOVE: {
            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
            pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
            pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_UP: {
            pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
            pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
            pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_TOUCHPAD_ACTIVE: {
            return UpdateMouseTarget(pointerEvent);
        }
        default: {
            MMI_HILOG_DISPATCHE("pointer action is unknown, pointerAction:%{public}d", pointerAction);
            return RET_ERR;
        }
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
int32_t InputWindowsManager::UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t groupId = FindDisplayGroupId(pointerEvent->GetTargetDisplayId());
    int32_t focusWindowId = GetFocusWindowId(groupId);
    const WindowInfo* windowInfo = nullptr;
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    for (const auto &item : windowsInfo) {
        if (item.id == focusWindowId) {
            windowInfo = &item;
            break;
        }
    }
    CHKPR(windowInfo, ERROR_NULL_POINTER);
    SetPrivacyModeFlag(windowInfo->privacyMode, pointerEvent);
    pointerEvent->SetTargetDisplayId(windowInfo->displayId);
    pointerEvent->SetTargetWindowId(windowInfo->id);
    pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOG_DISPATCHD("focusWindow:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_CROWN)
int32_t InputWindowsManager::UpdateCrownTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    return UpdateMouseTarget(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_CROWN

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display is not exist");
        return;
    }
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPV(physicDisplayInfo);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY) && \
    defined(OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER)
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    CHKPV(InputHandler->GetKeyCommandHandler());
    auto isInMethodWindow = InputHandler->GetKeyCommandHandler()->CheckInputMethodArea(pointerEvent);
    if (isInMethodWindow) {
        int32_t pointerId = pointerEvent->GetPointerId();
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
            return;
        }
        if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) {
            item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
            pointerEvent->UpdatePointerItem(pointerId, item);
        }
    }
    if (!isInMethodWindow) {
        KnuckleDrawingComponent::GetInstance().Draw(*physicDisplayInfo, pointerEvent);
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY && OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER

#ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
    TOUCH_DRAWING_MGR->UpdateDisplayInfo(*physicDisplayInfo);
    TOUCH_DRAWING_MGR->TouchDrawHandler(pointerEvent);
#endif // #ifdef OHOS_BUILD_ENABLE_TOUCH_DRAWING
}

#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

template <class T>
void InputWindowsManager::CreateAntiMisTakeObserver(T& item)
{
    CALL_INFO_TRACE;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        if (SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, item.isOpen) != RET_OK) {
            MMI_HILOGE("Get settingdata failed, key:%{public}s", key.c_str());
        }
        MMI_HILOGI("Anti mistake observer key:%{public}s, statusValue:%{public}d", key.c_str(), item.isOpen);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    CHKPV(statusObserver);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
}

template <class T>
void InputWindowsManager::CreatePrivacyProtectionObserver(T& item)
{
    CALL_INFO_TRACE;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        if (SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, item.isOpen) != RET_OK) {
            MMI_HILOGE("Get settingdata failed, key:%{public}s", key.c_str());
        }
        MMI_HILOGI("privacy protection key:%{public}s, statusValue:%{public}d", key.c_str(), item.isOpen);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    CHKPV(statusObserver);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
int32_t InputWindowsManager::UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto source = pointerEvent->GetSourceType();
    pointerActionFlag_ = pointerEvent->GetPointerAction();
#ifdef OHOS_BUILD_ENABLE_ANCO
    pointerEvent->SetAncoDeal(false);
#endif // OHOS_BUILD_ENABLE_ANCO
    if (IsFoldable_ && IgnoreTouchEvent(pointerEvent)) {
        MMI_HILOG_DISPATCHD("Ignore touch event, pointerAction:%{public}d", pointerActionFlag_);
        return RET_OK;
    };
    int32_t ret { RET_ERR };
    switch (source) {
#ifdef OHOS_BUILD_ENABLE_TOUCH
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            ret = UpdateTouchScreenTarget(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
        case PointerEvent::SOURCE_TYPE_MOUSE: {
            ret =  UpdateMouseTarget(pointerEvent);
            break;
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            ret = UpdateTouchPadTarget(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
        case PointerEvent::SOURCE_TYPE_JOYSTICK: {
            ret = UpdateJoystickTarget(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_JOYSTICK
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_CROWN)
        case PointerEvent::SOURCE_TYPE_CROWN: {
            ret = UpdateCrownTarget(pointerEvent);
            break;
        }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_CROWN
        default: {
            MMI_HILOG_DISPATCHE("Source type is unknown, source:%{public}d", source);
            return ret;
        }
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    HandlePullEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    return ret;
}

bool InputWindowsManager::IsInsideDisplay(const OLD::DisplayInfo& displayInfo, double physicalX, double physicalY)
{
    auto displayDirection = GetDisplayDirection(&displayInfo);
    auto physicalRect = RotateRect<int32_t>(displayDirection, { displayInfo.validWidth, displayInfo.validHeight });
    bool isInside = (physicalX >= 0 && physicalX < physicalRect.x) && (physicalY >= 0 && physicalY < physicalRect.y);
    PrintDisplayInfo(displayInfo);
    MMI_HILOGD("isInside:%{public}d physicalXY={%{private}f %{private}f} "
        "physicalRect={%{public}d %{public}d} useDirection:%{public}d}",
        static_cast<int32_t>(isInside),
        physicalX,
        physicalY,
        physicalRect.x,
        physicalRect.y,
        displayDirection);
    return isInside;
}

bool InputWindowsManager::CalculateLayout(const OLD::DisplayInfo &displayInfo, const Vector2D<double> &physical,
    Vector2D<double> &layout)
{
    Direction direction = GetDisplayDirection(&displayInfo);
    Vector2D<double> logical = physical;
    if (GetHardCursorEnabled()) {
        auto screenRect = RotateRect<double>(direction, {displayInfo.width, displayInfo.height});
        auto transforms = RotateAndFitScreen(direction, screenRect);
        logical = MMI::ApplyTransformSteps(transforms, physical);
    }
    layout.x = logical.x + displayInfo.x;
    layout.y = logical.y + displayInfo.y;

    MMI_HILOGD("calculated layout point, id:%{public}d, d:%{public}d, dd:%{public}d, ddd:%{public}d, "
        "dx:%{private}d, dy:%{private}d, px:%{private}f, py:%{private}f, "
        "lx:%{private}f, ly:%{private}f, lax:%{private}f, lay:%{private}f ",
        displayInfo.id, direction, displayInfo.direction, displayInfo.displayDirection,
        displayInfo.x, displayInfo.y, physical.x, physical.y,
        logical.x, logical.y, layout.x, layout.y);
    return true;
}

AcrossDirection InputWindowsManager::CalculateAcrossDirection(const OLD::DisplayInfo &displayInfo,
    const Vector2D<double> &layout)
{
    Vector2D<int32_t> layoutMax;

    if (!AddInt32(displayInfo.x, displayInfo.validWidth, layoutMax.x)) {
        MMI_HILOGE("The addition of layoutMax.x overflows");
        return AcrossDirection::ACROSS_ERROR;
    }
    if (!AddInt32(displayInfo.y, displayInfo.validHeight, layoutMax.y)) {
        MMI_HILOGE("The addition of layoutMax.y overflows");
        return AcrossDirection::ACROSS_ERROR;
    }

    if (layout.x < displayInfo.x) {
        return AcrossDirection::LEFTWARDS;
    } else if (layout.x >= layoutMax.x) {
        return AcrossDirection::RIGHTWARDS;
    }
    if (layout.y < displayInfo.y) {
        return AcrossDirection::UPWARDS;
    } else if (layout.y >= layoutMax.y) {
        return AcrossDirection::DOWNWARDS;
    }

    return AcrossDirection::ACROSS_ERROR;
}

bool InputWindowsManager::AcrossDisplay(const OLD::DisplayInfo &displayInfoDes, const OLD::DisplayInfo &displayInfoOri,
    Vector2D<double> &logical, Vector2D<double> &layout, const AcrossDirection &acrossDirection)
{
    Vector2D<int32_t> layoutMax;
    double layoutX, layoutY;
    int32_t pointerWidth = 0, pointerHeight = 0;
    bool re = false;
    layoutX = layout.x;
    layoutY = layout.y;
    CursorDrawingComponent::GetInstance().GetPointerImageSize(pointerWidth, pointerHeight);
    if (!AddInt32(displayInfoDes.x, displayInfoDes.validWidth, layoutMax.x)) {
        MMI_HILOGE("The addition of layoutMax.x overflows");
        return false;
    }
    if (!AddInt32(displayInfoDes.y, displayInfoDes.validHeight, layoutMax.y)) {
        MMI_HILOGE("The addition of layoutMax.y overflows");
        return false;
    }

    re |= (acrossDirection == RIGHTWARDS && displayInfoDes.x == displayInfoOri.x + displayInfoOri.validWidth);
    re |= (acrossDirection == LEFTWARDS && displayInfoDes.x + displayInfoDes.validWidth == displayInfoOri.x);
    re |= (acrossDirection == DOWNWARDS && displayInfoDes.y == displayInfoOri.y + displayInfoOri.validHeight);
    re |= (acrossDirection == UPWARDS && displayInfoDes.y + displayInfoDes.validHeight == displayInfoOri.y);
    if (!re) {
        MMI_HILOGI("the display is not in across direction.");
        return re;
    }

    if (layout.x < displayInfoDes.x) {
        layoutX = displayInfoDes.x;
    } else if (layout.x >= layoutMax.x) {
        layoutX = layoutMax.x - pointerWidth;
    }
    if (layout.y < displayInfoDes.y) {
        layoutY = displayInfoDes.y;
    } else if (layout.y >= layoutMax.y) {
        layoutY = layoutMax.y - pointerHeight;
    }
    logical = { layoutX - displayInfoDes.x, layoutY - displayInfoDes.y };
    return re;
}

void InputWindowsManager::FindPhysicalDisplay(const OLD::DisplayInfo& displayInfo, double& physicalX,
    double& physicalY, int32_t& displayId)
{
    CALL_DEBUG_ENTER;
    Vector2D<double> physical = { physicalX, physicalY };
    Vector2D<double> logical = physical;
    Vector2D<double> layout = { 0, 0 };
    AcrossDirection acrossDirection;
    if (!CalculateLayout(displayInfo, physical, layout)) {
        return;
    }
    int32_t groupId = FindDisplayGroupId(displayId);
    auto &displaysInfoVector = GetDisplayInfoVector(groupId);
    for (const auto &item : displaysInfoVector) {
        if (item.id == displayInfo.id) {
            continue;
        }
        acrossDirection = CalculateAcrossDirection(displayInfo, layout);
        MMI_HILOGI("acrossDirection :%{public}d, current displayId:%{public}d, target displayId:%{public}d",
            acrossDirection, displayInfo.id, item.id);
        if (acrossDirection == AcrossDirection::ACROSS_ERROR) {
            return;
        }
        if (!AcrossDisplay(item, displayInfo, logical, layout, acrossDirection)) {
            continue;
        }
        physical = logical;
        Direction direction = GetDisplayDirection(&item);
        if (GetHardCursorEnabled()) {
            auto screenRect = RotateRect<double>(direction, { item.width, item.height });
            auto transforms = RotateAndFitScreen(direction, screenRect);
            physical = ResetTransformSteps(transforms, logical);
        }
        physicalX = physical.x;
        physicalY = physical.y;
        displayId = item.id;
        MMI_HILOGD("switched into display, id:%{public}d, d:%{public}d, dd:%{public}d, ddd:%{public}d, "
            "dx:%{private}d, dy:%{private}d, dw:%{private}d, dh:%{private}d, "
            "lx:%{private}f, ly:%{private}f, px:%{private}f, py:%{private}f",
            displayId, direction, item.direction, item.displayDirection,
            item.x, item.y, item.width, item.height,
            logical.x, logical.y, physicalX, physicalY);
        break;
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::CoordinateCorrection(int32_t width, int32_t height, int32_t &integerX, int32_t &integerY)
{
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

bool InputWindowsManager::IsWindowRotation(const OLD::DisplayInfo *displayInfo)
{
    MMI_HILOGD("ROTATE_POLICY: %{public}d, FOLDABLE_DEVICE_POLICY:%{public}s",
        ROTATE_POLICY, FOLDABLE_DEVICE_POLICY.c_str());
    CHKPF(displayInfo);

    bool foldableDevicePolicyMain = false;
    bool foldableDevicePolicyFull = false;
    if (!FOLDABLE_DEVICE_POLICY.empty()) {
        foldableDevicePolicyMain = FOLDABLE_DEVICE_POLICY[0] == ROTATE_WINDOW_ROTATE;
    }
    if (FOLDABLE_DEVICE_POLICY.size() > FOLDABLE_DEVICE) {
        foldableDevicePolicyFull = FOLDABLE_DEVICE_POLICY[FOLDABLE_DEVICE] == ROTATE_WINDOW_ROTATE;
    }

    return (ROTATE_POLICY == WINDOW_ROTATE ||
        (ROTATE_POLICY == FOLDABLE_DEVICE &&
        ((displayInfo->displayMode == DisplayMode::MAIN && foldableDevicePolicyMain) ||
        (displayInfo->displayMode == DisplayMode::FULL && foldableDevicePolicyFull))));
}

Direction InputWindowsManager::GetDisplayDirection(const OLD::DisplayInfo *displayInfo)
{
    CHKPR(displayInfo, DIRECTION0);
    Direction displayDirection = static_cast<Direction>((
        ((displayInfo->direction - displayInfo->displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    if (GetHardCursorEnabled()) {
        if (IsWindowRotation(displayInfo)) {
            displayDirection = static_cast<Direction>((((displayInfo->direction - displayInfo->displayDirection) *
                ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        } else {
            displayDirection = displayInfo->direction;
        }
    }
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        displayDirection = displayInfo->direction;
    }
    return displayDirection;
}

void InputWindowsManager::GetWidthAndHeight(const OLD::DisplayInfo* displayInfo, int32_t &width, int32_t &height,
    bool isRealData)
{
    auto displayDirection = GetDisplayDirection(displayInfo);
    if (displayDirection == DIRECTION0 || displayDirection == DIRECTION180) {
        width = displayInfo->validWidth;
        height = displayInfo->validHeight;
    } else {
        if (!isRealData) {
            width = displayInfo->validWidth;
            height = displayInfo->validHeight;
            return;
        }
        height = displayInfo->validWidth;
        width = displayInfo->validHeight;
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::ReverseRotateScreen(const OLD::DisplayInfo& info, const double x, const double y,
    Coordinate2D& cursorPos) const
{
    const Direction direction = info.direction;
    MMI_HILOGD("X:%{private}.2f, Y:%{private}.2f, offsetXY={%{private}d %{private}d},"
        "info.WH:{%{private}d %{private}d} info.validWH:{%{private}d %{private}d}",
        x,
        y,
        info.offsetX,
        info.offsetY,
        info.width,
        info.height,
        info.validWidth,
        info.validHeight);
    switch (direction) {
        case DIRECTION0: {
            cursorPos.x = x;
            cursorPos.y = y;
            MMI_HILOGD("DIRECTION0, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION90: {
            cursorPos.y = static_cast<double>(info.validWidth) - 1 - x;
            cursorPos.x = y;
            MMI_HILOGD("DIRECTION90, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION180: {
            cursorPos.x = static_cast<double>(info.validWidth) - 1 - x;
            cursorPos.y = static_cast<double>(info.validHeight) - 1 - y;
            MMI_HILOGD("DIRECTION180, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION270: {
            cursorPos.x = static_cast<double>(info.validHeight) - 1 - y;
            cursorPos.y = x;
            MMI_HILOGD("DIRECTION270, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        default: {
            MMI_HILOGE("direction is invalid, direction:%{private}d", direction);
            break;
        }
    }
}

void InputWindowsManager::ReverseRotateDisplayScreen(const OLD::DisplayInfo& info, const double x, const double y,
    Coordinate2D& cursorPos) const
{
    Direction displayDirection = WIN_MGR->GetDisplayDirection(&info);
    MMI_HILOGD(
        "X:%{private}.2f, Y:%{private}.2f, info.WH:{%{private}d %{private}d}, info.validWH:{%{private}d %{private}d}",
        x,
        y,
        info.width,
        info.height,
        info.validWidth,
        info.validHeight);
    switch (displayDirection) {
        case DIRECTION0: {
            cursorPos.x = x;
            cursorPos.y = y;
            MMI_HILOGD("DIRECTION0, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION90: {
            cursorPos.y = static_cast<double>(info.validWidth) - 1 - x;
            cursorPos.x = y;
            MMI_HILOGD("DIRECTION90, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION180: {
            cursorPos.x = static_cast<double>(info.validWidth) - 1 - x;
            cursorPos.y = static_cast<double>(info.validHeight) - 1 - y;
            MMI_HILOGD("DIRECTION180, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION270: {
            cursorPos.x = static_cast<double>(info.validHeight) - 1 - y;
            cursorPos.y = x;
            MMI_HILOGD("DIRECTION270, physicalX:%{private}.2f, physicalY:%{private}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        default: {
            MMI_HILOGE("displayDirection is invalid, displayDirection:%{private}d", displayDirection);
            break;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData)
{
    int32_t groupId = FindDisplayGroupId(displayId);
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPV(displayInfo);
    double oldX = x;
    double oldY = y;
    int32_t lastDisplayId = displayId;
    if (!IsInsideDisplay(*displayInfo, x, y)) {
        FindPhysicalDisplay(*displayInfo, x, y, displayId);
        MMI_HILOGI("Not IsInsideDisplay, cursorXY:{%{private}f, %{private}f}->{%{private}f, %{private}f}",
            oldX, oldY, x, y);
    }
    if (displayId != lastDisplayId) {
        displayInfo = GetPhysicalDisplay(displayId);
        CHKPV(displayInfo);
    }
    int32_t width = 0;
    int32_t height = 0;
    GetWidthAndHeight(displayInfo, width, height, isRealData);
    int32_t integerX = static_cast<int32_t>(x);
    int32_t integerY = static_cast<int32_t>(y);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (IsPointerActiveRectValid(*displayInfo)) {
        width = displayInfo->pointerActiveWidth;
        height = displayInfo->pointerActiveHeight;
        MMI_HILOGD("vtp cursor active area w:%{private}d, h:%{private}d", width, height);
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    CoordinateCorrection(width, height, integerX, integerY);
    x = static_cast<double>(integerX) + (x - floor(x));
    y = static_cast<double>(integerY) + (y - floor(y));
    const auto iter = mouseLocationMap_.find(groupId);
    if (iter != mouseLocationMap_.end()) {
        mouseLocationMap_[groupId].displayId = displayId;
    }
    const auto it = cursorPosMap_.find(groupId);
    if (it != cursorPosMap_.end()) {
        cursorPosMap_[groupId].displayId = displayId;
    }
    if (isRealData) {
        PhysicalCoordinate coord {
            .x = integerX,
            .y = integerY,
        };
        RotateDisplayScreen(*displayInfo, coord);
        const auto iter = mouseLocationMap_.find(groupId);
        if (iter != mouseLocationMap_.end()) {
            mouseLocationMap_[groupId].physicalX = coord.x;
            mouseLocationMap_[groupId].physicalY = coord.y;
        }
        const auto it = cursorPosMap_.find(groupId);
        if (it != cursorPosMap_.end()) {
            cursorPosMap_[groupId].cursorPos.x = x;
            cursorPosMap_[groupId].cursorPos.y = y;
        }
    } else {
        const auto iter = mouseLocationMap_.find(groupId);
        if (iter != mouseLocationMap_.end()) {
            mouseLocationMap_[groupId].physicalX = integerX;
            mouseLocationMap_[groupId].physicalY = integerY;
        }
        CursorPosition cursorPosCur = {};

        const auto it = cursorPosMap_.find(groupId);
        if (it != cursorPosMap_.end()) {
            cursorPosCur = it->second;
        }
        ReverseRotateDisplayScreen(*displayInfo, x, y, cursorPosCur.cursorPos);
        cursorPosMap_[groupId] = cursorPosCur;
    }
    MouseLocation mouseLocationTmp;
    double physicalX = 0.0;
    double physicalY = 0.0;
    const auto& locationMap = mouseLocationMap_.find(groupId);
    if (locationMap != mouseLocationMap_.end()) {
        mouseLocationTmp = locationMap->second;
    }
    const auto& posMap = cursorPosMap_.find(groupId);
    if (posMap != cursorPosMap_.end()) {
        physicalX = posMap->second.cursorPos.x;
        physicalY = posMap->second.cursorPos.y;
    }
    MMI_HILOGD("Mouse Data: isRealData=%{public}d, displayId:%{public}d, mousePhysicalXY={%{private}d, %{private}d}, "
        "cursorPosXY: {%{private}.2f, %{private}.2f} -> {%{private}.2f %{private}.2f}",
        static_cast<int32_t>(isRealData), displayId, mouseLocationTmp.physicalX,
        mouseLocationTmp.physicalY, oldX, oldY, physicalX, physicalY);
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    auto &displaysInfoVector = GetDisplayInfoVector(MAIN_GROUPID);
    MouseLocation curMouseLocation;
    const auto iter = mouseLocationMap_.find(MAIN_GROUPID);
    if (iter != mouseLocationMap_.end()) {
        curMouseLocation = iter->second;
    }
    MMI_HILOGD("Mouselocation start: displayId:%{public}d, X:%{private}d, Y:%{private}d",
        curMouseLocation.displayId, curMouseLocation.physicalX, curMouseLocation.physicalY);
    if ((curMouseLocation.displayId < 0) && !displaysInfoVector.empty()) {
        OLD::DisplayInfo displayInfo = displaysInfoVector[0];
        if (GetHardCursorEnabled()) {
            (void)GetMainScreenDisplayInfo(displaysInfoVector, displayInfo);
        }
        const auto iter = mouseLocationMap_.find(MAIN_GROUPID);
        if (iter != mouseLocationMap_.end()) {
            mouseLocationMap_[MAIN_GROUPID].displayId = displayInfo.id;
            mouseLocationMap_[MAIN_GROUPID].physicalX = displayInfo.validWidth / TWOFOLD;
            mouseLocationMap_[MAIN_GROUPID].physicalY = displayInfo.validHeight / TWOFOLD;
            curMouseLocation = iter->second;
        }
        MMI_HILOGD("Mouselocation displayinfo: displayId:%{public}d, W:%{public}d, H:%{public}d",
            displayInfo.id, displayInfo.validWidth, displayInfo.validHeight);
        return curMouseLocation;
    }
    MMI_HILOGD("Mouselocation next: displayId:%{public}d, X:%{private}d, Y:%{private}d",
        curMouseLocation.displayId, curMouseLocation.physicalX, curMouseLocation.physicalY);
    return curMouseLocation;
}

CursorPosition InputWindowsManager::GetCursorPos()
{
    CALL_DEBUG_ENTER;
    auto &displaysInfoVector = GetDisplayInfoVector(MAIN_GROUPID);
    CursorPosition cursorPos;
    const auto iter = cursorPosMap_.find(MAIN_GROUPID);
    if (iter != cursorPosMap_.end()) {
        cursorPos = iter->second;
    }
    if ((cursorPos.displayId < 0) && !displaysInfoVector.empty()) {
        OLD::DisplayInfo displayInfo = displaysInfoVector[0];
        if (GetHardCursorEnabled()) {
            (void)GetMainScreenDisplayInfo(displaysInfoVector, displayInfo);
        }
        const auto iter = cursorPosMap_.find(MAIN_GROUPID);
        if (iter != cursorPosMap_.end()) {
            int32_t validW = displayInfo.validWidth;
            int32_t validH = displayInfo.validHeight;
            Direction direction = GetDisplayDirection(&displayInfo);
            if (direction == DIRECTION90 || direction == DIRECTION270) {
                std::swap(validW, validH);
            }
            cursorPosMap_[MAIN_GROUPID].displayId = displayInfo.id;
            cursorPosMap_[MAIN_GROUPID].cursorPos.x = validW * HALF_RATIO;
            cursorPosMap_[MAIN_GROUPID].cursorPos.y = validH * HALF_RATIO;
            cursorPosMap_[MAIN_GROUPID].direction = displayInfo.direction;
            cursorPosMap_[MAIN_GROUPID].displayDirection = displayInfo.displayDirection;
            cursorPos = cursorPosMap_[MAIN_GROUPID];
        }
    }
    return cursorPos;
}

CursorPosition InputWindowsManager::ResetCursorPos()
{
    CALL_DEBUG_ENTER;
    auto &displaysInfoVector = GetDisplayInfoVector(MAIN_GROUPID);
    if (!displaysInfoVector.empty()) {
        OLD::DisplayInfo displayInfo = displaysInfoVector[0];
        int32_t x = displayInfo.validWidth * HALF_RATIO;
        int32_t y = displayInfo.validHeight * HALF_RATIO;
        if (GetHardCursorEnabled()) {
            (void)GetMainScreenDisplayInfo(displaysInfoVector, displayInfo);
            x = displayInfo.validWidth * HALF_RATIO;
            y = displayInfo.validHeight * HALF_RATIO;
            Direction displayDirection = GetDisplayDirection(&displayInfo);
            if (displayDirection == DIRECTION90 || displayDirection == DIRECTION270) {
                std::swap(x, y);
            }
        }
        const auto iter = cursorPosMap_.find(MAIN_GROUPID);
        if (iter != cursorPosMap_.end()) {
            cursorPosMap_[MAIN_GROUPID].displayId = displayInfo.id;
            cursorPosMap_[MAIN_GROUPID].cursorPos.x = x;
            cursorPosMap_[MAIN_GROUPID].cursorPos.y = y;
        }
    } else {
        const auto iter = cursorPosMap_.find(MAIN_GROUPID);
        if (iter != cursorPosMap_.end()) {
            cursorPosMap_[MAIN_GROUPID].displayId = -1;
            cursorPosMap_[MAIN_GROUPID].cursorPos.x = 0;
            cursorPosMap_[MAIN_GROUPID].cursorPos.y = 0;
        }
    }
    CursorPosition cursorPos;
    const auto iter = cursorPosMap_.find(MAIN_GROUPID);
    if (iter != cursorPosMap_.end()) {
        cursorPos = iter->second;
    }
    MMI_HILOGI("ResetCursorPos cursorPosMap_[mainGroupId].displayId:%{public}d",
        cursorPos.displayId);
    return cursorPos;
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t InputWindowsManager::AppendExtraData(const ExtraData& extraData)
{
    CALL_DEBUG_ENTER;
    extraData_.appended = extraData.appended;
    extraData_.buffer = extraData.buffer;
    extraData_.sourceType = extraData.sourceType;
    extraData_.pointerId = extraData.pointerId;
    extraData_.pullId = extraData.pullId;
    extraData_.eventId = extraData.eventId;
    extraData_.drawCursor = extraData.drawCursor;
    if ((extraData_.eventId > 0) && (extraData.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) &&
        (mouseDownEventId_ < 0 || extraData.eventId < mouseDownEventId_)) {
        MMI_HILOGE("Mouse drag failed, PI:%{public}d, EI:%{public}d, DEI:%{public}d",
            extraData.pointerId, extraData.eventId, mouseDownEventId_);
        ClearExtraData();
        return RET_ERR;
    }
    return RET_OK;
}

void InputWindowsManager::ClearExtraData()
{
    CALL_DEBUG_ENTER;
    extraData_.appended = false;
    extraData_.buffer.clear();
    extraData_.sourceType = -1;
    extraData_.pointerId = -1;
    extraData_.pullId = -1;
    extraData_.eventId = -1;
    extraData_.drawCursor = false;
}

ExtraData InputWindowsManager::GetExtraData() const
{
    CALL_DEBUG_ENTER;
    return extraData_;
}

bool InputWindowsManager::IsWindowVisible(int32_t pid)
{
    CALL_DEBUG_ENTER;
    if (pid < 0) {
        MMI_HILOGE("pid is invalid");
        return true;
    }
    std::vector<sptr<Rosen::WindowVisibilityInfo>> infos;
    BytraceAdapter::StartWindowVisible(pid);
    Rosen::WindowManagerLite::GetInstance().GetVisibilityWindowInfo(infos);
    BytraceAdapter::StopWindowVisible();
    for (const auto &it: infos) {
        CHKPC(it);
        if (pid == it->pid_ &&
            it->visibilityState_ < Rosen::WindowVisibilityState::WINDOW_VISIBILITY_STATE_TOTALLY_OCCUSION) {
            MMI_HILOGD("pid:%{public}d has visible window", pid);
            return true;
        }
    }
    MMI_HILOGD("pid:%{public}d doesn't have visible window", pid);
    return false;
}

void InputWindowsManager::UpdatePointerAction(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t action = pointerEvent->GetPointerAction();
    switch (action) {
        case PointerEvent::POINTER_ACTION_MOVE: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
            break;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
        case PointerEvent::POINTER_ACTION_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
            break;
        }
        case PointerEvent::POINTER_ACTION_ENTER_WINDOW: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_IN_WINDOW);
            break;
        }
        case PointerEvent::POINTER_ACTION_LEAVE_WINDOW: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW);
            break;
        }
        default: {
            MMI_HILOG_DISPATCHI("Action is:%{public}d, no need change", action);
            break;
        }
    }
    MMI_HILOG_DISPATCHD("pointerAction:%{public}s", pointerEvent->DumpPointerAction());
}

void InputWindowsManager::DumpDisplayInfo(int32_t fd, const std::vector<OLD::DisplayInfo>& displaysInfo)
{
    mprintf(fd, "Displays information:\t");
    mprintf(fd, "displayInfos,num:%zu", displaysInfo.size());
    for (const auto &item : displaysInfo) {
        mprintf(fd, "\t displayInfos: rsId:%" PRIu64 " | displaySourceMode:%d id:%d | x:%d"
                    "| y:%d | width:%d | height:%d | name:%s | uniq:%s | direction:%d"
                    "| displayDirection:%d | displayMode:%u | offsetX:%d | offsetY:%d"
                    "| validWidth:%d | validHeight:%d | pointerActiveWidth:%d | pointerActiveHeight:%d\t",
                    item.rsId, item.displaySourceMode, item.id, item.x, item.y, item.width,
                    item.height, item.name.c_str(), item.uniq.c_str(), item.direction,
                    item.displayDirection, item.displayMode, item.offsetX, item.offsetY,
                    item.validWidth, item.validHeight, item.pointerActiveWidth, item.pointerActiveHeight);
        if (item.transform.size() == MATRIX3_SIZE) {
            mprintf(fd, "\t transform: scaleX:%f | scaleY:%f | anchorPointX:%f | anchorPointY:%f \t",
                item.transform[SCALE_X], item.transform[SCALE_Y], item.transform[ANCHOR_POINT_X],
                item.transform[ANCHOR_POINT_Y]);
        }
    }
}

void InputWindowsManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    #ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    auto proxy = POINTER_DEV_MGR.GetDelegateProxy();
    if (proxy != nullptr) {
        CursorDrawingComponent::GetInstance().SetDelegateProxy(proxy);
    }
    #endif  // OHOS_BUILD_ENABLE_POINTER_DRAWING
    std::shared_ptr<DelegateInterface> delegateProxy =
        CursorDrawingComponent::GetInstance().GetDelegateProxy();
    CHKPV(delegateProxy);
    std::vector<OLD::DisplayInfo> displaysInfo;
    std::vector<WindowInfo> windowsInfo;
    delegateProxy->OnPostSyncTask([this, &displaysInfo, &windowsInfo] {
        const auto& iter = displayGroupInfoMap_.find(MAIN_GROUPID);
        if (iter != displayGroupInfoMap_.end()) {
            displaysInfo = iter->second.displaysInfo;
            windowsInfo = iter->second.windowsInfo;
            return RET_OK;
        }
        displaysInfo = displayGroupInfo_.displaysInfo;
        windowsInfo = displayGroupInfo_.windowsInfo;
        return RET_OK;
    });
    mprintf(fd, "Windows information:\t");
    mprintf(fd, "windowsInfos,num:%zu", windowsInfo.size());
    for (const auto &item : windowsInfo) {
        mprintf(fd, "  windowsInfos: id:%d | pid:%d | uid:%d | area.x:%d | area.y:%d "
            "| area.width:%d | area.height:%d | defaultHotAreas.size:%zu "
            "| pointerHotAreas.size:%zu | agentWindowId:%d | flags:%u "
            "| action:%d | displayId:%d | zOrder:%f | Privacy:%d | Type:%d \t",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder,
            item.isSkipSelfWhenShowOnVirtualScreen, static_cast<int32_t>(item.windowInputType));
        for (const auto &win : item.defaultHotAreas) {
            mprintf(fd, "\t defaultHotAreas: x:%d | y:%d | width:%d | height:%d \t",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            mprintf(fd, "\t pointerHotAreas: x:%d | y:%d | width:%d | height:%d \t",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }

        std::string dump;
        dump += StringPrintf("\t pointerChangeAreas: ");
        for (const auto &it : item.pointerChangeAreas) {
            dump += StringPrintf("%d | ", it);
        }
        dump += StringPrintf("\n\t transform: ");
        for (const auto &it : item.transform) {
            dump += StringPrintf("%f | ", it);
        }
        std::istringstream stream(dump);
        std::string line;
        while (std::getline(stream, line, '\n')) {
            mprintf(fd, "%s", line.c_str());
        }
    }
    DumpDisplayInfo(fd, displaysInfo);
    mprintf(fd, "Input device and display bind info:\n%s", bindInfo_.Dumps().c_str());
#ifdef OHOS_BUILD_ENABLE_ANCO
    std::string ancoWindows;
    DumpAncoWindows(ancoWindows);
    mprintf(fd, "%s\n", ancoWindows.c_str());
#endif // OHOS_BUILD_ENABLE_ANCO
}

std::pair<double, double> InputWindowsManager::TransformWindowXY(const WindowInfo &window,
    double logicX, double logicY) const
{
    UpdateCurrentDisplay(window.displayId);
    double currX = logicX - currentDisplayXY_.first;
    double currY = logicY - currentDisplayXY_.second;
    Matrix3f transform(window.transform);
    if (window.transform.size() != MATRIX3_SIZE || transform.IsIdentity()) {
        return {currX, currY};
    }
    Vector3f logicXY(currX, currY, 1.0);
    Vector3f windowXY = transform * logicXY;
    return { windowXY[0], windowXY[1] };
}

std::pair<double, double> InputWindowsManager::TransformDisplayXY(const OLD::DisplayInfo &info,
    double logicX, double logicY) const
{
    Matrix3f transform(info.transform);
    if (info.transform.size() != MATRIX3_SIZE || transform.IsIdentity()) {
        return {logicX, logicY};
    }
    Vector3f logicXY(logicX, logicY, 1.0);
    Vector3f displayXY = transform * logicXY;
    return {round(displayXY[0]), round(displayXY[1])};
}

bool InputWindowsManager::IsValidZorderWindow(const WindowInfo &window,
    const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPF(pointerEvent);
    if (!(pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) || MMI_LE(pointerEvent->GetZOrder(), 0.0f)) {
        return true;
    }
    if (MMI_GE(window.zOrder, pointerEvent->GetZOrder())) {
        MMI_HILOGE("Current window zorder:%{public}f greater than the simulate target zOrder:%{public}f, "
            "ignore this window::%{public}d", window.zOrder, pointerEvent->GetZOrder(), window.id);
        return false;
    }
    return true;
}

bool InputWindowsManager::HandleWindowInputType(const WindowInfo &window, std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    if (!pointerEvent->GetPointerItem(pointerId, item)) {
        MMI_HILOG_WINDOWE("Invalid pointer:%{public}d", pointerId);
        return false;
    }
    int32_t sourceType = pointerEvent->GetSourceType();
    WindowInputType windowTypeTemp = window.windowInputType;
    if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        GetActiveWindowTypeById(window.id, windowTypeTemp);
    }
    switch (windowTypeTemp)
    {
        case WindowInputType::NORMAL:
            return false;
        case WindowInputType::TRANSMIT_ALL:
            return true;
        case WindowInputType::DUALTRIGGER_TOUCH:
            return true;
        case WindowInputType::TRANSMIT_EXCEPT_MOVE: {
            auto pointerAction = pointerEvent->GetPointerAction();
            return (pointerAction == PointerEvent::POINTER_ACTION_MOVE ||
                pointerAction == PointerEvent::POINTER_ACTION_PULL_MOVE);
        }
        case WindowInputType::ANTI_MISTAKE_TOUCH:
            return false;
        case WindowInputType::TRANSMIT_AXIS_MOVE:
            return false;
        case WindowInputType::TRANSMIT_MOUSE_MOVE:
            return false;
        case WindowInputType::TRANSMIT_LEFT_RIGHT:
            return false;
        case WindowInputType::TRANSMIT_BUTTOM:
            return false;
        case WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE:
            return false;
        case WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE:
            return false;
        default:
            return false;
    }
}

std::optional<WindowInfo> InputWindowsManager::GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId)
{
    CALL_DEBUG_ENTER;
    const std::vector<WindowInfo> &windowInfos = GetWindowGroupInfoByDisplayId(displayId);
    for (const auto &item : windowInfos) {
        if (windowId == item.id) {
            return std::make_optional(item);
        }
        for (const auto &uiExtentionWindow : item.uiExtentionWindowInfo) {
            if (windowId == uiExtentionWindow.id) {
                return std::make_optional(uiExtentionWindow);
            }
        }
    }
    return std::nullopt;
}

void InputWindowsManager::GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType,
    std::set<int32_t> &windowIds, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (targetMouseWinIds_.find(pointerItemId) != targetMouseWinIds_.end()) {
            windowIds = targetMouseWinIds_[pointerItemId];
        }
        return;
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
            return;
        }
        if (targetTouchWinIds_[deviceId].find(pointerItemId) != targetTouchWinIds_[deviceId].end()) {
                windowIds = targetTouchWinIds_[deviceId][pointerItemId];
        }
    }
}

void InputWindowsManager::AddTargetWindowIds(int32_t pointerItemId, int32_t sourceType, int32_t windowId,
    int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (targetMouseWinIds_.find(pointerItemId) != targetMouseWinIds_.end()) {
            targetMouseWinIds_[pointerItemId].insert(windowId);
        } else {
            std::set<int32_t> windowIds;
            windowIds.insert(windowId);
            targetMouseWinIds_.emplace(pointerItemId, windowIds);
        }
        return;
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
            MMI_HILOGI("Target device's windowIds not found, Add deviceId:%{public}d", deviceId);
            targetTouchWinIds_[deviceId] = {};
        }
        if (targetTouchWinIds_[deviceId].find(pointerItemId) != targetTouchWinIds_[deviceId].end()) {
            targetTouchWinIds_[deviceId][pointerItemId].insert(windowId);
        } else {
            std::set<int32_t> windowIds;
            windowIds.insert(windowId);
            targetTouchWinIds_[deviceId].emplace(pointerItemId, windowIds);
        }
    }
}

void InputWindowsManager::ClearTargetDeviceWindowId(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
        MMI_HILOGI("Target device's windowId not found, deviceId:%{public}d", deviceId);
        return;
    }
    targetTouchWinIds_.erase(deviceId);
}

void InputWindowsManager::ClearTargetWindowId(int32_t pointerId, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    if (targetTouchWinIds_.find(deviceId) == targetTouchWinIds_.end()) {
        return;
    }
    if (targetTouchWinIds_[deviceId].find(pointerId) == targetTouchWinIds_[deviceId].end()) {
        MMI_HILOGD("Clear target windowId fail, pointerId:%{public}d", pointerId);
        return;
    }
    targetTouchWinIds_[deviceId].erase(pointerId);
}

void InputWindowsManager::SetPrivacyModeFlag(SecureFlag privacyMode, std::shared_ptr<InputEvent> event)
{
    if (privacyMode == SecureFlag::PRIVACY_MODE) {
        MMI_HILOGD("Window security mode is privacy");
        event->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    } else {
        event->ClearFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    }
}

int32_t InputWindowsManager::CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid)
{
    CALL_DEBUG_ENTER;
    int32_t checkingPid = GetWindowPid(windowId);
    if (checkingPid != pid) {
        MMI_HILOGE("check windowId failed, windowId is %{public}d, pid is %{public}d", windowId, pid);
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputWindowsManager::ReverseXY(int32_t &x, int32_t &y)
{
    CALL_DEBUG_ENTER;
    auto &DisplaysInfo = GetDisplayInfoVector(MAIN_GROUPID);
    if (DisplaysInfo.empty()) {
        MMI_HILOGE("DisplaysInfo is empty");
        return;
    }
    const Direction direction = DisplaysInfo.front().direction;
    if (direction < Direction::DIRECTION0 || direction > Direction::DIRECTION270) {
        MMI_HILOGE("direction is invalid, direction:%{public}d", direction);
        return;
    }
    Coordinate2D matrix { 0.0, 0.0 };
    ReverseRotateScreen(DisplaysInfo.front(), x, y, matrix);
    x = static_cast<int32_t>(matrix.x);
    y = static_cast<int32_t>(matrix.y);
}

void InputWindowsManager::SendCancelEventWhenLock()
{
    CALL_INFO_TRACE;
    CHKPV(lastTouchEventOnBackGesture_);
    if (lastTouchEventOnBackGesture_->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        lastTouchEventOnBackGesture_->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN) {
            return;
    }
    lastTouchEventOnBackGesture_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    lastTouchEventOnBackGesture_->SetActionTime(GetSysClockTime());
    lastTouchEventOnBackGesture_->UpdateId();
    lastTouchEventOnBackGesture_->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
    auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPV(inputEventNormalizeHandler);
    MMI_HILOGI("Screen locked, Send cancel event");
    inputEventNormalizeHandler->HandleTouchEvent(lastTouchEventOnBackGesture_);
    auto iter = touchItemDownInfos_.find(lastTouchEventOnBackGesture_->GetPointerId());
    if (iter != touchItemDownInfos_.end()) {
        iter->second.flag = false;
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

bool InputWindowsManager::IsTransparentWin(
    std::unique_ptr<Media::PixelMap> &pixelMap, int32_t logicalX, int32_t logicalY)
    __attribute__((no_sanitize("cfi")))
{
    CALL_DEBUG_ENTER;
    if (pixelMap == nullptr) {
        return false;
    }

    uint32_t dst = 0;
    OHOS::Media::Position pos { logicalX, logicalY };
    uint32_t result = pixelMap->ReadPixel(pos, dst);
    if (result != RET_OK) {
        MMI_HILOGE("Failed to read pixelmap");
        return false;
    }
    MMI_HILOGD("dst:%{public}d, byteCount:%{public}d, width:%{public}d, height:%{public}d",
        dst, pixelMap->GetByteCount(), pixelMap->GetWidth(), pixelMap->GetHeight());
    return dst == RET_OK;
}

int32_t InputWindowsManager::SetCurrentUser(int32_t userId)
{
    return RET_OK;
}

void InputWindowsManager::PrintChangedWindowByEvent(int32_t eventType, const WindowInfo &newWindowInfo)
{
    auto iter = lastMatchedWindow_.find(eventType);
    if (iter != lastMatchedWindow_.end() && iter->second.id != newWindowInfo.id) {
        MMI_HILOGI("Target window changed %{public}d %{public}d %{public}d %{public}f "
            "%{public}d %{public}d %{public}f", eventType, iter->second.id, iter->second.pid,
            iter->second.zOrder, newWindowInfo.id, newWindowInfo.pid, newWindowInfo.zOrder);
    }
    lastMatchedWindow_[eventType] = newWindowInfo;
}

void InputWindowsManager::PrintChangedWindowBySync(const OLD::DisplayGroupInfo &newDisplayInfo)
{
    auto &WindowsInfo = GetWindowInfoVector(newDisplayInfo.groupId);
    auto &oldWindows = WindowsInfo;
    auto &newWindows = newDisplayInfo.windowsInfo;
    if (!oldWindows.empty() && !newWindows.empty()) {
        if (oldWindows[0].id != newWindows[0].id) {
            MMI_HILOGI("Window sync changed %{public}d %{public}d %{public}f %{public}d %{public}d %{public}f",
                oldWindows[0].id, oldWindows[0].pid, oldWindows[0].zOrder, newWindows[0].id,
                newWindows[0].pid, newWindows[0].zOrder);
        }
    }
    auto &DisplaysInfo = GetDisplayInfoVector(newDisplayInfo.groupId);
    if (newDisplayInfo.displaysInfo.empty() || DisplaysInfo.empty()) {
        MMI_HILOGE("displayGroupInfo.displaysInfo is empty");
        return;
    }
    for (const auto &item : newDisplayInfo.displaysInfo) {
        int32_t displayId = item.id;
        auto iter = std::find_if(DisplaysInfo.begin(), DisplaysInfo.end(),
            [displayId](const auto& displayInfo) {
            return displayId == displayInfo.id;
        });
        if (iter == DisplaysInfo.end()) {
            continue;
        }
        if (item.direction != iter->direction || item.displayDirection != iter->displayDirection) {
            MMI_HILOGI("displayInfos,id:%{public}d,x:%{private}d,y:%{private}d,width:%{public}d,height:%{public}d,"
                "name:%{public}s,uniq:%{public}s,direction:%{public}d,displayDirection:%{public}d,"
                "oldDirection:%{public}d,oldDisplayDirection:%{public}d", item.id, item.x, item.y, item.width,
                item.height, item.name.c_str(), item.uniq.c_str(), item.direction, item.displayDirection,
                iter->direction, iter->displayDirection);
        }
    }
}

bool InputWindowsManager::ParseConfig()
{
    std::string defaultConfig = "/system/etc/multimodalinput/white_list_config.json";
    return ParseJson(defaultConfig);
}

bool InputWindowsManager::ParseJson(const std::string &configFile)
{
    CALL_DEBUG_ENTER;
    std::string jsonStr = ReadJsonFile(configFile);
    if (jsonStr.empty()) {
        MMI_HILOGE("Read configFile failed");
        return false;
    }
    JsonParser jsonData(jsonStr.c_str());
    if (!cJSON_IsObject(jsonData.Get())) {
        MMI_HILOGE("The json data is not object");
        return false;
    }
    cJSON* whiteList = cJSON_GetObjectItemCaseSensitive(jsonData.Get(), "whiteList");
    if (!cJSON_IsArray(whiteList)) {
        MMI_HILOGE("White list number must be array");
        return false;
    }
    int32_t whiteListSize = cJSON_GetArraySize(whiteList);
    for (int32_t i = 0; i < whiteListSize; ++i) {
        cJSON *whiteListJson = cJSON_GetArrayItem(whiteList, i);
        if (!cJSON_IsObject(whiteListJson)) {
            MMI_HILOGE("White list json is not object");
            continue;
        }
        SwitchFocusKey switchFocusKey;
        cJSON *keyCodeJson = cJSON_GetObjectItemCaseSensitive(whiteListJson, "keyCode");
        if (!cJSON_IsNumber(keyCodeJson)) {
            MMI_HILOGE("Key code json is not number");
            continue;
        }
        switchFocusKey.keyCode = keyCodeJson->valueint;
        cJSON *pressedKeyJson = cJSON_GetObjectItemCaseSensitive(whiteListJson, "pressedKey");
        if (!cJSON_IsNumber(pressedKeyJson)) {
            MMI_HILOGE("Pressed key json is not number");
            continue;
        }
        switchFocusKey.pressedKey = pressedKeyJson->valueint;
        vecWhiteList_.push_back(switchFocusKey);
    }
    return true;
}

void InputWindowsManager::SetWindowStateNotifyPid(int32_t pid)
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        windowStateNotifyPid_ = pid;
    }
}

int32_t InputWindowsManager::GetWindowStateNotifyPid()
{
    return windowStateNotifyPid_;
}

int32_t InputWindowsManager::GetPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId)
{
    int32_t groupId = FindDisplayGroupId(displayId);
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (auto &item : WindowsInfo) {
        if (item.id == windowId) {
            return item.pid;
        }
        for (const auto &uiExtentionWindow : item.uiExtentionWindowInfo) {
            if (uiExtentionWindow.id == windowId) {
                return uiExtentionWindow.pid;
            }
        }
    }
    return RET_ERR;
}

int32_t InputWindowsManager::GetAgentPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId)
{
    int32_t groupId = FindDisplayGroupId(displayId);
    auto &WindowsInfo = GetWindowInfoVector(groupId);
    for (auto &item : WindowsInfo) {
        if (item.id == windowId) {
            return item.agentPid;
        }
        for (const auto &uiExtentionWindow : item.uiExtentionWindowInfo) {
            if (uiExtentionWindow.id == windowId) {
                return uiExtentionWindow.agentPid;
            }
        }
    }
    return RET_ERR;
}
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool InputWindowsManager::IsKeyPressed(int32_t pressedKey, std::vector<KeyEvent::KeyItem> &keyItems)
{
    CALL_DEBUG_ENTER;
    for (const auto &item : keyItems) {
        if (item.GetKeyCode() == pressedKey && item.IsPressed()) {
            return true;
        }
    }
    return false;
}

bool InputWindowsManager::IsOnTheWhitelist(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(keyEvent);
    for (const auto &item : vecWhiteList_) {
        if (item.keyCode == keyEvent->GetKeyCode()) {
            auto keyItems = keyEvent->GetKeyItems();
            if (item.pressedKey == -1 && keyItems.size() == 1) {
                return true;
            }
            bool flag = ((item.pressedKey != -1) && (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) &&
                (keyItems.size() == 2) && IsKeyPressed(item.pressedKey, keyItems));
            if (flag) {
                return true;
            }
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::SetPixelMapData(int32_t infoId, void *pixelMap)
    __attribute__((no_sanitize("cfi")))
{
    CALL_DEBUG_ENTER;
    if (infoId < 0 || pixelMap == nullptr) {
        MMI_HILOGE("The infoId is invalid or pixelMap is nullptr");
        return ERR_INVALID_VALUE;
    }
    std::unique_ptr<OHOS::Media::PixelMap> pixelMapSource(
        static_cast<OHOS::Media::PixelMap*>(pixelMap));
    Media::InitializationOptions opts;
    auto pixelMapPtr = OHOS::Media::PixelMap::Create(*pixelMapSource, opts);
    CHKPR(pixelMapPtr, RET_ERR);
    MMI_HILOGD("The byteCount:%{public}d, width:%{public}d, height:%{public}d",
        pixelMapPtr->GetByteCount(), pixelMapPtr->GetWidth(), pixelMapPtr->GetHeight());
    transparentWins_.insert_or_assign(infoId, std::move(pixelMapPtr));
    return RET_OK;
}

void InputWindowsManager::CleanInvalidPiexMap(int32_t groupId)
{
    auto &WindowInfo = GetWindowInfoVector(groupId);
    for (auto it = transparentWins_.begin(); it != transparentWins_.end();) {
        int32_t windowId = it->first;
        auto iter = std::find_if(WindowInfo.begin(), WindowInfo.end(),
            [windowId](const auto &window) {
                return window.id == windowId;
        });
        if (iter == WindowInfo.end()) {
            it = transparentWins_.erase(it);
        } else {
            ++it;
        }
    }
}

#ifdef OHOS_BUILD_ENABLE_ANCO
bool InputWindowsManager::IsKnuckleOnAncoWindow(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointerEvent);
    PointerEvent::PointerItem pointerItem {};
    int32_t pointerId = pointerEvent->GetPointerId();
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Get pointer item failed, pointer:%{public}d", pointerId);
        return false;
    }

    if (pointerItem.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE) {
        return false;
    }

    int32_t groupId = FindDisplayGroupId(pointerEvent->GetTargetDisplayId());
    const int32_t focusWindowId = GetFocusWindowId(groupId);
    WindowInfo *windowInfo = nullptr;
    std::vector<WindowInfo> windowInfos = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    auto iter = find_if(windowInfos.begin(), windowInfos.end(),
        [&](const auto &item) { return item.id == focusWindowId; });
    if (iter != windowInfos.end()) {
        windowInfo = &(*iter);
    }

    if (windowInfo == nullptr) {
        MMI_HILOGE("windowInfo is nullptr");
        return false;
    }

    return IsAncoWindowFocus(*windowInfo);
}
#endif // OHOS_BUILD_ENABLE_ANCO

void InputWindowsManager::UpdateKeyEventDisplayId(std::shared_ptr<KeyEvent> keyEvent,
    int32_t focusWindowId, int32_t groupId)
{
    CHKPV(keyEvent);
    bool hasFound = false;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplayTmp = windowsPerDisplay_;
    const auto iter = windowsPerDisplayMap_.find(groupId);
    if (iter != windowsPerDisplayMap_.end()) {
        windowsPerDisplayTmp = iter->second;
    }
    for (const auto &item : windowsPerDisplayTmp) {

        if (item.second.focusWindowId == focusWindowId) {
            keyEvent->SetTargetDisplayId(item.second.displayId);
            hasFound = true;
        }
    }
    auto &DisplaysInfo = GetDisplayInfoVector(groupId);
    if (!hasFound && !DisplaysInfo.empty()) {
        keyEvent->SetTargetDisplayId(DisplaysInfo[0].id);
    }
}

bool InputWindowsManager::OnDisplayRemovedOrCombinationChanged(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    auto &displaysInfoVector = GetDisplayInfoVector(displayGroupInfo.groupId);
    if (displayGroupInfo.displaysInfo.empty() || displaysInfoVector.empty()) {
        return false;
    }
    if (displayGroupInfo.displaysInfo.size() < displaysInfoVector.size()) {
        MMI_HILOGD("display has been removed");
        return true;
    }
    OLD::DisplayInfo newMainDisplayInfo;
    OLD::DisplayInfo oldMainDisplayInfo;
    (void)GetMainScreenDisplayInfo(displayGroupInfo.displaysInfo, newMainDisplayInfo);
    (void)GetMainScreenDisplayInfo(displaysInfoVector, oldMainDisplayInfo);
    MMI_HILOGI("newMainDisplayInfo:%{public}" PRIu64 ", oldMainDisplayInfo:%{public}" PRIu64,
        newMainDisplayInfo.rsId, oldMainDisplayInfo.rsId);
    if (displayGroupInfo.displaysInfo.size() == displaysInfoVector.size() &&
        newMainDisplayInfo.rsId != oldMainDisplayInfo.rsId) {
        MMI_HILOGD("current mainScreenDisplayId changed");
        return true;
    }
    return false;
}

bool InputWindowsManager::GetHardCursorEnabled()
{
    return CursorDrawingComponent::GetInstance().GetHardCursorEnabled();
}

void InputWindowsManager::SetFoldState()
{
    BytraceAdapter::StartFoldState(Rosen::DisplayManagerLite::GetInstance().IsFoldable());
    auto begin = std::chrono::high_resolution_clock::now();
    IsFoldable_ = Rosen::DisplayManagerLite::GetInstance().IsFoldable();
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::IS_FOLDABLE, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    BytraceAdapter::StopFoldState();
}

const OLD::DisplayInfo *InputWindowsManager::GetPhysicalDisplay(int32_t id,
    const OLD::DisplayGroupInfo &displayGroupInfo) const
{
    for (const auto &it : displayGroupInfo.displaysInfo) {
        if (it.id == id) {
            return &it;
        }
    }
    MMI_HILOGW("Failed to obtain physical(%{public}d) display", id);
    return nullptr;
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
std::optional<WindowInfo> InputWindowsManager::GetWindowInfoById(int32_t windowId) const
{
    for (const auto &it : windowsPerDisplayMap_) {
        for (auto iter = it.second.begin(); iter != it.second.end(); ++iter) {
            int32_t displayId = iter->first;
            if (displayId < 0) {
                MMI_HILOGE("windowsPerDisplay_ contain invalid displayId:%{public}d", displayId);
                continue;
            }
            for (const auto& item : iter->second.windowsInfo) {
                CHKCC(item.id == windowId &&
                    (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) != WindowInfo::FLAG_BIT_UNTOUCHABLE &&
                    transparentWins_.find(item.id) == transparentWins_.end());
                return std::make_optional(item);
            }
        }
    }
    return std::nullopt;
}

int32_t InputWindowsManager::ShiftAppMousePointerEvent(const ShiftWindowInfo &shiftWindowInfo, bool autoGenDown)
{
    auto lastPointerEventCopy = GetlastPointerEvent();
    if (!lastPointerEventCopy || !lastPointerEventCopy->IsButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT)) {
        MMI_HILOGE("Failed shift pointerEvent, left mouse button is not pressed");
        return RET_ERR;
    }
    const WindowInfo &sourceWindowInfo = shiftWindowInfo.sourceWindowInfo;
    const WindowInfo &targetWindowInfo = shiftWindowInfo.targetWindowInfo;
    std::shared_ptr<PointerEvent> pointerEvent = std::make_shared<PointerEvent>(*lastPointerEventCopy);
    pointerEvent->ClearButtonPressed();

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(pointerId, item);
    item.SetWindowX(lastLogicX_ - sourceWindowInfo.area.x);
    item.SetWindowY(lastLogicY_ - sourceWindowInfo.area.y);
    item.SetWindowXPos(lastLogicX_ - sourceWindowInfo.area.x);
    item.SetWindowYPos(lastLogicY_ - sourceWindowInfo.area.y);
    item.SetPressed(false);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->SetTargetDisplayId(sourceWindowInfo.displayId);
    pointerEvent->SetTargetWindowId(sourceWindowInfo.id);
    pointerEvent->SetAgentWindowId(sourceWindowInfo.agentWindowId);
    ClearTargetWindowId(pointerId, pointerEvent->GetDeviceId());
    pointerEvent->UpdatePointerItem(pointerId, item);
    auto filter = InputHandler->GetFilterHandler();
    CHKPR(filter, RET_ERR);
    filter->HandlePointerEvent(pointerEvent);
    if (autoGenDown) {
        item.SetWindowX(shiftWindowInfo.x);
        item.SetWindowY(shiftWindowInfo.y);
        item.SetWindowXPos(shiftWindowInfo.x);
        item.SetWindowYPos(shiftWindowInfo.y);
        if (shiftWindowInfo.x == -1 && shiftWindowInfo.y == -1) {
            item.SetWindowX(lastLogicX_ - targetWindowInfo.area.x);
            item.SetWindowY(lastLogicY_ - targetWindowInfo.area.y);
            item.SetWindowXPos(lastLogicX_ - targetWindowInfo.area.x);
            item.SetWindowYPos(lastLogicY_ - targetWindowInfo.area.y);
        }
        item.SetPressed(true);
        pointerEvent->ClearButtonPressed();
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
        pointerEvent->UpdatePointerItem(pointerId, item);
        pointerEvent->SetTargetDisplayId(targetWindowInfo.displayId);
        pointerEvent->SetTargetWindowId(targetWindowInfo.id);
        pointerEvent->SetAgentWindowId(targetWindowInfo.agentWindowId);
        HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "shift pointer event dispatch down event");
        filter->HandlePointerEvent(pointerEvent);
    }
    firstBtnDownWindowInfo_.first = targetWindowInfo.id;
    firstBtnDownWindowInfo_.second = targetWindowInfo.displayId;
    mouseDownInfo_ = targetWindowInfo;
    MMI_HILOGI("shift pointer event success for mouse");
    return RET_OK;
}

int32_t InputWindowsManager::ShiftAppSimulateTouchPointerEvent(const ShiftWindowInfo &shiftWindowInfo)
{
    CHKPR(lastTouchEvent_, RET_ERR);
    const WindowInfo &sourceWindowInfo = shiftWindowInfo.sourceWindowInfo;
    const WindowInfo &targetWindowInfo = shiftWindowInfo.targetWindowInfo;
    PointerEvent::PointerItem item;
    if (!lastTouchEvent_->GetPointerItem(shiftWindowInfo.fingerId, item) &&
        !lastTouchEvent_->GetOriginPointerItem(shiftWindowInfo.fingerId, item)) {
        MMI_HILOGE("Get pointer item failed");
        return RET_ERR;
    }
    if (!item.IsPressed()) {
        MMI_HILOGE("Failed shift pointerEvent, fingerId:%{public}d is not pressed", shiftWindowInfo.fingerId);
        return RET_ERR;
    }
    item.SetWindowX(lastTouchLogicX_ - sourceWindowInfo.area.x);
    item.SetWindowY(lastTouchLogicY_ - sourceWindowInfo.area.y);
    item.SetWindowXPos(lastTouchLogicX_ - sourceWindowInfo.area.x);
    item.SetWindowYPos(lastTouchLogicY_ - sourceWindowInfo.area.y);
    item.SetPressed(false);
    item.SetTargetWindowId(sourceWindowInfo.id);
    item.SetPointerId(shiftWindowInfo.fingerId);
    lastTouchEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    lastTouchEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    lastTouchEvent_->SetPointerId(shiftWindowInfo.fingerId);
    lastTouchEvent_->SetTargetDisplayId(sourceWindowInfo.displayId);
    lastTouchEvent_->SetTargetWindowId(sourceWindowInfo.id);
    lastTouchEvent_->SetAgentWindowId(sourceWindowInfo.agentWindowId);
    lastTouchEvent_->UpdateId();
    ClearTargetWindowId(shiftWindowInfo.fingerId, lastTouchEvent_->GetDeviceId());
    lastTouchEvent_->UpdatePointerItem(shiftWindowInfo.fingerId, item);
    auto filter = InputHandler->GetFilterHandler();
    CHKPR(filter, RET_ERR);
    filter->HandlePointerEvent(lastTouchEvent_);
    item.SetWindowX(shiftWindowInfo.x);
    item.SetWindowY(shiftWindowInfo.y);
    item.SetWindowXPos(shiftWindowInfo.x);
    item.SetWindowYPos(shiftWindowInfo.y);
    if (shiftWindowInfo.x == -1 && shiftWindowInfo.y == -1) {
        item.SetWindowX(lastTouchLogicX_ - targetWindowInfo.area.x);
        item.SetWindowY(lastTouchLogicY_ - targetWindowInfo.area.y);
        item.SetWindowXPos(lastTouchLogicX_ - targetWindowInfo.area.x);
        item.SetWindowYPos(lastTouchLogicY_ - targetWindowInfo.area.y);
    }
    item.SetPressed(true);
    item.SetTargetWindowId(targetWindowInfo.id);
    item.SetPointerId(shiftWindowInfo.fingerId);
    lastTouchEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    lastTouchEvent_->SetTargetDisplayId(targetWindowInfo.displayId);
    lastTouchEvent_->SetPointerId(shiftWindowInfo.fingerId);
    lastTouchEvent_->SetTargetWindowId(targetWindowInfo.id);
    lastTouchEvent_->SetAgentWindowId(targetWindowInfo.agentWindowId);
    lastTouchEvent_->UpdatePointerItem(shiftWindowInfo.fingerId, item);
    HITRACE_METER_NAME(HITRACE_TAG_MULTIMODALINPUT, "shift touch event dispatch down event");
    filter->HandlePointerEvent(lastTouchEvent_);
    return RET_OK;
}

int32_t InputWindowsManager::ShiftAppTouchPointerEvent(const ShiftWindowInfo &shiftWindowInfo)
{
    if (shiftWindowInfo.fingerId == -1) {
        MMI_HILOGE("Failed shift touchpointerEvent, fingerId is invalid");
        return RET_ERR;
    }
    if (ShiftAppSimulateTouchPointerEvent(shiftWindowInfo) != RET_OK) {
        MMI_HILOGE("Failed shift touchPointerEvent");
        return RET_ERR;
    }
    WindowInfoEX windowInfoEX;
    windowInfoEX.window = shiftWindowInfo.targetWindowInfo;
    windowInfoEX.flag = true;
    touchItemDownInfos_[shiftWindowInfo.fingerId] = windowInfoEX;
    MMI_HILOGI("Shift pointer event success for touch");
    return RET_OK;
}

int32_t InputWindowsManager::ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown)
{
    MMI_HILOGI("Start shift pointer event, sourceWindowId:%{public}d, targetWindowId:%{public}d,"
        "x:%{private}d, y:%{private}d, autoGenDown:%{public}d",
        param.sourceWindowId, param.targetWindowId, param.x, param.y, static_cast<int32_t>(autoGenDown));
    std::optional<WindowInfo> sourceWindowInfo = GetWindowInfoById(param.sourceWindowId);
    std::optional<WindowInfo> targetWindowInfo = GetWindowInfoById(param.targetWindowId);
    if (!sourceWindowInfo || !targetWindowInfo) {
        MMI_HILOGE("Failed shift pointerEvent, get null sourceWindowInfo, source:%{public}d, target:%{public}d",
        static_cast<int32_t>(!!sourceWindowInfo), static_cast<int32_t>(!!targetWindowInfo));
        return RET_ERR;
    }
    ShiftWindowInfo shiftWindowInfo;
    shiftWindowInfo.sourceWindowInfo = *sourceWindowInfo;
    shiftWindowInfo.targetWindowInfo = *targetWindowInfo;
    shiftWindowInfo.x = param.x;
    shiftWindowInfo.y = param.y;
    shiftWindowInfo.fingerId = param.fingerId;
    shiftWindowInfo.sourceType = param.sourceType;
    if (shiftWindowInfo.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return ShiftAppTouchPointerEvent(shiftWindowInfo);
    }
    else {
        return ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown);
    }
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
bool InputWindowsManager::CancelTouch(int32_t touch)
{
    auto iter = touchItemDownInfos_.find(touch);
    if ((iter != touchItemDownInfos_.end()) && iter->second.flag) {
        iter->second.flag = false;
        return true;
    }
    return false;
}

void InputWindowsManager::AttachTouchGestureMgr(std::shared_ptr<TouchGestureManager> touchGestureMgr)
{
    touchGestureMgr_ = touchGestureMgr;
}

void InputWindowsManager::CancelAllTouches(std::shared_ptr<PointerEvent> event, bool isDisplayChanged)
{
    CHKPV(event);
    auto pointerEvent = std::make_shared<PointerEvent>(*event);
    int32_t originAction = pointerEvent->GetPointerAction();
    pointerEvent->SetOriginPointerAction(originAction);
    auto items = event->GetAllPointerItems();
    for (const auto &item : items) {
        if (!item.IsPressed()) {
            continue;
        }
        int32_t pointerId = item.GetPointerId();
        int32_t action = PointerEvent::POINTER_ACTION_CANCEL;
        bool isDragging = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
                          (item.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId);
        if (isDragging) {
            action = PointerEvent::POINTER_ACTION_PULL_CANCEL;
        }
        pointerEvent->SetPointerAction(action);
        if (isDisplayChanged) {
            pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
        } else {
            pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
        }
        pointerEvent->SetPointerId(pointerId);

        if (AdjustFingerFlag(pointerEvent)) {
            continue;
        }
        MMI_HILOGI("Cancel touch, pointerId:%{public}d, action:%{public}d", pointerId, action);
        auto now = GetSysClockTime();
        pointerEvent->SetActionTime(now);
        pointerEvent->SetTargetWindowId(item.GetTargetWindowId());
        auto winOpt = GetWindowAndDisplayInfo(item.GetTargetWindowId(), pointerEvent->GetTargetDisplayId());
        if (winOpt) {
            pointerEvent->SetAgentWindowId(winOpt->agentWindowId);
        }
        pointerEvent->UpdateId();
        auto filter = InputHandler->GetFilterHandler();
        CHKPV(filter);
        filter->HandleTouchEvent(pointerEvent);
        CancelTouch(item.GetPointerId());
    }
}

#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)

std::shared_ptr<PointerEvent> InputWindowsManager::GetlastPointerEvent()
{
    std::lock_guard<std::mutex> guard(mtx_);
    return lastPointerEvent_;
}

std::pair<int32_t, int32_t> InputWindowsManager::CalcDrawCoordinate(const OLD::DisplayInfo& displayInfo,
    PointerEvent::PointerItem pointerItem)
{
    CALL_DEBUG_ENTER;
    double physicalX = pointerItem.GetRawDisplayX();
    double physicalY = pointerItem.GetRawDisplayY();
    if (!displayInfo.transform.empty()) {
        auto displayXY = TransformDisplayXY(displayInfo, physicalX, physicalY);
        physicalX = displayXY.first;
        physicalY = displayXY.second;
    }
    return {static_cast<int32_t>(physicalX), static_cast<int32_t>(physicalY)};
}

void InputWindowsManager::SetDragFlagByPointer(std::shared_ptr<PointerEvent> lastPointerEvent)
{
    if (lastPointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        dragFlag_ = true;
        MMI_HILOGD("Is in drag scene");
    }
    if (lastPointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
        dragFlag_ = false;
        isDragBorder_ = false;
    }
}

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
void InputWindowsManager::TouchEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    CHKPV(touchWindow);
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = pointerEvent->GetPointerId();
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", pointerId);
        return;
    }
    int32_t windowX = pointerItem.GetWindowX();
    int32_t windowY = pointerItem.GetWindowY();
    windowX = std::max(currentDisplayXY_.first, std::min(windowX, touchWindow->area.width));
    windowY = std::max(currentDisplayXY_.second, std::min(windowY, touchWindow->area.height));
    if (touchWindow->windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) {
        pointerItem.SetWindowX(windowX);
        pointerItem.SetWindowY(windowY);
        pointerItem.SetWindowXPos(windowX);
        pointerItem.SetWindowYPos(windowY);
        pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    }
    if (lastTouchWindowInfo_.id != touchWindow->id) {
        if (lastTouchWindowInfo_.id != -1 &&
            lastTouchWindowInfo_.windowInputType == WindowInputType::SLID_TOUCH_WINDOW) {
            MMI_HILOG_DISPATCHI("Send cancel to slid touch window, "
                "lastWindowType:%{public}d, nowWindowType:%{public}d",
                static_cast<int32_t>(lastTouchWindowInfo_.windowInputType),
                static_cast<int32_t>(touchWindow->windowInputType));
            DispatchTouch(PointerEvent::POINTER_ACTION_CANCEL);
            MMI_HILOG_DISPATCHI("Send down-action to the new window, (lastWId:%{public}d, LastPId:%{public}d), "
                "(newWId:%{public}d, newWId:%{public}d)",
                lastTouchWindowInfo_.id, lastTouchWindowInfo_.pid, touchWindow->id, touchWindow->pid);
            lastTouchLogicX_ = logicalX;
            lastTouchLogicY_ = logicalY;
            lastTouchEvent_ = pointerEvent;
            lastTouchWindowInfo_ = *touchWindow;
            lockWindowInfo_ = *touchWindow;
            DispatchTouch(PointerEvent::POINTER_ACTION_DOWN);
            return;
        }
    }
    lastTouchLogicX_ = logicalX;
    lastTouchLogicY_ = logicalY;
    lastTouchEvent_ = pointerEvent;
    lastTouchWindowInfo_ = *touchWindow;
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

bool InputWindowsManager::IsAccessibilityFocusEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    static std::unordered_set<int32_t> accessibilityEventAction {
        PointerEvent::POINTER_ACTION_HOVER_MOVE,
        PointerEvent::POINTER_ACTION_HOVER_ENTER,
        PointerEvent::POINTER_ACTION_HOVER_EXIT,
        PointerEvent::POINTER_ACTION_HOVER_CANCEL
    };
    auto pointerAction = pointerEvent->GetPointerAction();
    return accessibilityEventAction.find(pointerAction) != accessibilityEventAction.end();
}

bool InputWindowsManager::IsAccessibilityEventWithZorderInjected(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(pointerEvent);
    if (IsAccessibilityFocusEvent(pointerEvent) && pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE) &&
        pointerEvent->GetZOrder() > 0) {
        return true;
    }
    return false;
}

bool InputWindowsManager::NeedTouchTracking(PointerEvent &event) const
{
    if (!event.HasFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY)) {
        return false;
    }
    if (event.GetPointerAction() != PointerEvent::POINTER_ACTION_HOVER_MOVE) {
        return false;
    }
    return (event.GetPointerCount() == SINGLE_TOUCH);
}

void InputWindowsManager::ProcessTouchTracking(std::shared_ptr<PointerEvent> event, const WindowInfo &targetWindow)
{
    if (!NeedTouchTracking(*event)) {
        return;
    }
    if (event->GetTargetWindowId() == targetWindow.id) {
        return;
    }
    PointerEvent::PointerItem pointerItem {};
    if (!event->GetPointerItem(event->GetPointerId(), pointerItem)) {
        MMI_HILOGE("Corrupted pointer event, No:%{public}d,PI:%{public}d", event->GetId(), event->GetPointerId());
        return;
    }
    pointerItem.SetPressed(false);
    event->UpdatePointerItem(event->GetPointerId(), pointerItem);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_CANCEL);

    auto normalizeHandler = InputHandler->GetEventNormalizeHandler();
    CHKPV(normalizeHandler);
    normalizeHandler->HandleTouchEvent(event);

    pointerItem.SetPressed(true);
    event->UpdatePointerItem(event->GetPointerId(), pointerItem);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
}

int32_t InputWindowsManager::ClearMouseHideFlag(int32_t eventId)
{
    auto pointerEvent = GetlastPointerEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t lastEventId = pointerEvent->GetId();
    MMI_HILOGI("eventId=%{public}d, lastEventId=%{public}d", eventId, lastEventId);
    if (lastEventId == eventId) {
        DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        pointerEvent->ClearFlag(InputEvent::EVENT_FLAG_HIDE_POINTER);
        MMI_HILOGI("clear hide flag succ.");
        return RET_OK;
    }
    return RET_ERR;
}

void InputWindowsManager::GetActiveWindowTypeById(int32_t windowId, WindowInputType &windowTypeTemp)
{
    auto it = activeTouchWinTypes_.find(windowId);
    if (it != activeTouchWinTypes_.end()) {
        windowTypeTemp = it->second.windowInputType;
        MMI_HILOGD("GetActiveWindowTypeById success: windowId:%{public}d, windowTypeTemp:%{public}hhu",
            windowId,
            it->second.windowInputType);
    }
}

void InputWindowsManager::AddActiveWindow(int32_t windowId, int32_t pointerId)
{
    auto it = activeTouchWinTypes_.find(windowId);
    if (it != activeTouchWinTypes_.end()) {
        it->second.pointerSet.emplace(pointerId);
        MMI_HILOGD("AddActiveWindow success: windowId:%{public}d, windowType:%{public}hhu, "
                   "pointerId:%{public}d, pointerSet:%{public}zu",
            windowId,
            it->second.windowInputType,
            pointerId,
            it->second.pointerSet.size());
    } else {
        std::optional<WindowInfo> info = GetWindowInfoById(windowId);
        if (!info) {
            MMI_HILOGE("Failed to add active window: windowInfo with windowId:%{public}d not found", windowId);
            return;
        }
        activeTouchWinTypes_.emplace(windowId, ActiveTouchWin{(*info).windowInputType, { pointerId }});
    }
}

void InputWindowsManager::RemoveActiveWindow(std::shared_ptr<PointerEvent> pointerEvent)
{
    auto pointerAc = pointerEvent->GetPointerAction();
    if (pointerAc != PointerEvent::POINTER_ACTION_UP && pointerAc != PointerEvent::POINTER_ACTION_PULL_UP &&
        pointerAc != PointerEvent::POINTER_ACTION_CANCEL && pointerAc != PointerEvent::POINTER_ACTION_PULL_THROW) {
        return;
    }
    auto pointerId = pointerEvent->GetPointerId();
    for (auto it = activeTouchWinTypes_.begin(); it != activeTouchWinTypes_.end();) {
        auto pointerIter = it->second.pointerSet.find(pointerId);
        if (pointerIter != it->second.pointerSet.end()) {
            it->second.pointerSet.erase(pointerIter);
            MMI_HILOGD("RemoveActiveWindow success: windowId:%{public}d, windowType:%{public}hhu, "
                       "pointerId:%{public}d, pointerSet:%{public}zu, isInject:%{public}d",
                it->first,
                it->second.windowInputType,
                pointerId,
                it->second.pointerSet.size(),
                pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE));
        }
        if (it->second.pointerSet.empty()) {
            MMI_HILOGD("RemoveActiveWindow success: erase windowId:%{public}d, windowType:%{public}hhu",
                it->first,
                it->second.windowInputType);
            it = activeTouchWinTypes_.erase(it);
        } else {
            ++it;
        }
    }
}

void InputWindowsManager::ClearActiveWindow()
{
    activeTouchWinTypes_.clear();
    MMI_HILOGD("ClearActiveWindow success");
}

void InputWindowsManager::UpdateWindowInfoFlag(uint32_t flag, std::shared_ptr<InputEvent> event)
{
    CHKPV(event);
    MMI_HILOGD("UpdateWindowInfoFlag :flag %{public}d", flag);
    if ((flag & WindowInfo::FLAG_BIT_DISABLE_USER_ACTION)
        == WindowInfo::FLAG_BIT_DISABLE_USER_ACTION) {
        event->AddFlag(InputEvent::EVENT_FLAG_DISABLE_USER_ACTION);
    } else {
        event->ClearFlag(InputEvent::EVENT_FLAG_DISABLE_USER_ACTION);
    }
}
} // namespace MMI
} // namespace OHOS
