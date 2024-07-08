/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <linux/input.h>
#include <unordered_map>

#include "cJSON.h"
#include "dfx_hisysevent.h"
#include "event_log_helper.h"
#include "fingersense_wrapper.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "i_pointer_drawing_manager.h"
#include "mouse_event_normalize.h"
#include "pointer_drawing_manager.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "util.h"
#include "mmi_matrix3.h"
#include "util_ex.h"
#include "util_napi_error.h"
#include "input_device_manager.h"
#include "scene_board_judgement.h"
#include "i_preference_manager.h"
#include "parameters.h"
#include "setting_datashare.h"
#include "system_ability_definition.h"
#include "timer_manager.h"
#include "touch_drawing_manager.h"
#ifdef OHOS_BUILD_ENABLE_ANCO
#include "res_sched_client.h"
#include "res_type.h"
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "magic_pointer_velocity_tracker.h"
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManager"

namespace OHOS {
namespace MMI {
namespace {
#ifdef OHOS_BUILD_ENABLE_POINTER
constexpr int32_t DEFAULT_POINTER_STYLE { 0 };
constexpr int32_t CURSOR_CIRCLE_STYLE { 41 };
#endif // OHOS_BUILD_ENABLE_POINTER
constexpr int32_t OUTWINDOW_HOT_AREA { 20 };
constexpr int32_t SCALE_X { 0 };
constexpr int32_t SCALE_Y { 4 };
constexpr int32_t TOP_LEFT_AREA { 0 };
constexpr int32_t TOP_AREA { 1 };
constexpr int32_t TOP_RIGHT_AREA { 2 };
constexpr int32_t RIGHT_AREA { 3 };
constexpr int32_t BOTTOM_RIGHT_AREA { 4 };
constexpr int32_t BOTTOM_AREA { 5 };
constexpr int32_t BOTTOM_LEFT_AREA { 6 };
constexpr int32_t LEFT_AREA { 7 };
constexpr int32_t WAIT_TIME_FOR_REGISTER { 2000 };
constexpr int32_t RS_PROCESS_TIMEOUT { 500 * 1000 };
#ifdef OHOS_BUILD_ENABLE_ANCO
constexpr int32_t SHELL_WINDOW_COUNT { 1 };
#endif // OHOS_BUILD_ENABLE_ANCO
constexpr double HALF_RATIO { 0.5 };
constexpr int32_t TWOFOLD { 2 };
const std::string BIND_CFG_FILE_NAME { "/data/service/el1/public/multimodalinput/display_bind.cfg" };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string DEFAULT_ICON_PATH { "/system/etc/multimodalinput/mouse_icon/Default.svg" };
const std::string NAVIGATION_SWITCH_NAME { "settings.input.stylus_navigation_hint" };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
constexpr int32_t WINDOW_ROTATE { 0 };
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
    MMI_HILOGI("Bind cfg file name:%{public}s", BIND_CFG_FILE_NAME.c_str());
    lastWindowInfo_.id = -1;
    lastWindowInfo_.pid = -1;
    lastWindowInfo_.uid = -1;
    lastWindowInfo_.agentWindowId = -1;
    lastWindowInfo_.area = { 0, 0, 0, 0 };
    lastWindowInfo_.flags = -1;
    lastWindowInfo_.windowType = 0;
    mouseDownInfo_.id = -1;
    mouseDownInfo_.pid = -1;
    mouseDownInfo_.uid = -1;
    mouseDownInfo_.agentWindowId = -1;
    mouseDownInfo_.area = { 0, 0, 0, 0 };
    mouseDownInfo_.flags = -1;
    lastTouchWindowInfo_.id = -1;
    lastTouchWindowInfo_.pid = -1;
    lastTouchWindowInfo_.uid = -1;
    lastTouchWindowInfo_.agentWindowId = -1;
    lastTouchWindowInfo_.area = { 0, 0, 0, 0 };
    lastTouchWindowInfo_.flags = -1;
    lastTouchWindowInfo_.windowType = 0;
    displayGroupInfoTmp_.focusWindowId = -1;
    displayGroupInfoTmp_.width = 0;
    displayGroupInfoTmp_.height = 0;
    displayGroupInfo_.focusWindowId = -1;
    displayGroupInfo_.width = 0;
    displayGroupInfo_.height = 0;
    mouseDownInfo_.windowType = 0;
}

InputWindowsManager::~InputWindowsManager()
{
    CALL_INFO_TRACE;
    if (Rosen::DisplayManager::GetInstance().IsFoldable()) {
        UnregisterFoldStatusListener();
    }
}

void InputWindowsManager::DeviceStatusChanged(int32_t deviceId, const std::string &sysUid, const std::string devStatus)
{
    CALL_INFO_TRACE;
    if (devStatus == "add") {
        bindInfo_.AddInputDevice(deviceId, sysUid);
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
        [this] (int32_t deviceId, const std::string &sysUid, const std::string devStatus) {
            return this->DeviceStatusChanged(deviceId, sysUid, devStatus);
        }
        );
    TimerMgr->AddTimer(WAIT_TIME_FOR_REGISTER, 1, [this]() {
        MMI_HILOG_HANDLERD("Timer callback");
        RegisterFoldStatusListener();
    });
}

void InputWindowsManager::RegisterFoldStatusListener()
{
    CALL_INFO_TRACE;
    if (!Rosen::DisplayManager::GetInstance().IsFoldable()) {
        MMI_HILOG_HANDLERD("The device is not foldable");
        return;
    }
    foldStatusListener_ = sptr<FoldStatusLisener>::MakeSptr(*this);
    CHKPV(foldStatusListener_);
    auto ret = Rosen::DisplayManager::GetInstance().RegisterFoldStatusListener(foldStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        MMI_HILOG_HANDLERE("Failed to register fold status listener");
        foldStatusListener_ = nullptr;
    } else {
        MMI_HILOG_HANDLERD("Register fold status listener successed");
    }
}

void InputWindowsManager::UnregisterFoldStatusListener()
{
    CALL_INFO_TRACE;
    CHKPV(foldStatusListener_);
    auto ret = Rosen::DisplayManager::GetInstance().UnregisterFoldStatusListener(foldStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        MMI_HILOG_HANDLERE("Failed to unregister fold status listener");
    }
}

void InputWindowsManager::FoldStatusLisener::OnFoldStatusChanged(Rosen::FoldStatus foldStatus)
{
    CALL_INFO_TRACE;
    MMI_HILOG_HANDLERD("currentFoldStatus:%{public}d, lastFoldStatus:%{public}d", foldStatus, lastFoldStatus_);
    if (lastFoldStatus_ == foldStatus) {
        MMI_HILOG_HANDLERD("No need to set foldStatus");
        return;
    }
    lastFoldStatus_ = foldStatus;
    winMgr_.OnFoldStatusChanged(foldStatus);
}

void InputWindowsManager::OnFoldStatusChanged(Rosen::FoldStatus foldStatus)
{
    if (lastPointerEventForFold_ == nullptr) {
        MMI_HILOG_HANDLERE("lastPointerEventForFold_ is nullptr");
        return;
    }
    auto items = lastPointerEventForFold_->GetAllPointerItems();
    for (const auto &item : items) {
        if (!item.IsPressed()) {
            continue;
        }
        int32_t pointerId = item.GetPointerId();
        auto pointerEvent = std::make_shared<PointerEvent>(*lastPointerEventForFold_);
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        pointerEvent->SetActionTime(GetSysClockTime());
        pointerEvent->UpdateId();
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT | InputEvent::EVENT_FLAG_NO_MONITOR);
        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPV(inputEventNormalizeHandler);
        inputEventNormalizeHandler->HandleTouchEvent(pointerEvent);
    }
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

const std::vector<WindowInfo> &InputWindowsManager::GetWindowGroupInfoByDisplayId(int32_t displayId) const
{
    CALL_DEBUG_ENTER;
    if (displayId < 0) {
        return displayGroupInfo_.windowsInfo;
    }
    auto iter = windowsPerDisplay_.find(displayId);
    if (iter == windowsPerDisplay_.end()) {
        MMI_HILOGD("GetWindowInfo displayId:%{public}d is null from windowGroupInfo_", displayId);
        return displayGroupInfo_.windowsInfo;
    }
    if (iter->second.windowsInfo.empty()) {
        MMI_HILOGW("GetWindowInfo displayId:%{public}d is empty", displayId);
        return displayGroupInfo_.windowsInfo;
    }
    return iter->second.windowsInfo;
}

int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, INVALID_FD);
    const WindowInfo* windowInfo = nullptr;
    auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
    if (iter != touchItemDownInfos_.end() && !(iter->second.flag)) {
        MMI_HILOG_DISPATCHD("Drop event");
        return INVALID_FD;
    }
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    for (const auto &item : windowsInfo) {
        bool checkUIExtentionWindow = false;
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
            break;
        }
    }
    if (windowInfo == nullptr) {
        MMI_HILOG_DISPATCHD("window info is null, pointerAction:%{public}d", pointerEvent->GetPointerAction());
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_LEAVE_WINDOW) {
            windowInfo = &lastWindowInfo_;
        }
    }
    CHKPR(udsServer_, INVALID_FD);
    if (windowInfo != nullptr) {
        FoldScreenRotation(pointerEvent);
        MMI_HILOG_DISPATCHD("get pid:%{public}d from idxPidMap", windowInfo->pid);
        return udsServer_->GetClientFd(windowInfo->pid);
    }
    if (pointerEvent->GetPointerAction() != PointerEvent::POINTER_ACTION_CANCEL) {
        MMI_HILOG_DISPATCHD("window info is null, so pointerEvent is dropped! return -1");
        return udsServer_->GetClientFd(-1);
    }
    int32_t pid = -1;
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (iter != touchItemDownInfos_.end()) {
            MMI_HILOG_DISPATCHI("Cant not find pid");
            pid = iter->second.window.pid;
            iter->second.flag = false;
            MMI_HILOG_DISPATCHD("touchscreen occurs, new pid:%{public}d", pid);
        }
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (mouseDownInfo_.pid != -1) {
            pid = GetWindowPid(mouseDownInfo_.agentWindowId);
            MMI_HILOGD("mouseevent occurs, update the pid:%{public}d", pid);
            InitMouseDownInfo();
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    MMI_HILOGD("get clientFd by %{public}d", pid);
    return udsServer_->GetClientFd(pid);
}

void InputWindowsManager::FoldScreenRotation(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    auto iter = touchItemDownInfos_.find(pointerEvent->GetPointerId());
    if (iter == touchItemDownInfos_.end()) {
        MMI_HILOG_DISPATCHD("Unable to find finger information for touch.pointerId:%{public}d",
            pointerEvent->GetPointerId());
        return;
    }
    auto displayId = pointerEvent->GetTargetDisplayId();
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPV(physicDisplayInfo);
    if (ROTATE_POLICY == WINDOW_ROTATE) {
        MMI_HILOG_DISPATCHD("Not in the unfolded state of the folding screen");
        return;
    }
    if (lastDirection_ == static_cast<Direction>(-1)) {
        lastDirection_ = physicDisplayInfo->direction;
    } else {
        if (physicDisplayInfo->direction != lastDirection_) {
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
                int32_t pointerAction = pointerEvent->GetPointerAction();
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
                pointerEvent->SetOriginPointerAction(pointerAction);
                MMI_HILOG_DISPATCHI("touch event send cancel");
                iter->second.flag = false;
            }
        }
        lastDirection_ = physicDisplayInfo->direction;
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
std::vector<std::pair<int32_t, TargetInfo>> InputWindowsManager::UpdateTarget(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    if (!isParseConfig_) {
        ParseConfig();
        isParseConfig_ = true;
    }
    std::vector<std::pair<int32_t, TargetInfo>> vecTarget;
    if (keyEvent == nullptr) {
        MMI_HILOG_DISPATCHE("keyEvent is nullptr");
        return vecTarget;
    }
    auto vecData = GetPidAndUpdateTarget(keyEvent);
    for (const auto &item : vecData) {
        int32_t fd = INVALID_FD;
        int32_t pid = item.first;
        if (pid <= 0) {
            MMI_HILOG_DISPATCHE("Invalid pid");
            continue;
        }
        fd = udsServer_->GetClientFd(pid);
        if (fd < 0) {
            MMI_HILOG_DISPATCHE("Invalid fd");
            continue;
        }
        vecTarget.emplace_back(std::make_pair(fd, item.second));
    }
    return vecTarget;
}

void InputWindowsManager::HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    int32_t focusWindowId = displayGroupInfo_.focusWindowId;
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(keyEvent->GetTargetDisplayId());
    for (auto &item : windowsInfo) {
        if (item.id == focusWindowId) {
            keyEvent->SetTargetWindowId(item.id);
            keyEvent->SetAgentWindowId(item.agentWindowId);
            return;
        }
    }
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

int32_t InputWindowsManager::GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    CHKPR(udsServer_, INVALID_FD);
    CHKPR(pointerEvent, INVALID_FD);
    const WindowInfo* windowInfo = nullptr;
    std::vector<WindowInfo> windowInfos = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    for (const auto &item : windowInfos) {
        bool checkUIExtentionWindow = false;
        for (auto &uiExtentionWindowInfo : item.uiExtentionWindowInfo) {
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
    MMI_HILOGD("Get pid:%{public}d from idxPidMap", windowInfo->pid);
    return udsServer_->GetClientFd(windowInfo->pid);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
std::vector<std::pair<int32_t, TargetInfo>> InputWindowsManager::GetPidAndUpdateTarget(
    std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    std::vector<std::pair<int32_t, TargetInfo>> vecData;
    if (keyEvent == nullptr) {
        MMI_HILOG_DISPATCHE("keyEvent is nullptr");
        return vecData;
    }
    const int32_t focusWindowId = displayGroupInfo_.focusWindowId;
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
        return vecData;
    }
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (IsAncoWindowFocus(*windowInfo)) {
        MMI_HILOG_DISPATCHD("focusWindowId:%{public}d is anco window", focusWindowId);
        return vecData;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    TargetInfo targetInfo = { windowInfo->privacyMode, windowInfo->id, windowInfo->agentWindowId };
    vecData.emplace_back(std::make_pair(windowInfo->pid, targetInfo));
    if (isUIExtention) {
        for (auto &item : iter->uiExtentionWindowInfo) {
            if (item.privacyUIFlag) {
                targetInfo.privacyMode = item.privacyMode;
                targetInfo.id = item.id;
                targetInfo.agentWindowId = item.agentWindowId;
                vecData.emplace_back(std::make_pair(item.pid, targetInfo));
            }
        }
    }
    return vecData;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t InputWindowsManager::GetWindowPid(int32_t windowId) const
{
    CALL_DEBUG_ENTER;
    int32_t windowPid = INVALID_PID;
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        MMI_HILOGD("get windowId:%{public}d", item.id);
        if (item.id == windowId) {
            windowPid = item.pid;
            break;
        }
    }
    return windowPid;
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

void InputWindowsManager::CheckFocusWindowChange(const DisplayGroupInfo &displayGroupInfo)
{
    const int32_t oldFocusWindowId = displayGroupInfo_.focusWindowId;
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
    using IdNames = std::set<std::pair<int32_t, std::string>>;
    IdNames newInfo;
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        newInfo.insert(std::make_pair(item.id, item.uniq));
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
    const auto &displayInfo = displayGroupInfo_.displaysInfo[0];
    bindInfo_.AddLocalDisplay(displayInfo.id, displayInfo.uniq);
    for (const auto &item : newInfo) {
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

void InputWindowsManager::UpdateCaptureMode(const DisplayGroupInfo &displayGroupInfo)
{
    if (captureModeInfo_.isCaptureMode && (!displayGroupInfo_.windowsInfo.empty()) &&
        ((displayGroupInfo_.focusWindowId != displayGroupInfo.focusWindowId) ||
        (displayGroupInfo_.windowsInfo[0].id != displayGroupInfo.windowsInfo[0].id))) {
        captureModeInfo_.isCaptureMode = false;
    }
}

void InputWindowsManager::UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo)
{
    CALL_DEBUG_ENTER;
    PrintWindowGroupInfo(windowGroupInfo);
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (windowGroupInfo.windowsInfo.size() == SHELL_WINDOW_COUNT && IsAncoWindow(windowGroupInfo.windowsInfo[0])) {
        return UpdateShellWindow(windowGroupInfo.windowsInfo[0]);
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    DisplayGroupInfo displayGroupInfo = displayGroupInfoTmp_;
    displayGroupInfo.focusWindowId = windowGroupInfo.focusWindowId;
    for (const auto &item : windowGroupInfo.windowsInfo) {
        UpdateDisplayInfoByIncrementalInfo(item, displayGroupInfo);
    }

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    pointerDrawFlag_ = NeedUpdatePointDrawFlag(windowGroupInfo.windowsInfo);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_ANCO
    UpdateWindowInfoExt(windowGroupInfo, displayGroupInfo);
#endif // OHOS_BUILD_ENABLE_ANCO
    UpdateDisplayInfoExtIfNeed(displayGroupInfo, false);
}

void InputWindowsManager::UpdateDisplayInfoExtIfNeed(DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt)
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
    auto physicDisplayInfo = GetPhysicalDisplay(displayGroupInfo.displaysInfo[0].id);
    CHKPV(physicDisplayInfo);
    TOUCH_DRAWING_MGR->UpdateDisplayInfo(*physicDisplayInfo);
    TOUCH_DRAWING_MGR->RotationScreen();
}

void InputWindowsManager::UpdateDisplayInfoByIncrementalInfo(const WindowInfo &window,
    DisplayGroupInfo &displayGroupInfo)
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

void InputWindowsManager::UpdateWindowsInfoPerDisplay(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay;
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
    for (const auto &item : windowsPerDisplay) {
        int32_t displayId = item.first;
        if (windowsPerDisplay_.find(displayId) != windowsPerDisplay_.end()) {
            CheckZorderWindowChange(windowsPerDisplay_[displayId].windowsInfo, item.second.windowsInfo);
        }
    }

    windowsPerDisplay_ = windowsPerDisplay;
}


void InputWindowsManager::UpdateDisplayInfo(DisplayGroupInfo &displayGroupInfo)
{
    auto action = WINDOW_UPDATE_ACTION::ADD_END;
    if (!displayGroupInfo.windowsInfo.empty()) {
        action = displayGroupInfo.windowsInfo.back().action;
    }
    MMI_HILOGD("Current action is:%{public}d", action);
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    pointerDrawFlag_ = NeedUpdatePointDrawFlag(displayGroupInfo.windowsInfo);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    std::sort(displayGroupInfo.windowsInfo.begin(), displayGroupInfo.windowsInfo.end(),
        [](const WindowInfo &lwindow, const WindowInfo &rwindow) -> bool {
        return lwindow.zOrder > rwindow.zOrder;
    });
    CheckFocusWindowChange(displayGroupInfo);
    UpdateCaptureMode(displayGroupInfo);
    displayGroupInfoTmp_ = displayGroupInfo;
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled() ||
        action == WINDOW_UPDATE_ACTION::ADD_END) {
        if ((currentUserId_ < 0) || (currentUserId_ == displayGroupInfoTmp_.currentUserId)) {
            PrintChangedWindowBySync(displayGroupInfoTmp_);
            displayGroupInfo_ = displayGroupInfoTmp_;
            UpdateWindowsInfoPerDisplay(displayGroupInfo);
        }
    }
    PrintDisplayInfo();
    UpdateDisplayIdAndName();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() && INPUT_DEV_MGR->HasPointerDevice()) {
#else
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
        UpdatePointerChangeAreas(displayGroupInfo);
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    InitPointerStyle();
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (!displayGroupInfo.displaysInfo.empty() && pointerDrawFlag_) {
        PointerDrawingManagerOnDisplayInfo(displayGroupInfo);
    }
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    UpdateDisplayMode();
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    if (INPUT_DEV_MGR->HasPointerDevice() && pointerDrawFlag_) {
        NotifyPointerToWindow();
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

DisplayMode InputWindowsManager::GetDisplayMode() const
{
    return displayMode_;
}

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
void InputWindowsManager::UpdateDisplayMode()
{
    CALL_DEBUG_ENTER;
    if (displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGE("displaysInfo is empty");
        return;
    }
    DisplayMode mode = displayGroupInfo_.displaysInfo[0].displayMode;
    if (mode == displayMode_) {
        MMI_HILOGD("displaymode not change, mode:%{public}d, diaplayMode_:%{public}d", mode, displayMode_);
        return;
    }
    displayMode_ = mode;
    if (FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_ == nullptr) {
        MMI_HILOGD("send fingersense display mode is nullptr");
        return;
    }
    MMI_HILOGI("update fingersense display mode, displayMode:%{public}d", displayMode_);
    FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_(static_cast<int32_t>(displayMode_));
}
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
void InputWindowsManager::PointerDrawingManagerOnDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    IPointerDrawingManager::GetInstance()->OnDisplayInfo(displayGroupInfo);
    if (INPUT_DEV_MGR->HasPointerDevice()) {
        MouseLocation mouseLocation = GetMouseInfo();
        int32_t displayId = MouseEventHdr->GetDisplayId();
        displayId = displayId < 0 ? displayGroupInfo_.displaysInfo[0].id : displayId;
        auto displayInfo = GetPhysicalDisplay(displayId);
        CHKPV(displayInfo);
        int32_t logicX = mouseLocation.physicalX + displayInfo->x;
        int32_t logicY = mouseLocation.physicalY + displayInfo->y;
        std::optional<WindowInfo> windowInfo;
        CHKPV(lastPointerEvent_);
        if (lastPointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_DOWN &&
            lastPointerEvent_->GetPressedButtons().empty()) {
            windowInfo = GetWindowInfo(logicX, logicY);
        } else {
            windowInfo = SelectWindowInfo(logicX, logicY, lastPointerEvent_);
        }
        CHKFRV(windowInfo, "The windowInfo is nullptr");
        int32_t windowPid = GetWindowPid(windowInfo->id);
        WinInfo info = { .windowPid = windowPid, .windowId = windowInfo->id };
        IPointerDrawingManager::GetInstance()->OnWindowInfo(info);
        PointerStyle pointerStyle;
        GetPointerStyle(info.windowPid, info.windowId, pointerStyle);
        MMI_HILOGD("get pointer style, pid:%{public}d, windowid:%{public}d, style:%{public}d",
            info.windowPid, info.windowId, pointerStyle.id);
        if (!dragFlag_) {
            SetMouseFlag(lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP);
            isDragBorder_ = SelectPointerChangeArea(*windowInfo, pointerStyle, logicX, logicY);
            dragPointerStyle_ = pointerStyle;
            MMI_HILOGD("not in drag SelectPointerStyle, pointerStyle is:%{public}d", dragPointerStyle_.id);
        }
        JudgMouseIsDownOrUp(dragFlag_);
        if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
            dragFlag_ = true;
            MMI_HILOGD("Is in drag scene");
        }
        if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP) {
            dragFlag_ = false;
            isDragBorder_ = false;
        }
        IPointerDrawingManager::GetInstance()->DrawPointerStyle(dragPointerStyle_);
    }
}

bool InputWindowsManager::NeedUpdatePointDrawFlag(const std::vector<WindowInfo> &windows)
{
    CALL_DEBUG_ENTER;
    return !windows.empty() && windows.back().action == WINDOW_UPDATE_ACTION::ADD_END;
}
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

void InputWindowsManager::GetPointerStyleByArea(WindowArea area, int32_t pid, int32_t winId, PointerStyle& pointerStyle)
{
    CALL_DEBUG_ENTER;
    switch (area) {
        case WindowArea::ENTER:
        case WindowArea::EXIT:
            MMI_HILOG_CURSORD("SetPointerStyle for Enter or exit! No need to deal with it now");
            break;
        case WindowArea::FOCUS_ON_TOP_LEFT:
        case WindowArea::FOCUS_ON_BOTTOM_RIGHT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST_SOUTH_EAST;
            break;
        case WindowArea::FOCUS_ON_TOP_RIGHT:
        case WindowArea::FOCUS_ON_BOTTOM_LEFT:
            pointerStyle.id = MOUSE_ICON::NORTH_EAST_SOUTH_WEST;
            break;
        case WindowArea::FOCUS_ON_TOP:
        case WindowArea::FOCUS_ON_BOTTOM:
            pointerStyle.id = MOUSE_ICON::NORTH_SOUTH;
            break;
        case WindowArea::FOCUS_ON_LEFT:
        case WindowArea::FOCUS_ON_RIGHT:
            pointerStyle.id = MOUSE_ICON::WEST_EAST;
            break;
        case WindowArea::TOP_LEFT_LIMIT:
            pointerStyle.id = MOUSE_ICON::SOUTH_EAST;
            break;
        case WindowArea::TOP_RIGHT_LIMIT:
            pointerStyle.id = MOUSE_ICON::SOUTH_WEST;
            break;
        case WindowArea::TOP_LIMIT:
            pointerStyle.id = MOUSE_ICON::SOUTH;
            break;
        case WindowArea::LEFT_LIMIT:
            pointerStyle.id = MOUSE_ICON::EAST;
            break;
        case WindowArea::RIGHT_LIMIT:
            pointerStyle.id = MOUSE_ICON::WEST;
            break;
        case WindowArea::BOTTOM_LEFT_LIMIT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST;
            break;
        case WindowArea::BOTTOM_LIMIT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST;
            break;
        case WindowArea::BOTTOM_RIGHT_LIMIT:
            pointerStyle.id = MOUSE_ICON::NORTH_WEST;
            break;
        case WindowArea::FOCUS_ON_INNER:
            GetPointerStyle(pid, winId, pointerStyle);
            break;
    }
}

void InputWindowsManager::SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    PointerStyle pointerStyle;
    GetPointerStyleByArea(area, pid, windowId, pointerStyle);
    UpdateWindowPointerVisible(pid);
    if (lastPointerStyle_.id == pointerStyle.id) {
        MMI_HILOG_CURSORE("Tha lastPointerStyle is totally equal with this, no need to change it");
        return;
    }
    lastPointerStyle_.id = pointerStyle.id;
    IconStyle iconStyle = IPointerDrawingManager::GetInstance()->GetIconStyle(MOUSE_ICON(pointerStyle.id));
    if (windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        iconStyle.iconPath != DEFAULT_ICON_PATH)) {
        PointerStyle style;
        GetPointerStyle(pid, GLOBAL_WINDOW_ID, style);
        lastPointerStyle_ = style;
    }
    MMI_HILOG_CURSORI("Window id:%{public}d set pointer style:%{public}d success", windowId, lastPointerStyle_.id);
    IPointerDrawingManager::GetInstance()->DrawPointerStyle(lastPointerStyle_);
}

void InputWindowsManager::UpdateWindowPointerVisible(int32_t pid)
{
    bool visible = IPointerDrawingManager::GetInstance()->GetPointerVisible(pid);
    IPointerDrawingManager::GetInstance()->SetPointerVisible(pid, visible, 0);
}

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputWindowsManager::SendPointerEvent(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerAction);
    MouseLocation mouseLocation = GetMouseInfo();
    lastLogicX_ = mouseLocation.physicalX;
    lastLogicY_ = mouseLocation.physicalY;
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW ||
        Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
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
    LogTracer lt1(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    if (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        pointerEvent->SetBuffer(extraData_.buffer);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    auto fd = udsServer_->GetClientFd(lastWindowInfo_.pid);
    auto sess = udsServer_->GetSession(fd);
    CHKPRV(sess, "The last window has disappeared");
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}

void InputWindowsManager::DispatchPointer(int32_t pointerAction, int32_t windowId)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        MMI_HILOGI("the mouse is hide");
        return;
    }
    if (lastPointerEvent_ == nullptr) {
        SendPointerEvent(pointerAction);
        return;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->UpdateId();
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerAction);
    PointerEvent::PointerItem lastPointerItem;
    int32_t lastPointerId = lastPointerEvent_->GetPointerId();
    if (!lastPointerEvent_->GetPointerItem(lastPointerId, lastPointerItem)) {
        MMI_HILOGE("GetPointerItem:%{public}d fail", lastPointerId);
        return;
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_ENTER_WINDOW && windowId <= 0) {
        std::optional<WindowInfo> windowInfo;
        int32_t eventAction = lastPointerEvent_->GetPointerAction();
        bool checkFlag = (eventAction == PointerEvent::POINTER_ACTION_MOVE &&
            lastPointerEvent_->GetPressedButtons().empty()) ||
            (eventAction >= PointerEvent::POINTER_ACTION_AXIS_BEGIN &&
            eventAction <= PointerEvent::POINTER_ACTION_AXIS_END);
        if (checkFlag) {
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
    SetPrivacyModeFlag(lastWindowInfo_.privacyMode, pointerEvent);
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
    if (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        pointerEvent->SetBuffer(extraData_.buffer);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    if (pointerAction == PointerEvent::POINTER_ACTION_LEAVE_WINDOW) {
        pointerEvent->SetAgentWindowId(lastWindowInfo_.id);
    }
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_FREEZE);
    auto filter = InputHandler->GetFilterHandler();
    filter->HandlePointerEvent(pointerEvent);
}

void InputWindowsManager::NotifyPointerToWindow()
{
    CALL_DEBUG_ENTER;
    std::optional<WindowInfo> windowInfo;
    if (lastPointerEvent_ == nullptr) {
        MMI_HILOGD("lastPointerEvent_ is nullptr");
        return;
    }
    windowInfo = GetWindowInfo(lastLogicX_, lastLogicY_);
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
    DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
}
#endif // OHOS_BUILD_ENABLE_POINTER

void InputWindowsManager::PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo)
{
    std::string window;
    window += StringPrintf("windowId:[");
    for (const auto &item : windowsInfo) {
        MMI_HILOGD("windowsInfos,id:%{public}d,pid:%{public}d,uid:%{public}d,"
            "area.x:%{public}d,area.y:%{public}d,area.width:%{public}d,area.height:%{public}d,"
            "defaultHotAreas.size:%{public}zu,pointerHotAreas.size:%{public}zu,"
            "agentWindowId:%{public}d,flags:%{public}d,action:%{public}d,displayId:%{public}d,"
            "zOrder:%{public}f, privacyMode:%{public}d",
            item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
            item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
            item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder, item.privacyMode);
        for (const auto &win : item.defaultHotAreas) {
            MMI_HILOGD("defaultHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                win.x, win.y, win.width, win.height);
        }
        for (const auto &pointer : item.pointerHotAreas) {
            MMI_HILOGD("pointerHotAreas:x:%{public}d,y:%{public}d,width:%{public}d,height:%{public}d",
                pointer.x, pointer.y, pointer.width, pointer.height);
        }

        window += StringPrintf("%d,", item.id);
        std::string dump;
        dump += StringPrintf("pointChangeAreas:[");
        for (auto it : item.pointerChangeAreas) {
            dump += StringPrintf("%d,", it);
        }
        dump += StringPrintf("]\n");

        dump += StringPrintf("transform:[");
        for (auto it : item.transform) {
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
    MMI_HILOGD("windowsGroupInfo,focusWindowId:%{public}d,displayId:%{public}d",
        windowGroupInfo.focusWindowId, windowGroupInfo.displayId);
    PrintWindowInfo(windowGroupInfo.windowsInfo);
}

void InputWindowsManager::PrintDisplayInfo()
{
    if (!HiLogIsLoggable(MMI_LOG_DOMAIN, MMI_LOG_TAG, LOG_DEBUG)) {
        return;
    }
    MMI_HILOGD("logicalInfo,width:%{public}d,height:%{public}d,focusWindowId:%{public}d",
        displayGroupInfo_.width, displayGroupInfo_.height, displayGroupInfo_.focusWindowId);
    MMI_HILOGD("windowsInfos,num:%{public}zu", displayGroupInfo_.windowsInfo.size());
    PrintWindowInfo(displayGroupInfo_.windowsInfo);

    MMI_HILOGD("displayInfos,num:%{public}zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        MMI_HILOGD("displayInfos,id:%{public}d,x:%{public}d,y:%{public}d,"
            "width:%{public}d,height:%{public}d,name:%{public}s,"
            "uniq:%{public}s,direction:%{public}d,displayDirection:%{public}d",
            item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
            item.uniq.c_str(), item.direction, item.displayDirection);
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
    MMI_HILOGD("Failed to search for Physical,uniq:%{public}s", uniq.c_str());
    if (displayGroupInfo_.displaysInfo.size() > 0) {
        return &displayGroupInfo_.displaysInfo[0];
    }
    return nullptr;
}

const DisplayInfo *InputWindowsManager::GetDefaultDisplayInfo() const
{
    return FindPhysicalDisplayInfo("default0");
}

void InputWindowsManager::RotateScreen(const DisplayInfo& info, PhysicalCoordinate& coord) const
{
    const Direction direction = info.direction;
    if (direction == DIRECTION0) {
        MMI_HILOGD("direction is DIRECTION0");
        return;
    }
    if (direction == DIRECTION90) {
        MMI_HILOGD("direction is DIRECTION90");
        double temp = coord.x;
        if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
            coord.x = info.height - coord.y;
        } else {
            coord.x = info.width - coord.y;
        }
        coord.y = temp;
        MMI_HILOGD("physicalX:%{public}f, physicalY:%{public}f", coord.x, coord.y);
        return;
    }
    if (direction == DIRECTION180) {
        MMI_HILOGD("direction is DIRECTION180");
        coord.x = info.width - coord.x;
        coord.y = info.height - coord.y;
        MMI_HILOGD("physicalX:%{public}f, physicalY:%{public}f", coord.x, coord.y);
        return;
    }
    if (direction == DIRECTION270) {
        MMI_HILOGD("direction is DIRECTION270");
        double temp = coord.y;
        if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
            coord.y = info.width - coord.x;
        } else {
            coord.y = info.height - coord.x;
        }
        coord.x = temp;
        MMI_HILOGD("physicalX:%{public}f, physicalY:%{public}f", coord.x, coord.y);
    }
}

void InputWindowsManager::GetPhysicalDisplayCoord(struct libinput_event_touch* touch,
    const DisplayInfo& info, EventTouch& touchInfo)
{
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
        .y = libinput_event_touch_get_y_transformed(touch, height),
    };
    MMI_HILOGD("width:%{public}d, height:%{public}d, physicalX:%{public}f, physicalY:%{public}f",
        width, height, coord.x, coord.y);
    RotateScreen(info, coord);
    touchInfo.point.x = static_cast<int32_t>(coord.x);
    touchInfo.point.y = static_cast<int32_t>(coord.y);
    touchInfo.toolRect.point.x = static_cast<int32_t>(libinput_event_touch_get_tool_x_transformed(touch, width));
    touchInfo.toolRect.point.y = static_cast<int32_t>(libinput_event_touch_get_tool_y_transformed(touch, height));
    touchInfo.toolRect.width = static_cast<int32_t>(
        libinput_event_touch_get_tool_width_transformed(touch, width));
    touchInfo.toolRect.height = static_cast<int32_t>(
        libinput_event_touch_get_tool_height_transformed(touch, height));
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
    EventTouch& touchInfo, int32_t& physicalDisplayId)
{
    CHKPF(touch);
    std::string screenId = bindInfo_.GetBindDisplayNameByInputDevice(deviceId);
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
    PhysicalCoordinate& coord, int32_t& displayId) const
{
    CHKPF(tip);
    auto displayInfo = FindPhysicalDisplayInfo("default0");
    CHKPF(displayInfo);
    MMI_HILOGD("PhysicalDisplay.width:%{public}d, PhysicalDisplay.height:%{public}d, "
               "PhysicalDisplay.topLeftX:%{public}d, PhysicalDisplay.topLeftY:%{public}d",
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
    RotateScreen(*displayInfo, phys);
    coord.x = phys.x;
    coord.y = phys.y;
    MMI_HILOGD("physicalX:%{public}f, physicalY:%{public}f, displayId:%{public}d", phys.x, phys.y, displayId);
    return true;
}

bool InputWindowsManager::CalculateTipPoint(struct libinput_event_tablet_tool* tip,
    int32_t& targetDisplayId, PhysicalCoordinate& coord) const
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
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return true;
    }
    MouseLocation mouseLocation = GetMouseInfo();
    int32_t displayId = MouseEventHdr->GetDisplayId();
    if (displayId < 0) {
        displayId = displayGroupInfo_.displaysInfo[0].id;
    }
    auto displayInfo = GetPhysicalDisplay(displayId);
    CHKPF(displayInfo);
    int32_t logicX = mouseLocation.physicalX + displayInfo->x;
    int32_t logicY = mouseLocation.physicalY + displayInfo->y;
    std::optional<WindowInfo> touchWindow = GetWindowInfo(logicX, logicY);
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

    auto it = pointerStyle_.find(pid);
    if (it != pointerStyle_.end()) {
        pointerStyle_.erase(it);
        MMI_HILOGD("Clear the pointer style map, pd:%{public}d", pid);
    }
}

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
    if (sceneIter == pointerStyle_.end() || sceneIter->second.find(sceneWinId) == sceneIter->second.end()) {
        pointerStyle_[scenePid] = {};
        MMI_HILOG_CURSORE("SceneBoardPid %{public}d or windowId:%{public}d does not exist on pointerStyle_",
            scenePid, sceneWinId);
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
    return RET_OK;
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
            if (item.second.id == DEFAULT_POINTER_STYLE) {
                item.second.id = globalStyle_.id;
            } else if (item.second.id == CURSOR_CIRCLE_STYLE) {
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
    MMI_HILOG_CURSORD("start to get pid by window %{public}d", windowId);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        return UpdatePoinerStyle(pid, windowId, pointerStyle);
    }
    if (!isUiExtension && uiExtensionPointerStyle_.count(pid) != 0) {
        MMI_HILOG_CURSORI("clear the uiextension mouse style for pid %{public}d", pid);
        uiExtensionPointerStyle_.erase(pid);
    }
    SetUiExtensionInfo(isUiExtension, pid, windowId);
    return UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle, isUiExtension);
}

int32_t InputWindowsManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CALL_DEBUG_ENTER;
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
    return RET_OK;
}

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

    MMI_HILOG_CURSORD("Window type:%{public}d get pointer style:%{public}d success", windowId, iter->second.id);
    pointerStyle = iter->second;
    return RET_OK;
}

void InputWindowsManager::InitPointerStyle()
{
    CALL_DEBUG_ENTER;
    PointerStyle pointerStyle;
    pointerStyle.id = DEFAULT_POINTER_STYLE;
    for (const auto& windowItem : displayGroupInfo_.windowsInfo) {
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
        if (!AddInt32(item.x, item.width, displayMaxX)) {
            MMI_HILOGE("The addition of displayMaxX overflows");
            return false;
        }
        if (!AddInt32(item.y, item.height, displayMaxY)) {
            MMI_HILOGE("The addition of displayMaxY overflows");
            return false;
        }
        if (((windowX >= item.x) && (windowX < displayMaxX)) &&
            (windowY >= item.y) && (windowY < displayMaxY)) {
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
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputWindowsManager::AdjustDisplayCoordinate(
    const DisplayInfo& displayInfo, double& physicalX, double& physicalY) const
{
    int32_t width = displayInfo.width;
    int32_t height = displayInfo.height;
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
    bool checkFlag = (firstBtnDownWindowId_ == -1) ||
        ((action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) && (pointerEvent->GetPressedButtons().size() == 1)) ||
        ((action == PointerEvent::POINTER_ACTION_MOVE) && (pointerEvent->GetPressedButtons().empty())) ||
        (extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) ||
        (action == PointerEvent::POINTER_ACTION_PULL_UP) ||
        ((action == PointerEvent::POINTER_ACTION_AXIS_BEGIN || action == PointerEvent::POINTER_ACTION_AXIS_END) &&
        (pointerEvent->GetPressedButtons().empty()));
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(pointerEvent->GetTargetDisplayId());
    if (checkFlag) {
        int32_t targetWindowId = pointerEvent->GetTargetWindowId();
        static std::unordered_map<int32_t, int32_t> winId2ZorderMap;
        bool isHotArea = false;
        if (targetWindowId <= 1) {
            targetMouseWinIds_.clear();
        }
        for (const auto &item : windowsInfo) {
            if (IsTransparentWin(item.pixelMap, logicalX - item.area.x, logicalY - item.area.y)) {
                winId2ZorderMap.insert({item.id, item.zOrder});
                MMI_HILOG_DISPATCHE("It's an abnormal window and pointer find the next window");
                continue;
            }
            if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
                !IsValidZorderWindow(item, pointerEvent)) {
                winId2ZorderMap.insert({item.id, item.zOrder});
                MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching, "
                    "window:%{public}d, flags:%{public}d, pid:%{public}d", item.id, item.flags, item.pid);
                continue;
            } else if ((extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE) ||
                (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP)) {
                if (IsInHotArea(logicalX, logicalY, item.pointerHotAreas, item)) {
                    if ((item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) &&
                        ((pointerEvent->GetPressedButtons().empty()) ||
                        (action == PointerEvent::POINTER_ACTION_PULL_UP) ||
                        (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN) ||
                        (action == PointerEvent::POINTER_ACTION_AXIS_UPDATE) ||
                        (action == PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) ||
                        (action == PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW) ||
                        (action == PointerEvent::POINTER_ACTION_AXIS_END))) {
                        winId2ZorderMap.insert({item.id, item.zOrder});
                        continue;
                    }
                    firstBtnDownWindowId_ = item.id;
                    MMI_HILOG_DISPATCHD("Mouse event select pull window, window:%{public}d, pid:%{public}d",
                        firstBtnDownWindowId_, item.pid);
                    break;
                } else {
                    winId2ZorderMap.insert({item.id, item.zOrder});
                    continue;
                }
            } else if ((targetWindowId < 0) && (IsInHotArea(logicalX, logicalY, item.pointerHotAreas, item))) {
                if ((item.windowInputType == WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE) &&
                    ((pointerEvent->GetPressedButtons().empty()) ||
                    (action == PointerEvent::POINTER_ACTION_PULL_UP) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_UPDATE) ||
                    (action == PointerEvent::POINTER_ACTION_AXIS_END))) {
                    continue;
                }
                firstBtnDownWindowId_ = item.id;
                if (!item.uiExtentionWindowInfo.empty()) {
                    CheckUIExtentionWindowPointerHotArea(logicalX, logicalY,
                        item.uiExtentionWindowInfo, firstBtnDownWindowId_);
                }
                MMI_HILOG_DISPATCHD("Find out the dispatch window of this pointer event when the targetWindowId "
                    "hasn't been set up yet, window:%{public}d, pid:%{public}d", firstBtnDownWindowId_, item.pid);
                bool isSpecialWindow = HandleWindowInputType(item, pointerEvent);
                if (isSpecialWindow) {
                    AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id);
                    isHotArea = true;
                    continue;
                } else if (isHotArea) {
                    AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id);
                    break;
                } else {
                    break;
                }

            } else if ((targetWindowId >= 0) && (targetWindowId == item.id)) {
                firstBtnDownWindowId_ = targetWindowId;
                MMI_HILOG_DISPATCHD("Find out the dispatch window of this pointer event when the targetWindowId "
                    "has been set up already, window:%{public}d, pid:%{public}d", firstBtnDownWindowId_, item.pid);
                break;
            } else {
                winId2ZorderMap.insert({item.id, item.zOrder});
                MMI_HILOG_DISPATCHD("Continue searching for the dispatch window of this pointer event");
            }
        }
        if ((firstBtnDownWindowId_ < 0) && (action == PointerEvent::POINTER_ACTION_BUTTON_DOWN) &&
            (pointerEvent->GetPressedButtons().size() == 1)) {
            for (auto iter = winId2ZorderMap.begin(); iter != winId2ZorderMap.end(); iter++) {
                MMI_HILOG_DISPATCHI("%{public}d, %{public}d", iter->first, iter->second);
            }
        }
        winId2ZorderMap.clear();
    }
    MMI_HILOG_DISPATCHD("firstBtnDownWindowId_:%{public}d", firstBtnDownWindowId_);
    for (const auto &item : windowsInfo) {
        for (const auto &windowInfo : item.uiExtentionWindowInfo) {
            if (windowInfo.id == firstBtnDownWindowId_) {
                return std::make_optional(windowInfo);
            }
        }
        if (item.id == firstBtnDownWindowId_) {
            return std::make_optional(item);
        }
    }
    return std::nullopt;
}

void InputWindowsManager::CheckUIExtentionWindowPointerHotArea(int32_t logicalX, int32_t logicalY,
    const std::vector<WindowInfo>& windowInfos, int32_t& windowId)
{
    for (auto it = windowInfos.rbegin(); it != windowInfos.rend(); ++it) {
        if (IsInHotArea(logicalX, logicalY, it->pointerHotAreas, *it)) {
            windowId = it->id;
            break;
        }
    }
}

std::optional<WindowInfo> InputWindowsManager::GetWindowInfo(int32_t logicalX, int32_t logicalY)
{
    CALL_DEBUG_ENTER;
    for (const auto& item : displayGroupInfo_.windowsInfo) {
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
        MMI_HILOG_CURSORD("windowHotAreas size:%{public}zu, windowId:%{public}d",
            windowHotAreas.size(), windowId);
        findFlag = InWhichHotArea(logicalX, logicalY, windowHotAreas, pointerStyle);
    }
    return findFlag;
}

void InputWindowsManager::UpdatePointerChangeAreas(const DisplayGroupInfo &displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    for (const auto &windowInfo : displayGroupInfo.windowsInfo) {
        std::vector<Rect> windowHotAreas;
        int32_t windowId = windowInfo.id;
        Rect windowArea = windowInfo.area;
        windowArea.width = windowInfo.transform[SCALE_X] != 0 ? windowInfo.area.width / windowInfo.transform[SCALE_X]
            : windowInfo.area.width;
        windowArea.height = windowInfo.transform[SCALE_Y] != 0 ?  windowInfo.area.height / windowInfo.transform[SCALE_Y]
            : windowInfo.area.height;
        std::vector<int32_t> pointerChangeAreas = windowInfo.pointerChangeAreas;
        UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
        UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
        UpdateInnerAngleArea(windowArea, pointerChangeAreas, windowHotAreas);
        if (windowsHotAreas_.find(windowId) == windowsHotAreas_.end()) {
            windowsHotAreas_.emplace(windowId, windowHotAreas);
        } else {
            windowsHotAreas_[windowId] = windowHotAreas;
        }
    }
}

void InputWindowsManager::UpdatePointerChangeAreas()
{
    CALL_DEBUG_ENTER;
    UpdatePointerChangeAreas(displayGroupInfoTmp_);
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

void InputWindowsManager::UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
    const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow)
{
    CHKPV(pointerEvent);
    MMI_HILOG_DISPATCHD("LastWindowInfo:%{public}d, touchWindow:%{public}d", lastWindowInfo_.id, touchWindow.id);
    if (lastWindowInfo_.id != touchWindow.id) {
        DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
        lastLogicX_ = logicalX;
        lastLogicY_ = logicalY;
        lastPointerEvent_ = pointerEvent;
        lastWindowInfo_ = touchWindow;
        DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
        return;
    }
    lastLogicX_ = logicalX;
    lastLogicY_ = logicalY;
    lastPointerEvent_ = pointerEvent;
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
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayY();
    auto touchWindow = SelectWindowInfo(logicalX, logicalY, pointerEvent);
    if (!touchWindow) {
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN || mouseDownInfo_.id == -1) {
            MMI_HILOGE("touchWindow is nullptr, targetWindow:%{public}d", pointerEvent->GetTargetWindowId());
            int64_t beginTime = GetSysClockTime();
            IPointerDrawingManager::GetInstance()->DrawMovePointer(displayId, physicalX, physicalY);
            int64_t endTime = GetSysClockTime();
            if ((endTime - beginTime) > RS_PROCESS_TIMEOUT) {
                MMI_HILOGW("Rs process timeout");
            }
            return RET_ERR;
        }
        touchWindow = std::make_optional(mouseDownInfo_);
        int32_t pointerAction = pointerEvent->GetPointerAction();
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        pointerEvent->SetOriginPointerAction(pointerAction);
        MMI_HILOGI("mouse event send cancel, window:%{public}d, pid:%{public}d", touchWindow->id, touchWindow->pid);
    }

    bool checkFlag = pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_UPDATE ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_BEGIN ||
        pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END;
    if (checkFlag) {
        if ((!GetHoverScrollState()) && (displayGroupInfo_.focusWindowId != touchWindow->id)) {
            MMI_HILOGD("disable mouse hover scroll in inactive window, targetWindowId:%{public}d", touchWindow->id);
            return RET_OK;
        }
    }
    PointerStyle pointerStyle;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState() &&
            IsMouseDrawing(pointerEvent->GetPointerAction())) {
            MMI_HILOGD("Turn the mouseDisplay from false to true");
            IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
        }
        pointerStyle = IPointerDrawingManager::GetInstance()->GetLastMouseStyle();
        MMI_HILOGD("showing the lastMouseStyle %{public}d, lastPointerStyle %{public}d",
            pointerStyle.id, lastPointerStyle_.id);
    } else {
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
        if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
            IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
            DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
        }
        IPointerDrawingManager::GetInstance()->UpdateDisplayInfo(*physicalDisplayInfo);
        WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
        IPointerDrawingManager::GetInstance()->OnWindowInfo(info);
    }
    GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
    if (isUiExtension_) {
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
        MMI_HILOGD("pointerStyle is :%{public}d, windowId is :%{public}d, logicalX is :%{public}d,"
            "logicalY is :%{public}d", pointerStyle.id, window.id, logicalX, logicalY);
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
    if (ROTATE_POLICY == WINDOW_ROTATE && Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        direction = physicalDisplayInfo->direction;
        TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(direction, physicalDisplayInfo->width,
            physicalDisplayInfo->height, physicalX, physicalY);
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MAGIC_POINTER_VELOCITY_TRACKER->MonitorCursorMovement(pointerEvent);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    int64_t beginTime = GetSysClockTime();
    if (IsMouseDrawing(pointerEvent->GetPointerAction())) {
        IPointerDrawingManager::GetInstance()->DrawPointer(displayId, physicalX, physicalY,
            dragPointerStyle_, direction);
    }
    int64_t endTime = GetSysClockTime();
    if ((endTime - beginTime) > RS_PROCESS_TIMEOUT) {
        MMI_HILOGW("Rs process timeout");
    }
    if (captureModeInfo_.isCaptureMode && (touchWindow->id != captureModeInfo_.windowId)) {
        captureModeInfo_.isCaptureMode = false;
    }
    SetPrivacyModeFlag(touchWindow->privacyMode, pointerEvent);
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    auto windowX = logicalX - touchWindow->area.x;
    auto windowY = logicalY - touchWindow->area.y;
    if (!(touchWindow->transform.empty())) {
        auto windowXY = TransformWindowXY(*touchWindow, logicalX, logicalY);
        windowX = windowXY.first;
        windowY = windowXY.second;
    }
    windowX = static_cast<int32_t>(windowX);
    windowY = static_cast<int32_t>(windowY);
    pointerItem.SetWindowX(windowX);
    pointerItem.SetWindowY(windowY);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    if ((extraData_.appended && (extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE)) ||
        (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP)) {
        pointerEvent->SetBuffer(extraData_.buffer);
        UpdatePointerAction(pointerEvent);
    } else {
        pointerEvent->ClearBuffer();
    }
    CHKPR(udsServer_, ERROR_NULL_POINTER);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    UpdatePointerEvent(logicalX, logicalY, pointerEvent, *touchWindow);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_ANCO
    if (touchWindow && IsInAncoWindow(*touchWindow, logicalX, logicalY)) {
        MMI_HILOGD("Process mouse event in Anco window, targetWindowId:%{public}d", touchWindow->id);
        SimulatePointerExt(pointerEvent);
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
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
               isUiExtension_ ? uiExtensionPid_ : touchWindow->pid, isUiExtension_ ? uiExtensionWindowId_ :
               touchWindow->id, touchWindow->agentWindowId,
               logicalX, logicalY, pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), windowX, windowY);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        MMI_HILOGD("Clear extra data");
        ClearExtraData();
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

void InputWindowsManager::JudgMouseIsDownOrUp(bool dragState)
{
    if (!dragState && (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_UP ||
        pointerActionFlag_ == PointerEvent::POINTER_ACTION_BUTTON_DOWN)) {
        SetMouseFlag(true);
        return;
    }
    if (lastPointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_BUTTON_DOWN) {
        SetMouseFlag(true);
    }
}

int32_t InputWindowsManager::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    if (windowId < 0) {
        MMI_HILOGE("Windowid(%{public}d) is invalid", windowId);
        return RET_ERR;
    }
    if ((captureModeInfo_.isCaptureMode == isCaptureMode) && !isCaptureMode) {
        MMI_HILOGE("Windowid:(%{public}d) is not capture mode", windowId);
        return RET_OK;
    }
    captureModeInfo_.windowId = windowId;
    captureModeInfo_.isCaptureMode = isCaptureMode;
    MMI_HILOGI("Windowid:(%{public}d) is (%{public}d)", windowId, isCaptureMode);
    return RET_OK;
}

bool InputWindowsManager::GetMouseIsCaptureMode() const
{
    return captureModeInfo_.isCaptureMode;
}

bool InputWindowsManager::IsNeedDrawPointer(PointerEvent::PointerItem &pointerItem) const
{
    if (pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN) {
        std::shared_ptr<InputDevice> inputDevice = INPUT_DEV_MGR->GetInputDevice(pointerItem.GetDeviceId());
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

#ifdef OHOS_BUILD_ENABLE_TOUCH
bool InputWindowsManager::SkipAnnotationWindow(uint32_t flag, int32_t toolType)
{
    return ((flag & WindowInfo::FLAG_BIT_HANDWRITING) == WindowInfo::FLAG_BIT_HANDWRITING &&
            toolType == PointerEvent::TOOL_TYPE_FINGER);
}

bool InputWindowsManager::SkipNavigationWindow(WindowInputType windowType, int32_t toolType)
{
    MMI_HILOGD("windowType: %{public}d, toolType: %{public}d", static_cast<int32_t>(windowType), toolType);
    if ((windowType != WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE &&
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
    for (auto &windowinfo : uiExtentionWindowInfo) {
        if (windowinfo.id == windowId) {
            *touchWindow = &windowinfo;
            isUiExtentionWindow = true;
            break;
        }
    }
}

int32_t InputWindowsManager::UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOG_DISPATCHE("This display is not existent");
        return RET_ERR;
    }
    pointerEvent->SetTargetDisplayId(displayId);

    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPR(physicDisplayInfo, ERROR_NULL_POINTER);
    double physicalX = 0;
    double physicalY = 0;
    if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) {
        physicalX = pointerItem.GetDisplayX();
        physicalY = pointerItem.GetDisplayY();
    } else {
        physicalX = pointerItem.GetDisplayXPos();
        physicalY = pointerItem.GetDisplayYPos();
    }
    AdjustDisplayCoordinate(*physicDisplayInfo, physicalX, physicalY);
    int32_t logicalX1 = 0;
    int32_t logicalY1 = 0;

    if (!AddInt32(static_cast<int32_t>(physicalX), physicDisplayInfo->x, logicalX1)) {
        MMI_HILOG_DISPATCHE("The addition of logicalX overflows");
        return RET_ERR;
    }
    if (!AddInt32(static_cast<int32_t>(physicalY), physicDisplayInfo->y, logicalY1)) {
        MMI_HILOG_DISPATCHE("The addition of logicalY overflows");
        return RET_ERR;
    }
    double logicalX = physicalX + physicDisplayInfo->x;
    double logicalY = physicalY + physicDisplayInfo->y;
    WindowInfo *touchWindow = nullptr;
    auto targetWindowId = pointerItem.GetTargetWindowId();
    bool isHotArea = false;
    std::vector<WindowInfo> windowsInfo = GetWindowGroupInfoByDisplayId(displayId);
    bool isFirstSpecialWindow = false;
    static std::unordered_map<int32_t, WindowInfo> winMap;
    for (auto &item : windowsInfo) {
        bool checkWindow = (item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE ||
            !IsValidZorderWindow(item, pointerEvent);
        if (checkWindow) {
            MMI_HILOG_DISPATCHD("Skip the untouchable or invalid zOrder window to continue searching,"
                "window:%{public}d, flags:%{public}d", item.id, item.flags);
            winMap.insert({item.id, item});
            continue;
        }
        if (IsTransparentWin(item.pixelMap, logicalX - item.area.x, logicalY - item.area.y)) {
            MMI_HILOG_DISPATCHE("It's an abnormal window and touchscreen find the next window");
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

        bool checkToolType = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
            ((pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId) ||
            pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN);
        checkToolType = checkToolType || (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
        if (checkToolType) {
            MMI_HILOG_DISPATCHD("Enter checkToolType");
            if (IsInHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
                item.defaultHotAreas, item)) {
                touchWindow = &item;
                break;
            } else {
                winMap.insert({item.id, item});
                continue;
            }
        }
        if (targetWindowId >= 0) {
            bool isUiExtentionWindow = false;
            GetUIExtentionWindowInfo(item.uiExtentionWindowInfo, targetWindowId, &touchWindow, isUiExtentionWindow);
            if (isUiExtentionWindow) {
                break;
            }
            if (item.id == targetWindowId) {
                touchWindow = &item;
                break;
            }
        } else if (IsInHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
            item.defaultHotAreas, item)) {
            int32_t windowId = 0;
            touchWindow = &item;
            CheckUIExtentionWindowDefaultHotArea(static_cast<int32_t>(logicalX), static_cast<int32_t>(logicalY),
                item.uiExtentionWindowInfo, windowId);
            bool isUiExtentionWindow = false;
            if (windowId > 0) {
                GetUIExtentionWindowInfo(item.uiExtentionWindowInfo, windowId, &touchWindow, isUiExtentionWindow);
            }
            if (isUiExtentionWindow) {
                break;
            }
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
                    MMI_HILOG_DISPATCHI("the first special window status:%{public}d", isFirstSpecialWindow);
                }
            }
            if (isSpecialWindow) {
                AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id);
                isHotArea = true;
                continue;
            } else if (isHotArea) {
                AddTargetWindowIds(pointerEvent->GetPointerId(), pointerEvent->GetSourceType(), item.id);
                break;
            } else {
                break;
            }
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
        if (it == touchItemDownInfos_.end() ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            MMI_HILOG_DISPATCHE("The touchWindow is nullptr, logicalX:%{public}f,"
                "logicalY:%{public}f, pointerId:%{public}d", logicalX, logicalY, pointerId);
            return RET_ERR;
        }
        touchWindow = &it->second.window;
        if (it->second.flag) {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
            MMI_HILOG_DISPATCHI("Not found event down target window, maybe this window was untouchable,"
                "need send cancel event, windowId:%{public}d pointerId:%{public}d", touchWindow->id, pointerId);
        }
    }
    winMap.clear();
#ifdef OHOS_BUILD_ENABLE_ANCO
    bool isInAnco = touchWindow && IsInAncoWindow(*touchWindow, logicalX, logicalY);
    if (isInAnco) {
        MMI_HILOG_DISPATCHD("Process touch screen event in Anco window, targetWindowId:%{public}d", touchWindow->id);
        // Simulate uinput automated injection operations (MMI_GE(pointerEvent->GetZOrder(), 0.0f))
        bool isCompensatePointer = pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE);
        if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            MMI_HILOG_DISPATCHI("In Anco, WI:%{public}d, SI:%{public}d SW:%{public}d",
                touchWindow->id, isCompensatePointer, isFirstSpecialWindow);
        }
        if (isCompensatePointer || isFirstSpecialWindow) {
            SimulatePointerExt(pointerEvent);
            isFirstSpecialWindow = false;
        } else {
            if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
                std::unordered_map<std::string, std::string> mapPayload;
                mapPayload["msg"] = "";
                constexpr int32_t touchDownBoost = 1006;
                OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
                    OHOS::ResourceSchedule::ResType::RES_TYPE_ANCO_CUST, touchDownBoost, mapPayload);
            } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
                constexpr int32_t touchUpBoost = 1007;
                std::unordered_map<std::string, std::string> mapPayload;
                mapPayload["msg"] = "";
                OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
                    OHOS::ResourceSchedule::ResType::RES_TYPE_ANCO_CUST, touchUpBoost, mapPayload);
            }
        }
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_ANCO
    auto windowX = logicalX - touchWindow->area.x;
    auto windowY = logicalY - touchWindow->area.y;
    if (!(touchWindow->transform.empty())) {
        auto windowXY = TransformWindowXY(*touchWindow, logicalX, logicalY);
        windowX = windowXY.first;
        windowY = windowXY.second;
    }
    SetPrivacyModeFlag(touchWindow->privacyMode, pointerEvent);
    pointerEvent->SetTargetWindowId(touchWindow->id);
    pointerEvent->SetAgentWindowId(touchWindow->agentWindowId);
    pointerItem.SetDisplayX(static_cast<int32_t>(physicalX));
    pointerItem.SetDisplayY(static_cast<int32_t>(physicalY));
    pointerItem.SetWindowX(static_cast<int32_t>(windowX));
    pointerItem.SetWindowY(static_cast<int32_t>(windowY));
    pointerItem.SetDisplayXPos(physicalX);
    pointerItem.SetDisplayYPos(physicalY);
    pointerItem.SetWindowXPos(windowX);
    pointerItem.SetWindowYPos(windowY);
    pointerItem.SetToolWindowX(pointerItem.GetToolDisplayX() + physicDisplayInfo->x - touchWindow->area.x);
    pointerItem.SetToolWindowY(pointerItem.GetToolDisplayY() + physicDisplayInfo->y - touchWindow->area.y);
    pointerItem.SetTargetWindowId(touchWindow->id);
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    bool checkExtraData = extraData_.appended && extraData_.sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN &&
        ((pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_FINGER && extraData_.pointerId == pointerId) ||
        pointerItem.GetToolType() == PointerEvent::TOOL_TYPE_PEN);
    checkExtraData = checkExtraData || (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP);
    if (checkExtraData) {
        pointerEvent->SetBuffer(extraData_.buffer);
        UpdatePointerAction(pointerEvent);
        PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, touchWindow);
    }
    int32_t pointerAction = pointerEvent->GetPointerAction();
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
        if (pointerEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOG_FREEZEI("PA:%{public}s,Pid:%{public}d,TWI:%{public}d,"
                "FWI:%{public}d,EID:%{public}d,"
                "W:%{public}d,H:%{public}d,AX:%{public}d,AY:%{public}d,"
                "flags:%{public}d,DID:%{public}d"
                "AWI:%{public}d,zOrder:%{public}1f",
                pointerEvent->DumpPointerAction(), touchWindow->pid, touchWindow->id,
                displayGroupInfo_.focusWindowId, pointerEvent->GetId(),
                touchWindow->area.width, touchWindow->area.height, touchWindow->area.x,
                touchWindow->area.y, touchWindow->flags, displayId,
                pointerEvent->GetAgentWindowId(), touchWindow->zOrder);
        } else {
            MMI_HILOG_FREEZEI("PA:%{public}s,Pid:%{public}d,TWI:%{public}d,"
                "FWI:%{public}d,EID:%{public}d,LX:%{public}1f,LY:%{public}1f,"
                "DX:%{public}1f,DY:%{public}1f,WX:%{public}1f,WY:%{public}1f,"
                "W:%{public}d,H:%{public}d,AX:%{public}d,AY:%{public}d,"
                "flags:%{public}d,DID:%{public}d"
                "AWI:%{public}d,zOrder:%{public}1f",
                pointerEvent->DumpPointerAction(), touchWindow->pid, touchWindow->id,
                displayGroupInfo_.focusWindowId, pointerEvent->GetId(), logicalX, logicalY, physicalX,
                physicalY, windowX, windowY, touchWindow->area.width, touchWindow->area.height, touchWindow->area.x,
                touchWindow->area.y, touchWindow->flags, displayId,
                pointerEvent->GetAgentWindowId(), touchWindow->zOrder);
        }
    }
    bool gestureInject = false;
    if ((pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) && MMI_GNE(pointerEvent->GetZOrder(), 0.0f)) {
        gestureInject = true;
    }
    if (IsNeedDrawPointer(pointerItem)) {
        if (!IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
            IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
            if (touchWindow->id != lastWindowInfo_.id) {
                lastWindowInfo_ = *touchWindow;
            }
            DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW, lastWindowInfo_.id);
        }
        PointerStyle pointerStyle;
        GetPointerStyle(touchWindow->pid, touchWindow->id, pointerStyle);
        IPointerDrawingManager::GetInstance()->UpdateDisplayInfo(*physicDisplayInfo);
        WinInfo info = { .windowPid = touchWindow->pid, .windowId = touchWindow->id };
        IPointerDrawingManager::GetInstance()->OnWindowInfo(info);
        IPointerDrawingManager::GetInstance()->DrawPointer(displayId,
            pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), pointerStyle, physicDisplayInfo->direction);
    } else if (IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        if ((!checkExtraData) && (!(extraData_.appended &&
            extraData_.sourceType == PointerEvent::SOURCE_TYPE_MOUSE))) {
            MMI_HILOG_DISPATCHD("PointerAction is to leave the window");
            DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
            if (!gestureInject) {
                IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
            }
        }
    }

    pointerAction = pointerEvent->GetPointerAction();
    if (pointerAction == PointerEvent::POINTER_ACTION_DOWN ||
        pointerAction == PointerEvent::POINTER_ACTION_HOVER_ENTER) {
        WindowInfoEX windowInfoEX;
        windowInfoEX.window = *touchWindow;
        windowInfoEX.flag = true;
        touchItemDownInfos_[pointerId] = windowInfoEX;
        MMI_HILOG_FREEZEI("PointerId:%{public}d, touchWindow:%{public}d", pointerId, touchWindow->id);
    } else if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) {
        MMI_HILOG_DISPATCHD("Clear extra data");
        pointerEvent->ClearBuffer();
        lastTouchEvent_ = nullptr;
        lastTouchWindowInfo_.id = -1;
        ClearExtraData();
    }
    return ERR_OK;
}

void InputWindowsManager::CheckUIExtentionWindowDefaultHotArea(int32_t logicalX, int32_t logicalY,
    const std::vector<WindowInfo>& windowInfos, int32_t& windowId)
{
    for (auto it = windowInfos.rbegin(); it != windowInfos.rend(); ++it) {
        if (IsInHotArea(logicalX, logicalY, it->defaultHotAreas, *it)) {
            windowId = it->id;
            break;
        }
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
            DispatchTouch(PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW);
        }
        lastTouchLogicX_ = logicalX;
        lastTouchLogicY_ = logicalY;
        lastTouchEvent_ = pointerEvent;
        lastTouchWindowInfo_ = *touchWindow;
        DispatchTouch(PointerEvent::POINTER_ACTION_PULL_IN_WINDOW);
        return;
    }
    lastTouchLogicX_ = logicalX;
    lastTouchLogicY_ = logicalY;
    lastTouchEvent_ = pointerEvent;
    lastTouchWindowInfo_ = *touchWindow;
}

void InputWindowsManager::DispatchTouch(int32_t pointerAction)
{
    CALL_INFO_TRACE;
    CHKPV(udsServer_);
    CHKPV(lastTouchEvent_);
    if (pointerAction == PointerEvent::POINTER_ACTION_PULL_IN_WINDOW) {
        WindowInfo touchWindow;
        bool isChanged { false };
        for (const auto &item : displayGroupInfo_.windowsInfo) {
            if ((item.flags & WindowInfo::FLAG_BIT_UNTOUCHABLE) == WindowInfo::FLAG_BIT_UNTOUCHABLE) {
                MMI_HILOGD("Skip the untouchable window to continue searching, "
                    "window:%{public}d, flags:%{public}d", item.id, item.flags);
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
    currentPointerItem.SetWindowX(lastTouchLogicX_ - lastTouchWindowInfo_.area.x);
    currentPointerItem.SetWindowY(lastTouchLogicY_ - lastTouchWindowInfo_.area.y);
    currentPointerItem.SetDisplayX(lastPointerItem.GetDisplayX());
    currentPointerItem.SetDisplayY(lastPointerItem.GetDisplayY());
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
    pointerEvent->SetSourceType(lastTouchEvent_->GetSourceType());
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetDeviceId(lastTouchEvent_->GetDeviceId());
    auto fd = udsServer_->GetClientFd(lastTouchWindowInfo_.pid);
    auto sess = udsServer_->GetSession(fd);
    if (sess == nullptr) {
        MMI_HILOGI("The last window has disappeared");
        return;
    }

    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_FREEZE);
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(pointerEvent, pkt);
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Send message failed, errCode:%{public}d", MSG_SEND_FAIL);
        return;
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
int32_t InputWindowsManager::UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    int32_t pointerAction = pointerEvent->GetPointerAction();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
        case PointerEvent::POINTER_ACTION_MOVE: {
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
            pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
            pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
            return UpdateMouseTarget(pointerEvent);
        }
        case PointerEvent::POINTER_ACTION_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
            pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
            pointerEvent->SetButtonPressed(PointerEvent::MOUSE_BUTTON_LEFT);
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
    int32_t focusWindowId = displayGroupInfo_.focusWindowId;
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
    pointerEvent->SetTargetWindowId(windowInfo->id);
    pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOG_DISPATCHD("focusWindow:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);

    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#ifdef OHOS_BUILD_ENABLE_CROWN
int32_t InputWindowsManager::UpdateCrownTarget(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t focusWindowId = displayGroupInfo_.focusWindowId;
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
    pointerEvent->SetTargetWindowId(windowInfo->id);
    pointerEvent->SetAgentWindowId(windowInfo->agentWindowId);
    MMI_HILOG_DISPATCHD("focusWindow:%{public}d, pid:%{public}d", focusWindowId, windowInfo->pid);

    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_CROWN

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
void InputWindowsManager::DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (knuckleDrawMgr_ == nullptr) {
        knuckleDrawMgr_ = std::make_shared<KnuckleDrawingManager>();
    }
    if (knuckleDynamicDrawingManager_ == nullptr) {
        knuckleDynamicDrawingManager_ = std::make_shared<KnuckleDynamicDrawingManager>();
    }
    auto displayId = pointerEvent->GetTargetDisplayId();
    if (!UpdateDisplayId(displayId)) {
        MMI_HILOGE("This display is not exist");
        return;
    }
    auto physicDisplayInfo = GetPhysicalDisplay(displayId);
    CHKPV(physicDisplayInfo);

    knuckleDrawMgr_->UpdateDisplayInfo(*physicDisplayInfo);
    knuckleDrawMgr_->KnuckleDrawHandler(pointerEvent);
    knuckleDynamicDrawingManager_->UpdateDisplayInfo(*physicDisplayInfo);
    knuckleDynamicDrawingManager_->KnuckleDynamicDrawHandler(pointerEvent);

    TOUCH_DRAWING_MGR->UpdateDisplayInfo(*physicDisplayInfo);
    TOUCH_DRAWING_MGR->TouchDrawHandler(pointerEvent);
}

#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

template <class T>
void InputWindowsManager::CreateAntiMisTakeObserver(T& item)
{
    CALL_INFO_TRACE;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        if (SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).GetBoolValue(key, item.isOpen) != RET_OK) {
            MMI_HILOGE("Get settingdata failed, key: %{public}s", key.c_str());
        }
        MMI_HILOGI("Anti mistake observer key: %{public}s, statusValue: %{public}d", key.c_str(), item.isOpen);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    CHKPV(statusObserver);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret: %{public}d", ret);
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
    lastPointerEventForFold_ = pointerEvent;
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
#ifdef OHOS_BUILD_ENABLE_CROWN
        case PointerEvent::SOURCE_TYPE_CROWN: {
            return UpdateCrownTarget(pointerEvent);
        }
#endif // OHOS_BUILD_ENABLE_CROWN
        default: {
            MMI_HILOG_DISPATCHE("Source type is unknown, source:%{public}d", source);
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

void InputWindowsManager::GetWidthAndHeight(const DisplayInfo* displayInfo, int32_t &width, int32_t &height)
{
    if (ROTATE_POLICY == WINDOW_ROTATE) {
        if (displayInfo->direction == DIRECTION0 || displayInfo->direction == DIRECTION180) {
            width = displayInfo->width;
            height = displayInfo->height;
        } else {
            if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
                width = displayInfo->width;
                height = displayInfo->height;
                return;
            }
            height = displayInfo->width;
            width = displayInfo->height;
        }
    } else {
        width = displayInfo->width;
        height = displayInfo->height;
    }
}
void InputWindowsManager::ReverseRotateScreen(const DisplayInfo& info, const double x, const double y,
    Coordinate2D& cursorPos) const
{
    const Direction direction = info.direction;
    MMI_HILOGD("X:%{public}.2f, Y:%{public}.2f, info.width:%{public}d, info.height:%{public}d",
        x, y, info.width, info.height);
    switch (direction) {
        case DIRECTION0: {
            MMI_HILOGD("direction is DIRECTION0");
            cursorPos.x = x;
            cursorPos.y = y;
            MMI_HILOGD("physicalX:%{public}.2f, physicalY:%{public}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION90: {
            MMI_HILOGD("direction is DIRECTION90");
            cursorPos.y = static_cast<double>(info.width) - x;
            cursorPos.x = y;
            MMI_HILOGD("physicalX:%{public}.2f, physicalY:%{public}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION180: {
            MMI_HILOGD("direction is DIRECTION180");
            cursorPos.x = static_cast<double>(info.width) - x;
            cursorPos.y = static_cast<double>(info.height) - y;
            MMI_HILOGD("physicalX:%{public}.2f, physicalY:%{public}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        case DIRECTION270: {
            MMI_HILOGD("direction is DIRECTION270");
            cursorPos.x = static_cast<double>(info.height) - y;
            cursorPos.y = x;
            MMI_HILOGD("physicalX:%{public}.2f, physicalY:%{public}.2f", cursorPos.x, cursorPos.y);
            break;
        }
        default: {
            MMI_HILOGE("direction is invalid, direction:%{public}d", direction);
            break;
        }
    }
}

void InputWindowsManager::UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData)
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
    GetWidthAndHeight(displayInfo, width, height);
    CoordinateCorrection(width, height, integerX, integerY);
    x = static_cast<double>(integerX) + (x - floor(x));
    y = static_cast<double>(integerY) + (y - floor(y));

    if (ROTATE_POLICY == WINDOW_ROTATE && isRealData) {
        PhysicalCoordinate coord {
            .x = integerX,
            .y = integerY,
        };
        RotateScreen(*displayInfo, coord);
        mouseLocation_.physicalX = static_cast<int32_t>(coord.x);
        mouseLocation_.physicalY = static_cast<int32_t>(coord.y);
    } else {
        mouseLocation_.physicalX = integerX;
        mouseLocation_.physicalY = integerY;
    }
    mouseLocation_.displayId = displayId;
    MMI_HILOGD("Mouse Data: physicalX:%{public}d,physicalY:%{public}d, displayId:%{public}d",
        mouseLocation_.physicalX, mouseLocation_.physicalY, displayId);
    cursorPos_.displayId = displayId;
    if (ROTATE_POLICY == WINDOW_ROTATE && !isRealData) {
        ReverseRotateScreen(*displayInfo, x, y, cursorPos_.cursorPos);
        return;
    }
    cursorPos_.cursorPos.x = x;
    cursorPos_.cursorPos.y = y;
}

MouseLocation InputWindowsManager::GetMouseInfo()
{
    if ((mouseLocation_.displayId < 0) && !displayGroupInfo_.displaysInfo.empty()) {
        const DisplayInfo &displayInfo = displayGroupInfo_.displaysInfo[0];
        mouseLocation_.displayId = displayInfo.id;
        mouseLocation_.physicalX = displayInfo.width / TWOFOLD;
        mouseLocation_.physicalY = displayInfo.height / TWOFOLD;
    }
    return mouseLocation_;
}

CursorPosition InputWindowsManager::GetCursorPos()
{
    if ((cursorPos_.displayId < 0) && !displayGroupInfo_.displaysInfo.empty()) {
        const DisplayInfo &displayInfo = displayGroupInfo_.displaysInfo[0];
        cursorPos_.displayId = displayInfo.id;
        cursorPos_.cursorPos.x = displayInfo.width * HALF_RATIO;
        cursorPos_.cursorPos.y = displayInfo.height * HALF_RATIO;
    }
    return cursorPos_;
}

CursorPosition InputWindowsManager::ResetCursorPos()
{
    if (!displayGroupInfo_.displaysInfo.empty()) {
        const DisplayInfo &displayInfo = displayGroupInfo_.displaysInfo[0];
        cursorPos_.displayId = displayInfo.id;
        cursorPos_.cursorPos.x = displayInfo.width * HALF_RATIO;
        cursorPos_.cursorPos.y = displayInfo.height * HALF_RATIO;
    } else {
        cursorPos_.displayId = -1;
        cursorPos_.cursorPos.x = 0;
        cursorPos_.cursorPos.y = 0;
    }
    return cursorPos_;
}
#endif // OHOS_BUILD_ENABLE_POINTER

int32_t InputWindowsManager::AppendExtraData(const ExtraData& extraData)
{
    CALL_DEBUG_ENTER;
    extraData_.appended = extraData.appended;
    extraData_.buffer = extraData.buffer;
    extraData_.sourceType = extraData.sourceType;
    extraData_.pointerId = extraData.pointerId;
    return RET_OK;
}

void InputWindowsManager::ClearExtraData()
{
    CALL_DEBUG_ENTER;
    extraData_.appended = false;
    extraData_.buffer.clear();
    extraData_.sourceType = -1;
    extraData_.pointerId = -1;
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
    Rosen::WindowManagerLite::GetInstance().GetVisibilityWindowInfo(infos);
    for (const auto &it: infos) {
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

void InputWindowsManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Windows information:\t");
    mprintf(fd, "windowsInfos,num:%zu", displayGroupInfo_.windowsInfo.size());
    for (const auto &item : displayGroupInfo_.windowsInfo) {
        mprintf(fd, "  windowsInfos: id:%d | pid:%d | uid:%d | area.x:%d | area.y:%d "
                "| area.width:%d | area.height:%d | defaultHotAreas.size:%zu "
                "| pointerHotAreas.size:%zu | agentWindowId:%d | flags:%d "
                "| action:%d | displayId:%d | zOrder:%f \t",
                item.id, item.pid, item.uid, item.area.x, item.area.y, item.area.width,
                item.area.height, item.defaultHotAreas.size(), item.pointerHotAreas.size(),
                item.agentWindowId, item.flags, item.action, item.displayId, item.zOrder);
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
    mprintf(fd, "Displays information:\t");
    mprintf(fd, "displayInfos,num:%zu", displayGroupInfo_.displaysInfo.size());
    for (const auto &item : displayGroupInfo_.displaysInfo) {
        mprintf(fd, "\t displayInfos: id:%d | x:%d | y:%d | width:%d | height:%d | name:%s "
                "| uniq:%s | direction:%d | displayDirection:%d | displayMode:%d \t",
                item.id, item.x, item.y, item.width, item.height, item.name.c_str(),
                item.uniq.c_str(), item.direction, item.displayDirection, item.displayMode);
    }
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
    Matrix3f transform(window.transform);
    if (window.transform.size() != MATRIX3_SIZE || transform.IsIdentity()) {
        return {logicX, logicY};
    }
    Vector3f logicXY(logicX, logicY, 1.0);
    Vector3f windowXY = transform * logicXY;
    return {round(windowXY[0]), round(windowXY[1])};
}

bool InputWindowsManager::IsValidZorderWindow(const WindowInfo &window,
    const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPR(pointerEvent, false);
    if (!(pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE)) || MMI_LE(pointerEvent->GetZOrder(), 0.0f)) {
        return true;
    }
    if (MMI_GE(window.zOrder, pointerEvent->GetZOrder())) {
        MMI_HILOGE("current window zorder:%{public}f greater than the simulate target zOrder:%{public}f, "
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
    int32_t toolType = item.GetToolType();
    int32_t sourceType = pointerEvent->GetSourceType();
    switch (window.windowInputType)
    {
        case WindowInputType::NORMAL:
            return false;
        case WindowInputType::TRANSMIT_ALL:
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
    std::vector<WindowInfo> windowInfos = GetWindowGroupInfoByDisplayId(displayId);
    for (const auto &item : windowInfos) {
        if (windowId == item.id) {
            return std::make_optional(item);
        }
    }
    return std::nullopt;
}

void InputWindowsManager::GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType,
    std::vector<int32_t> &windowIds)
{
    CALL_DEBUG_ENTER;
    if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (targetMouseWinIds_.find(pointerItemId) != targetMouseWinIds_.end()) {
            windowIds = targetMouseWinIds_[pointerItemId];
        }
        return;
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (targetTouchWinIds_.find(pointerItemId) != targetTouchWinIds_.end()) {
            windowIds = targetTouchWinIds_[pointerItemId];
        }
    }
}

void InputWindowsManager::AddTargetWindowIds(int32_t pointerItemId, int32_t sourceType, int32_t windowId)
{
    CALL_DEBUG_ENTER;
    if (sourceType == PointerEvent::SOURCE_TYPE_MOUSE) {
        if (targetMouseWinIds_.find(pointerItemId) != targetMouseWinIds_.end()) {
            targetMouseWinIds_[pointerItemId].push_back(windowId);
        } else {
            std::vector<int32_t> windowIds;
            windowIds.push_back(windowId);
            targetMouseWinIds_.emplace(pointerItemId, windowIds);
        }
        return;
    } else if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        if (targetTouchWinIds_.find(pointerItemId) != targetTouchWinIds_.end()) {
            targetTouchWinIds_[pointerItemId].push_back(windowId);
        } else {
            std::vector<int32_t> windowIds;
            windowIds.push_back(windowId);
            targetTouchWinIds_.emplace(pointerItemId, windowIds);
        }
    }
}

void InputWindowsManager::ClearTargetWindowId(int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    if (targetTouchWinIds_.find(pointerId) == targetTouchWinIds_.end()) {
        MMI_HILOGD("Clear target windowId fail, pointerId:%{public}d", pointerId);
        return;
    }
    targetTouchWinIds_.erase(pointerId);
}

void InputWindowsManager::SetPrivacyModeFlag(SecureFlag privacyMode, std::shared_ptr<InputEvent> event)
{
    if (privacyMode == SecureFlag::PRIVACY_MODE) {
        MMI_HILOGD("Window security mode is privacy");
        event->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
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
    if (displayGroupInfo_.displaysInfo.empty()) {
        MMI_HILOGE("displayGroupInfo_.displaysInfo is empty");
        return;
    }
    const Direction direction = displayGroupInfo_.displaysInfo.front().direction;
    if (direction < Direction::DIRECTION0 || direction > Direction::DIRECTION270) {
        MMI_HILOGE("direction is invalid, direction:%{public}d", direction);
        return;
    }
    Coordinate2D matrix { 0.0, 0.0 };
    ReverseRotateScreen(displayGroupInfo_.displaysInfo.front(), x, y, matrix);
    x = static_cast<int32_t>(matrix.x);
    y = static_cast<int32_t>(matrix.y);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

bool InputWindowsManager::IsTransparentWin(void* pixelMap, int32_t logicalX, int32_t logicalY)
{
    CALL_DEBUG_ENTER;
    if (pixelMap == nullptr) {
        return false;
    }

    uint32_t dst = 0;
    OHOS::Media::Position pos { logicalY, logicalX };
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(pixelMap);
    CHKPF(pixelMapPtr);
    uint32_t result = pixelMapPtr->ReadPixel(pos, dst);
    if (result != RET_OK) {
        MMI_HILOGE("Failed to read pixelmap");
        return false;
    }
    MMI_HILOGD("dst:%{public}d, byteCount:%{public}d, width:%{public}d, height:%{public}d",
        dst, pixelMapPtr->GetByteCount(), pixelMapPtr->GetWidth(), pixelMapPtr->GetHeight());
    return dst == RET_OK;
}

int32_t InputWindowsManager::SetCurrentUser(int32_t userId)
{
    CALL_DEBUG_ENTER;
    currentUserId_ = userId;
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

void InputWindowsManager::PrintChangedWindowBySync(const DisplayGroupInfo &newDisplayInfo)
{
    auto &oldWindows = displayGroupInfo_.windowsInfo;
    auto &newWindows = newDisplayInfo.windowsInfo;
    if (!oldWindows.empty() && !newWindows.empty()) {
        if (oldWindows[0].id != newWindows[0].id) {
            MMI_HILOGI("Window sync changed %{public}d %{public}d %{public}f %{public}d %{public}d %{public}f",
                oldWindows[0].id, oldWindows[0].pid, oldWindows[0].zOrder, newWindows[0].id,
                newWindows[0].pid, newWindows[0].zOrder);
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
    cJSON* jsonData = cJSON_Parse(jsonStr.c_str());
    if (!cJSON_IsObject(jsonData)) {
        MMI_HILOGE("jsonData is not object");
        return false;
    }
    cJSON* whiteList = cJSON_GetObjectItemCaseSensitive(jsonData, "whiteList");
    if (!cJSON_IsArray(whiteList)) {
        MMI_HILOGE("whiteList number must be array");
        return false;
    }
    int32_t whiteListSize = cJSON_GetArraySize(whiteList);
    for (int32_t i = 0; i < whiteListSize; ++i) {
        cJSON *whiteListJson = cJSON_GetArrayItem(whiteList, i);
        if (!cJSON_IsObject(whiteListJson)) {
            MMI_HILOGE("whiteListJson is not object");
            continue;
        }
        SwitchFocusKey switchFocusKey;
        cJSON *keyCodeJson = cJSON_GetObjectItemCaseSensitive(whiteListJson, "keyCode");
        if (!cJSON_IsNumber(keyCodeJson)) {
            MMI_HILOGE("keyCodeJson is not number");
            continue;
        }
        switchFocusKey.keyCode = keyCodeJson->valueint;
        cJSON *pressedKeyJson = cJSON_GetObjectItemCaseSensitive(whiteListJson, "pressedKey");
        if (!cJSON_IsNumber(pressedKeyJson)) {
            MMI_HILOGE("pressedKeyJson is not number");
            continue;
        }
        switchFocusKey.pressedKey = pressedKeyJson->valueint;
        vecWhiteList_.push_back(switchFocusKey);
    }
    return true;
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
    CHKPR(keyEvent, false);
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
} // namespace MMI
} // namespace OHOS
