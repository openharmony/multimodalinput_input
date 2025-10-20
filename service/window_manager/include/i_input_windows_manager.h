/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef I_INPUT_WINDOWS_MANAGER_H
#define I_INPUT_WINDOWS_MANAGER_H

#include <memory>
#include <mutex>

#include "libinput.h"
#include "extra_data.h"
#ifdef OHOS_BUILD_ENABLE_ANCO
#include "ianco_channel.h"
#endif
#include "key_event.h"
#include "pointer_event.h"
#include "pointer_style.h"
#include "struct_multimodal.h"
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
#include "touch_gesture_manager.h"
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
#include "uds_server.h"
#include "old_display_info.h"
#include "shift_info.h"

namespace OHOS {
namespace MMI {
struct MouseLocation {
    int32_t displayId { -1 };
    int32_t physicalX { 0 };
    int32_t physicalY { 0 };
};

struct Coordinate2D {
    double x;
    double y;
};

struct CursorPosition {
    int32_t displayId { -1 };
    Direction direction { Direction::DIRECTION0 };
    Direction displayDirection { Direction::DIRECTION0 };
    Coordinate2D cursorPos {};
};

struct TargetInfo {
    SecureFlag privacyMode { SecureFlag::DEFAULT_MODE };
    int32_t id { -1 };
    int32_t agentWindowId { -1 };
};

class IInputWindowsManager {
public:
    IInputWindowsManager() = default;
    virtual ~IInputWindowsManager() = default;

    virtual void Init(UDSServer& udsServer) = 0;
    virtual bool JudgeCameraInFore() = 0;
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId) = 0;
    virtual bool AdjustFingerFlag(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual void PrintEnterEventInfo(std::shared_ptr<PointerEvent> pointerEvent) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    virtual bool IsFocusedSession(int32_t session) const = 0;
    virtual void UpdateDisplayInfo(OLD::DisplayGroupInfo &displayGroupInfo) = 0;
    virtual void UpdateDisplayInfoExtIfNeed(OLD::DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt) = 0;
    virtual void ProcessInjectEventGlobalXY(std::shared_ptr<PointerEvent> pointerEvent, int32_t useCoordinate) = 0;
    virtual void UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo) = 0;
    virtual int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) = 0;
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) = 0;
    virtual int32_t GetWindowPid(int32_t windowId) const = 0;
    virtual int32_t GetWindowAgentPid(int32_t windowId) const = 0;
    virtual int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) = 0;
    virtual bool GetMouseIsCaptureMode() const = 0;
    virtual int32_t GetDisplayBindInfo(DisplayBindInfos &infos) = 0;
    virtual int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) = 0;
    virtual int32_t AppendExtraData(const ExtraData& extraData) = 0;
    virtual bool IsWindowVisible(int32_t pid) = 0;
    virtual ExtraData GetExtraData() const = 0;
    virtual const std::vector<WindowInfo> GetWindowGroupInfoByDisplayIdCopy(int32_t displayId) const = 0;
    virtual std::pair<double, double> TransformWindowXY(const WindowInfo &, double, double) const = 0;
    virtual void ClearTargetDeviceWindowId(int32_t deviceId) = 0;
    virtual void ClearTargetWindowId(int32_t pointerId, int32_t deviceId) = 0;
    virtual std::pair<double, double> TransformDisplayXY(const OLD::DisplayInfo &info,
        double logicX, double logicY) const = 0;
    virtual int32_t SetPixelMapData(int32_t infoId, void *pixelMap) = 0;
    virtual void SetFoldState () = 0;
    virtual bool CheckAppFocused(int32_t pid) = 0;
    virtual bool GetCancelEventFlag(std::shared_ptr<PointerEvent> pointerEvent) = 0;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    virtual std::vector<std::pair<int32_t, TargetInfo>> UpdateTarget(std::shared_ptr<KeyEvent> keyEvent) = 0;
    virtual void HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent) = 0;
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    virtual int32_t CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid) = 0;
    virtual int32_t ClearMouseHideFlag(int32_t eventId) = 0;

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual MouseLocation GetMouseInfo() = 0;
    virtual CursorPosition GetCursorPos() = 0;
    virtual CursorPosition ResetCursorPos() = 0;
    virtual void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData = true) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual int32_t SetHoverScrollState(bool state) = 0;
    virtual int32_t GetFocusWindowId(int32_t groupId = DEFAULT_GROUP_ID) const = 0;
    virtual bool GetHoverScrollState() const = 0;
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual int32_t SetPointerStyle(int32_t pid, int32_t windowId,
        PointerStyle pointerStyle, bool isUiExtension = false) = 0;
    virtual int32_t GetPointerStyle(int32_t pid, int32_t windowId,
        PointerStyle &pointerStyle, bool isUiExtension = false) const = 0;
    virtual void DispatchPointer(int32_t pointerAction, int32_t windowId = -1) = 0;
    virtual void SendPointerEvent(int32_t pointerAction) = 0;
    virtual bool IsMouseSimulate() = 0;
    virtual bool HasMouseHideFlag() = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    virtual void UpdatePointerDrawingManagerWindowInfo() = 0;
#endif // defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)

#ifdef OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    virtual bool IsNeedRefreshLayer(int32_t windowId) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif //OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    virtual bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId, bool isNeedClear = false,
        bool hasValidAreaDowned = false) = 0;
    virtual bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, PhysicalCoordinate& coord, PointerEvent::PointerItem& pointerItem) = 0;
    virtual const OLD::DisplayInfo *GetDefaultDisplayInfo() const = 0;
    virtual void ReverseXY(int32_t &x, int32_t &y) = 0;
    virtual void FoldScreenRotation(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual void SendCancelEventWhenLock() = 0;
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual bool UpdateDisplayId(int32_t& displayId) = 0;
    virtual void DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual const OLD::DisplayInfo *GetPhysicalDisplay(int32_t id) const = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual void UpdatePointerChangeAreas() = 0;
    virtual bool SelectPointerChangeArea(int32_t windowId, int32_t logicalX, int32_t logicalY);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    virtual std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId) = 0;
    virtual void GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType, std::set<int32_t> &windowIds,
        int32_t deviceId) = 0;
    virtual int32_t SetCurrentUser(int32_t userId) = 0;
    virtual DisplayMode GetDisplayMode() const = 0;
    virtual void SetWindowStateNotifyPid(int32_t userId, int32_t pid) = 0;
    virtual int32_t GetWindowStateNotifyPid(int32_t userId) = 0;
    virtual int32_t GetPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId) = 0;
    virtual int32_t GetAgentPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId) = 0;
    virtual int32_t FindDisplayUserId(int32_t displayId) const = 0;
#ifdef OHOS_BUILD_ENABLE_ANCO
    virtual void InitializeAnco() = 0;
    virtual int32_t AncoAddChannel(sptr<IAncoChannel> channel) = 0;
    virtual int32_t AncoRemoveChannel(sptr<IAncoChannel> channel) = 0;
    virtual void CleanShellWindowIds() = 0;
    virtual bool IsKnuckleOnAncoWindow(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t SyncKnuckleStatus(bool isKnuckleEnable) = 0;
#endif // OHOS_BUILD_ENABLE_ANCO
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual int32_t ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown) = 0;
    virtual Direction GetDisplayDirection(const OLD::DisplayInfo *displayInfo) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    virtual void AttachTouchGestureMgr(std::shared_ptr<TouchGestureManager> touchGestureMgr) = 0;
    virtual void CancelAllTouches(std::shared_ptr<PointerEvent> event, bool isDisplayChanged = false) = 0;
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
#ifdef OHOS_BUILD_ENABLE_TOUCH
    virtual std::shared_ptr<PointerEvent> GetLastPointerEventForGesture() = 0;
#endif // OHOS_BUILD_ENABLE_TOUCH
    virtual std::pair<int32_t, int32_t> CalcDrawCoordinate(const OLD::DisplayInfo& displayInfo,
        PointerEvent::PointerItem pointerItem) = 0;
#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual bool IsMouseDragging() const = 0;
    virtual void EnsureMouseEventCycle(std::shared_ptr<PointerEvent> event) = 0;
    virtual void CleanMouseEventCycle(std::shared_ptr<PointerEvent> event) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER

    static std::shared_ptr<IInputWindowsManager> GetInstance();
    static void DestroyInstance();
    virtual bool GetHardCursorEnabled() = 0;

private:
    static std::mutex mutex_;
    static std::shared_ptr<IInputWindowsManager> instance_;
};

#define WIN_MGR ::OHOS::MMI::IInputWindowsManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_WINDOWS_MANAGER_H