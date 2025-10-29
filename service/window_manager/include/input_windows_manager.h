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

#ifndef INPUT_WINDOWS_MANAGER_H
#define INPUT_WINDOWS_MANAGER_H

#include <shared_mutex>
#include "mmi_transform.h"
#include "window_manager_lite.h"

#include "i_input_windows_manager.h"
#include "input_display_bind_helper.h"

namespace OHOS {
namespace MMI {
constexpr uint32_t SCREEN_CONTROL_WINDOW_TYPE = 2138;
struct WindowInfoEX {
    WindowInfo window;
    bool flag { false };
};

struct SwitchFocusKey {
    int32_t keyCode { -1 };
    int32_t pressedKey { -1 };
};

enum AcrossDirection : int32_t {
    ACROSS_ERROR = 0,
    UPWARDS = 1,
    DOWNWARDS = 2,
    LEFTWARDS = 3,
    RIGHTWARDS = 4,
};

class InputWindowsManager final : public IInputWindowsManager {
public:
    InputWindowsManager();
    ~InputWindowsManager();
    DISALLOW_COPY_AND_MOVE(InputWindowsManager);

    void Init(UDSServer& udsServer);
    void SetMouseFlag(bool state);
    bool GetMouseFlag();
    bool JudgeCameraInFore();
#ifdef OHOS_BUILD_ENABLE_POINTER
    void JudgMouseIsDownOrUp(bool dragState);
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId);
    bool AdjustFingerFlag(std::shared_ptr<PointerEvent> pointerEvent);
    void PrintEnterEventInfo(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    bool HandleWindowInputType(const WindowInfo &window, std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateCaptureMode(const OLD::DisplayGroupInfo &displayGroupInfo);
    bool IsFocusedSession(int32_t session) const;
    void UpdateDisplayInfo(OLD::DisplayGroupInfo &displayGroupInfo);
    void UpdateDisplayInfoExtIfNeed(OLD::DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt);
    void UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo);
    void ProcessInjectEventGlobalXY(std::shared_ptr<PointerEvent> pointerEvent, int32_t useCoordinate);
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void DumpDisplayInfo(int32_t fd, const std::vector<OLD::DisplayInfo>& displaysInfo);
    int32_t GetWindowPid(int32_t windowId, const std::vector<WindowInfo> &windowsInfo) const;
    int32_t GetWindowPid(int32_t windowId) const;
    int32_t GetWindowAgentPid(int32_t windowId) const;
    int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode);
    bool GetMouseIsCaptureMode() const;
    void DeviceStatusChanged(int32_t deviceId, const std::string &name, const std::string &sysUid,
        const std::string devStatus);
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t AppendExtraData(const ExtraData& extraData);
    bool IsWindowVisible(int32_t pid);
    void ClearExtraData();
    ExtraData GetExtraData() const;
    const std::vector<WindowInfo> GetWindowGroupInfoByDisplayIdCopy(int32_t displayId) const;
    std::pair<double, double> TransformWindowXY(const WindowInfo &window, double logicX, double logicY) const;
    std::pair<double, double> TransformDisplayXY(const OLD::DisplayInfo &info, double logicX, double logicY) const;
    bool GetCancelEventFlag(std::shared_ptr<PointerEvent> pointerEvent);
    void SetFoldState ();
    bool CheckAppFocused(int32_t pid);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    std::vector<std::pair<int32_t, TargetInfo>> GetPidAndUpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
    void ReissueEvent(std::shared_ptr<KeyEvent> keyEvent, int32_t focusWindowId);
    std::vector<std::pair<int32_t, TargetInfo>> UpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
    bool IsKeyPressed(int32_t pressedKey, std::vector<KeyEvent::KeyItem> &keyItems);
    bool IsOnTheWhitelist(std::shared_ptr<KeyEvent> keyEvent);
    void HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent);
    int32_t focusWindowId_ { -1 };
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid);
    int32_t ClearMouseHideFlag(int32_t eventId);

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    MouseLocation GetMouseInfo();
    CursorPosition GetCursorPos();
    CursorPosition ResetCursorPos();
    void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData = true);
    std::shared_ptr<PointerEvent> CreatePointerByLastPointer(int32_t pointerAction);
    void EnterMouseCaptureMode(const OLD::DisplayGroupInfo &displayGroupInfo);
    void LimitMouseLocaltionInEvent(const OLD::DisplayInfo *displayInfo, int32_t &integerX, int32_t &integerY,
        double &x, double &y, bool isRealData);
    void ClearPointerLockedWindow();
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    const OLD::DisplayGroupInfo GetDisplayGroupInfo(int32_t groupId = DEFAULT_GROUP_ID);
    int32_t SetHoverScrollState(bool state);
    bool GetHoverScrollState() const;
    bool SelectPointerChangeArea(int32_t windowId, int32_t logicalX, int32_t logicalY);
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false);
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
        bool isUiExtension = false) const;
    void SetUiExtensionInfo(bool isUiExtension, int32_t uiExtensionPid, int32_t uiExtensionWindoId);
    void DispatchPointer(int32_t pointerAction, int32_t windowId = -1);
    void SendPointerEvent(int32_t pointerAction);
    bool IsMouseSimulate();
    bool HasMouseHideFlag();
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    void UpdatePointerDrawingManagerWindowInfo();
#endif // defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)

#ifdef OHOS_BUILD_ENABLE_POINTER
    PointerStyle GetLastPointerStyle() const;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool IsNeedRefreshLayer(int32_t windowId);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void AdjustDisplayCoordinate(const OLD::DisplayInfo& displayInfo, double& physicalX, double& physicalY) const;
    bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId, bool isNeedClear = false, bool hasValidAreaDowned = false);
#endif // OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void ReverseRotateScreen(const OLD::DisplayInfo& info, const double x, const double y,
        Coordinate2D& cursorPos) const;
    void ReverseRotateDisplayScreen(const OLD::DisplayInfo& info, const double x, const double y,
        Coordinate2D& cursorPos) const;
    void ScreenRotateAdjustDisplayXY(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const;
    void RotateScreen(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const;
    void RotateDisplayScreen(const OLD::DisplayInfo& info, PhysicalCoordinate& coord);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool TransformTipPoint(struct libinput_event_tablet_tool* tip, PhysicalCoordinate& coord, int32_t& displayId,
        PointerEvent::PointerItem& pointerItem);
    bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, PhysicalCoordinate& coord, PointerEvent::PointerItem& pointerItem);
    const OLD::DisplayInfo *GetDefaultDisplayInfo() const;
    void ReverseXY(int32_t &x, int32_t &y);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void FoldScreenRotation(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void SendCancelEventWhenLock();
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_ANCO
    void UpdateWindowInfoExt(const WindowGroupInfo &windowGroupInfo, const OLD::DisplayGroupInfo &displayGroupInfo);
    void UpdateOneHandDataExt(const OLD::DisplayInfo &displayInfo);
    void UpdateShellWindow(const WindowInfo &window);
    void UpdateDisplayInfoExt(const OLD::DisplayGroupInfo &displayGroupInfo);
    bool IsInAncoWindow(const WindowInfo &window, int32_t x, int32_t y) const;
    bool IsAncoWindow(const WindowInfo &window) const;
    bool IsAncoWindowFocus(const WindowInfo &window) const;
    void SimulatePointerExt(std::shared_ptr<PointerEvent> pointerEvent);
    void SimulateKeyExt(std::shared_ptr<KeyEvent> keyEvent);
    void SimulateKeyEventIfNeeded(std::shared_ptr<KeyEvent> keyEvent);
    void DumpAncoWindows(std::string& out) const;
    void CleanShellWindowIds();
    bool IsKnuckleOnAncoWindow(std::shared_ptr<PointerEvent> pointerEvent);
    void SendOneHandData(const OLD::DisplayInfo &displayInfo, std::shared_ptr<PointerEvent> &pointerEvent);
    bool IsAncoGameActive();
    bool IsShouldSendToAnco(std::shared_ptr<PointerEvent> pointerEvent, bool isFirstSpecialWindow);
#endif // OHOS_BUILD_ENABLE_ANCO

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool UpdateDisplayId(int32_t& displayId);
    void DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    const OLD::DisplayInfo *GetPhysicalDisplay(int32_t id) const;
    const OLD::DisplayInfo *GetPhysicalDisplay(int32_t id,
        const OLD::DisplayGroupInfo &displayGroupInfo) const;

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void UpdatePointerChangeAreas();
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId);
    void GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType, std::set<int32_t> &windowIds,
        int32_t deviceId);
    void AddTargetWindowIds(int32_t pointerItemId, int32_t sourceType, int32_t windowId, int32_t deviceId);
    void ClearTargetDeviceWindowId(int32_t deviceId);
    void ClearTargetWindowId(int32_t pointerId, int32_t deviceId);
    bool IsTransparentWin(std::unique_ptr<Media::PixelMap> &pixelMap, int32_t logicalX, int32_t logicalY);
    int32_t SetCurrentUser(int32_t userId);
    DisplayMode GetDisplayMode() const;
    void SetWindowStateNotifyPid(int32_t userId, int32_t pid);
    int32_t GetWindowStateNotifyPid(int32_t userId);
    int32_t GetPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId);
    int32_t GetAgentPidByDisplayIdAndWindowId(int32_t displayId, int32_t windowId);
    int32_t FindDisplayUserId(int32_t displayId) const;
#ifdef OHOS_BUILD_ENABLE_ANCO
    void InitializeAnco();
    int32_t AncoAddChannel(sptr<IAncoChannel> channel);
    int32_t AncoRemoveChannel(sptr<IAncoChannel> channel);
    int32_t SyncKnuckleStatus(bool isKnuckleEnable);
#endif // OHOS_BUILD_ENABLE_ANCO

    int32_t SetPixelMapData(int32_t infoId, void *pixelMap);

    void CleanInvalidPiexMap(int32_t groupId = DEFAULT_GROUP_ID);
    void HandleWindowPositionChange(const OLD::DisplayGroupInfo &displayGroupInfo);
    void SendCancelEventWhenWindowChange(int32_t pointerId, int32_t groupId = DEFAULT_GROUP_ID);
    bool GetHardCursorEnabled();
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown);
    Direction GetDisplayDirection(const OLD::DisplayInfo *displayInfo);
    bool IsWindowRotation(const OLD::DisplayInfo *displayInfo);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    void AttachTouchGestureMgr(std::shared_ptr<TouchGestureManager> touchGestureMgr);
    void CancelAllTouches(std::shared_ptr<PointerEvent> event, bool isDisplayChanged = false);
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
#ifdef OHOS_BUILD_ENABLE_TOUCH
    std::shared_ptr<PointerEvent> GetLastPointerEventForGesture() { return lastPointerEventforGesture_; };
    std::pair<int32_t, int32_t> CalcDrawCoordinate(const OLD::DisplayInfo& displayInfo,
        PointerEvent::PointerItem pointerItem);
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    bool IsPointInsideWindowArea(int x, int y, const WindowInfo& windowItem) const;
    bool IsPointInsideSpecialWindow(double x, double y);
    bool IsMouseInCastWindow();
    bool IsCaptureMode();
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    bool IsMouseDragging() const;
    void EnsureMouseEventCycle(std::shared_ptr<PointerEvent> event);
    void CleanMouseEventCycle(std::shared_ptr<PointerEvent> event);
#endif // OHOS_BUILD_ENABLE_POINTER

private:
    bool NeedTouchTracking(PointerEvent &event) const;
    void ProcessTouchTracking(std::shared_ptr<PointerEvent> event, const WindowInfo &targetWindow);
    bool IgnoreTouchEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void ReissueCancelTouchEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;
    void PrintHighZorder(const std::vector<WindowInfo> &windowsInfo, int32_t pointerAction,
        int32_t targetWindowId, int32_t logicalX, int32_t logicalY);
    void PrintZorderInfo(const WindowInfo &windowInfo, std::string &window);
    void PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo);
    void PrintDisplayGroupInfo(const OLD::DisplayGroupInfo displayGroupInfo);
    void PrintDisplayInfo(const OLD::DisplayInfo displayInfo);
    void PrintWindowGroupInfo(const WindowGroupInfo &windowGroupInfo);
    void PrintWindowNavbar(int32_t groupId = DEFAULT_GROUP_ID);
    void CheckFocusWindowChange(const OLD::DisplayGroupInfo &displayGroupInfo);
    void CheckZorderWindowChange(const std::vector<WindowInfo> &oldWindowsInfo,
        const std::vector<WindowInfo> &newWindowsInfo);
    void UpdateDisplayIdAndName(int32_t groupId = DEFAULT_GROUP_ID);
    void UpdateCustomStyle(int32_t windowId, PointerStyle pointerStyle);
    void UpdatePointerAction(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsNeedDrawPointer(PointerEvent::PointerItem &pointerItem) const;
    bool IsWritePen(PointerEvent::PointerItem &pointerItem) const;
    bool IsWriteTablet(PointerEvent::PointerItem &pointerItem) const;
    void UpdateDisplayInfoByIncrementalInfo(const WindowInfo &window, OLD::DisplayGroupInfo &displayGroupInfo);
    void UpdateWindowsInfoPerDisplay(const OLD::DisplayGroupInfo &displayGroupInfo,
        const std::vector<int32_t> &deleteGroups);
    std::pair<int32_t, int32_t> TransformSampleWindowXY(int32_t logicX, int32_t logicY) const;
    bool IsValidZorderWindow(const WindowInfo &window, const std::shared_ptr<PointerEvent>& pointerEvent);
    bool SkipPrivacyProtectionWindow(const std::shared_ptr<PointerEvent>& pointerEvent, const bool &isSkip);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void UpdateTopBottomArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateLeftRightArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateInnerAngleArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void CoordinateCorrection(int32_t width, int32_t height, int32_t &integerX, int32_t &integerY);
    void GetWidthAndHeight(const OLD::DisplayInfo* displayInfo, int32_t &width, int32_t &height,
        bool isRealData = true);
    void UpdateCurrentDisplay(int32_t displayId) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void SetPrivacyModeFlag(SecureFlag privacyMode, std::shared_ptr<InputEvent> event);
    void PrintChangedWindowByEvent(int32_t eventType, const WindowInfo &newWindowInfo);
    void PrintChangedWindowBySync(const OLD::DisplayGroupInfo &newDisplayInfo);
    bool IsMouseDrawing(int32_t currentAction);
    bool ParseConfig();
    bool ParseJson(const std::string &configFile);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void SendUIExtentionPointerEvent(double logicalX, double logicalY,
        const WindowInfo& windowInfo, std::shared_ptr<PointerEvent> pointerEvent);
    void DispatchUIExtentionPointerEvent(double logicalX, double logicalY,
        std::shared_ptr<PointerEvent> pointerEvent);
    void PrintPointerEventInfo(const WindowInfo& item, std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::vector<int32_t> HandleHardwareCursor(const OLD::DisplayInfo *physicalDisplayInfo,
        int32_t physicalX, int32_t physicalY);
    void GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
        int32_t &physicalX, int32_t &physicalY);
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow);
    void NotifyPointerToWindow(int32_t groupId = DEFAULT_GROUP_ID);
    void OnSessionLost(SessionPtr session);
    void InitPointerStyle(int32_t groupId = DEFAULT_GROUP_ID);
    const std::vector<WindowInfo>& GetWindowGroupInfoByDisplayId(int32_t displayId) const;
    const std::vector<OLD::DisplayInfo>& GetDisplayInfoVector(int32_t groupId = DEFAULT_GROUP_ID) const;
    const std::vector<WindowInfo>& GetWindowInfoVector(int32_t groupId = DEFAULT_GROUP_ID) const;
    int32_t GetFocusWindowId(int32_t groupId = DEFAULT_GROUP_ID) const;
    int32_t GetMainDisplayId(int32_t groupId = DEFAULT_GROUP_ID) const;
    int32_t GetFocusPid(int32_t groupId = DEFAULT_GROUP_ID) const;
    int32_t GetLogicalPositionX(int32_t id);
    int32_t GetLogicalPositionY(int32_t id);
    Direction GetLogicalPositionDirection(int32_t id);
    Direction GetPositionDisplayDirection(int32_t id);
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t UpdatePoinerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle);
    int32_t UpdateSceneBoardPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
        bool isUiExtension = false);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    std::optional<WindowInfo> SelectWindowInfo(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent);
    void CheckUIExtentionWindowPointerHotArea(int32_t logicalX, int32_t logicalY,
        const std::vector<WindowInfo>& windowInfos, int32_t& windowId);
    std::optional<WindowInfo> GetWindowInfo(int32_t logicalX, int32_t logicalY, int32_t groupId = DEFAULT_GROUP_ID);
    bool IsInsideDisplay(const OLD::DisplayInfo& displayInfo, double physicalX, double physicalY);
    bool CalculateLayout(const OLD::DisplayInfo& displayInfo, const Vector2D<double> &physical,
        Vector2D<double>& layout);
    void FindPhysicalDisplay(const OLD::DisplayInfo& displayInfo, double& physicalX,
        double& physicalY, int32_t& displayId);
    bool AcrossDisplay(const OLD::DisplayInfo &displayInfoDes, const OLD::DisplayInfo &displayInfoOri,
        Vector2D<double> &logical, Vector2D<double> &layout, const AcrossDirection &acrossDirection);
    AcrossDirection CalculateAcrossDirection(const OLD::DisplayInfo &displayInfo, const Vector2D<double> &layout);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void InitMouseDownInfo();
    bool SelectPointerChangeArea(const WindowInfo &windowInfo, PointerStyle &pointerStyle,
        int32_t logicalX, int32_t logicalY);
    void UpdatePointerChangeAreas(const OLD::DisplayGroupInfo &displayGroupInfo);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    void AdjustDisplayRotation(int32_t groupId = DEFAULT_GROUP_ID);
    void SetPointerEvent(int32_t pointerAction, std::shared_ptr<PointerEvent> pointerEvent);
    void DispatchPointerCancel(int32_t displayId);
    void AdjustDragPosition(int32_t groupId = DEFAULT_GROUP_ID);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    void PointerDrawingManagerOnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo,
        bool isDisplayRemoved = false);
void DrawPointer(bool isDisplayRemoved);
bool NeedUpdatePointDrawFlag(const std::vector<WindowInfo> &windows);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

    void UpdateFixedXY(const OLD::DisplayInfo& displayInfo, std::shared_ptr<PointerEvent> &pointerEvent);
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
void UpdatePointerItemInOneHandMode(const OLD::DisplayInfo &displayInfo, std::shared_ptr<PointerEvent> &pointerEvent);
void UpdateDisplayXYInOneHandMode(double& physicalX, double& physicalY, const OLD::DisplayInfo &displayInfo,
    float oneHandScale);
void HandleOneHandMode(const OLD::DisplayInfo &displayInfo, std::shared_ptr<PointerEvent> &pointerEvent,
    PointerEvent::PointerItem &pointerItem);
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool SkipAnnotationWindow(uint32_t flag, int32_t toolType);
    bool SkipNavigationWindow(WindowInputType windowType, int32_t toolType);
    void HandleGestureInjection(bool gestureInject);
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateTargetTouchWinIds(const WindowInfo &item, PointerEvent::PointerItem &pointerItem,
        std::shared_ptr<PointerEvent> pointerEvent, int32_t pointerId, int32_t displayId, int32_t deviceId);
    void ClearMismatchTypeWinIds(int32_t pointerId, int32_t displayId, int32_t deviceId);
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool IsValidNavigationWindow(const WindowInfo& touchWindow, double physicalX, double physicalY);
    bool IsNavigationWindowInjectEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateTransformDisplayXY(std::shared_ptr<PointerEvent> pointerEvent,
        const std::vector<WindowInfo>& windowsInfo, const OLD::DisplayInfo& displayInfo);
    void HandlePullEvent(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void PullEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow);
    void DispatchTouch(int32_t pointerAction, int32_t groupId = DEFAULT_GROUP_ID);
    const OLD::DisplayInfo *FindPhysicalDisplayInfo(const std::string& uniq) const;
    bool GetPhysicalDisplayCoord(int32_t deviceId, struct libinput_event_touch* touch,
        const OLD::DisplayInfo& info, EventTouch& touchInfo, bool isNeedClear = false,
        bool hasValidAreaDowned = false);
    void TriggerTouchUpOnInvalidAreaEntry(int32_t pointerId);
    void SetAntiMisTake(bool state);
    void SetAntiMisTakeStatus(bool state);
    void CheckUIExtentionWindowDefaultHotArea(std::pair<int32_t, int32_t> logicalXY, bool isHotArea,
        const std::shared_ptr<PointerEvent> pointerEvent, const std::vector<WindowInfo>& windowInfos,
        const WindowInfo** touchWindow);
    void GetUIExtentionWindowInfo(std::vector<WindowInfo> &uiExtentionWindowInfo, int32_t windowId,
        WindowInfo **touchWindow, bool &isUiExtentionWindow);
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
    void TouchEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow);
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, const WindowInfo &window) const;
    bool InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, PointerStyle &pointerStyle) const;
    bool InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    template <class T>
    void CreateAntiMisTakeObserver(T& item);
    template <class T>
    void CreatePrivacyProtectionObserver(T& item);

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    int32_t UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_CROWN)
    int32_t UpdateCrownTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_CROWN
    void UpdateDisplayMode(int32_t groupId = DEFAULT_GROUP_ID);
    void HandleValidDisplayChange(const OLD::DisplayGroupInfo &displayGroupInfo);
    void ResetPointerPositionIfOutValidDisplay(const OLD::DisplayGroupInfo &displayGroupInfo);
    void CancelMouseEvent();
    bool IsPositionOutValidDisplay(
        Coordinate2D &position, const OLD::DisplayInfo &currentDisplay, bool isPhysicalPos = false,
        bool hasValidAreaDowned = false);
    void CancelTouchScreenEventIfValidDisplayChange(const OLD::DisplayGroupInfo &displayGroupInfo);
    bool IsValidDisplayChange(const OLD::DisplayInfo &displayInfo);
    void UpdateKeyEventDisplayId(std::shared_ptr<KeyEvent> keyEvent, int32_t focusWindowId, int32_t groupId = DEFAULT_GROUP_ID);
    bool OnDisplayRemovedOrCombinationChanged(const OLD::DisplayGroupInfo &displayGroupInfo);
    void ChangeWindowArea(int32_t x, int32_t y, WindowInfo &windowInfo);
    void ResetPointerPosition(const OLD::DisplayGroupInfo &displayGroupInfo);
    int32_t GetMainScreenDisplayInfo(const std::vector<OLD::DisplayInfo> &displaysInfo,
        OLD::DisplayInfo &mainScreenDisplayInfo) const;
    bool IsPointerOnCenter(const CursorPosition &currentPos, const OLD::DisplayInfo &currentDisplay);
    void SendBackCenterPointerEevent(const CursorPosition &cursorPos);
    WINDOW_UPDATE_ACTION UpdateWindowInfo(OLD::DisplayGroupInfo &displayGroupInfo);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    std::optional<WindowInfo> GetWindowInfoById(int32_t windowId) const;
    int32_t ShiftAppMousePointerEvent(const ShiftWindowInfo &shiftWindowInfo, bool autoGenDown);
    int32_t ShiftAppTouchPointerEvent(const ShiftWindowInfo &shiftWindowInfo);
    int32_t ShiftAppSimulateTouchPointerEvent(const ShiftWindowInfo &shiftWindowInfo);
    CursorPosition GetCursorPos(const OLD::DisplayGroupInfo &displayGroupInfo);
    CursorPosition ResetCursorPos(const OLD::DisplayGroupInfo &displayGroupInfo);
    GlobalCoords DisplayCoords2GlobalCoords(const Coordinate2D &displayCoords, int32_t displayId);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    bool CancelTouch(int32_t touch);
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    bool IsPointerActiveRectValid(const OLD::DisplayInfo &currentDisplay);
    bool IsKeyEventFromVKeyboard(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    bool IsAccessibilityFocusEvent(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsAccessibilityEventWithZorderInjected(std::shared_ptr<PointerEvent> pointerEvent);
    void GetActiveWindowTypeById(int32_t windowId, WindowInputType &windowTypeTemp);
    void AddActiveWindow(int32_t windowId, int32_t pointerId);
    void RemoveActiveWindow(std::shared_ptr<PointerEvent> pointerEvent);
    void ClearActiveWindow();
    void UpdateWindowInfoFlag(uint32_t flag, std::shared_ptr<InputEvent> event);
private:
    OLD::DisplayGroupInfo& FindTargetDisplayGroupInfo(int32_t displayId);
    int32_t FindDisplayGroupId(int32_t displayId) const;
    const OLD::DisplayGroupInfo& FindDisplayGroupInfo(int32_t displayId) const;
    OLD::DisplayGroupInfo& GetDefaultDisplayGroupInfo();
    const OLD::DisplayGroupInfo& GetConstMainDisplayGroupInfo() const;
    void RotateScreen90(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const;
    void RotateScreen0(const OLD::DisplayInfo& info, PhysicalCoordinate& coord) const;
    void InitDisplayGroupInfo(OLD::DisplayGroupInfo &displayGroupInfo);
    void DeleteInvalidDisplayGroups(const OLD::DisplayGroupInfo &displayGroupInfo,
        std::vector<int32_t> &deleteGroups);
    void DeleteInvalidWindowGroups(const std::vector<int32_t> &deleteGroups);
private:
    UDSServer* udsServer_ { nullptr };
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool isUiExtension_ { false };
    int32_t uiExtensionPid_ { -1 };
    int32_t uiExtensionWindowId_ { -1 };
    std::pair<int32_t, int32_t> firstBtnDownWindowInfo_ {-1, -1};
    std::optional<WindowInfo> axisBeginWindowInfo_ { std::nullopt };
    int32_t lastLogicX_ { -1 };
    int32_t lastLogicY_ { -1 };
    WindowInfo lastWindowInfo_;
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
    std::map<int32_t, std::map<int32_t, PointerStyle>> pointerStyle_;
    std::map<int32_t, std::map<int32_t, PointerStyle>> uiExtensionPointerStyle_;
    WindowInfo mouseDownInfo_;
    PointerStyle globalStyle_;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    int32_t lastTouchLogicX_ { -1 };
    int32_t lastTouchLogicY_ { -1 };
    WindowInfo lastTouchWindowInfo_;
    std::shared_ptr<PointerEvent> lastTouchEvent_ { nullptr };
    std::shared_ptr<PointerEvent> lastTouchEventOnBackGesture_ { nullptr };
#endif // OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    std::weak_ptr<TouchGestureManager> touchGestureMgr_;
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    std::map<int32_t, OLD::DisplayGroupInfo> displayGroupInfoMap_;
    std::map<int32_t, OLD::DisplayGroupInfo> displayGroupInfoMapTmp_;
    bool mainGroupExisted_;
    DisplayGroupInfo displayGroupInfoTmp_;
    std::mutex tmpInfoMutex_;
    OLD::DisplayGroupInfo displayGroupInfo_;
    DisplayGroupInfo displayGroupInfoCurr_;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay_;
    std::map<int32_t, std::map<int32_t, WindowGroupInfo>> windowsPerDisplayMap_;
    PointerStyle lastPointerStyle_;
    PointerStyle dragPointerStyle_;
    MouseLocation mouseLocation_ = { -1, 0, 0 };
    WindowInfo lockWindowInfo_;

    std::map<int32_t, MouseLocation> mouseLocationMap_;
    CursorPosition cursorPos_ {};
    std::map<int32_t, CursorPosition> cursorPosMap_;


    std::map<int32_t, WindowInfoEX> touchItemDownInfos_;
    std::map<int32_t, std::map<int32_t, WindowInfoEX>> touchItemDownInfosMap_;
    std::map<int32_t, std::vector<Rect>> windowsHotAreas_;
    std::map<int32_t, std::map<int32_t, std::vector<Rect>>> windowsHotAreasMap_;

    InputDisplayBindHelper bindInfo_;
    struct CaptureModeInfo {
        int32_t windowId { -1 };
        bool isCaptureMode { false };
    } captureModeInfo_;
    std::map<int32_t, CaptureModeInfo> captureModeInfoMap_;
    ExtraData extraData_;
    int32_t mouseDownEventId_ { -1 };
    bool haveSetObserver_ { false };
    bool dragFlag_ { false };
    bool isDragBorder_ { false };
    bool pointerDrawFlag_ { false };
    std::map<int32_t, bool> pointerDrawFlagMap_;
    DisplayMode displayMode_ { DisplayMode::UNKNOWN };
    std::map<int32_t, DisplayMode> displayModeMap_;
    struct AntiMisTake {
        std::string switchName;
        bool isOpen { false };
    } antiMistake_;
    bool isOpenAntiMisTakeObserver_ { false };
    struct PrivacyProtection {
        std::string switchName;
        bool isOpen { false };
    } privacyProtection_;
    bool isOpenPrivacyProtectionserver_ { false };
    bool mouseFlag_ {false};
    struct ActiveTouchWin {
        WindowInputType windowInputType{ WindowInputType::NORMAL };
        std::set<int32_t> pointerSet;
        explicit ActiveTouchWin(WindowInputType windowInputType, std::set<int32_t> pointerSet = {})
            : windowInputType(windowInputType), pointerSet(pointerSet)
        {}
    };
    std::map<int32_t, ActiveTouchWin> activeTouchWinTypes_;
    std::map<int32_t, std::map<int32_t, std::set<int32_t>>> targetTouchWinIds_;
    std::map<int32_t, std::set<int32_t>> targetMouseWinIds_;
    int32_t pointerActionFlag_ { -1 };
    int32_t currentUserId_ { -1 };
    std::shared_ptr<PointerEvent> lastPointerEventforWindowChange_ { nullptr };
    std::map<int32_t, std::shared_ptr<PointerEvent>> lastPointerEventforWindowChangeMap_;
    bool cancelTouchStatus_ { false };
    std::pair<int32_t, Direction> lastDirection_ { -1, static_cast<Direction>(-1) };
    std::map<int32_t, WindowInfo> lastMatchedWindow_;
    std::vector<SwitchFocusKey> vecWhiteList_;
    bool isParseConfig_ { false };
    std::map<int32_t, int32_t> windowStateNotifyUserIdPid_;
    std::map<int32_t, std::unique_ptr<Media::PixelMap>> transparentWins_;
#ifdef OHOS_BUILD_ENABLE_TOUCH
    std::shared_ptr<PointerEvent> lastPointerEventforGesture_ { nullptr };
#endif // OHOS_BUILD_ENABLE_TOUCH
    bool IsFoldable_ { false };
    int32_t timerId_ { -1 };
    int32_t lastDpi_ { 0 };
    std::map<int32_t, int32_t> lastDpiMap_;
    std::shared_ptr<PointerEvent> GetlastPointerEvent();
    void SetDragFlagByPointer(std::shared_ptr<PointerEvent> lastPointerEvent);
    std::mutex mtx_;
    std::atomic_bool isFoldPC_ { false };
    std::mutex oneHandMtx_;
    int32_t scalePercent_ = 100;
    mutable int32_t lastWinX_ { 0 };
    mutable int32_t lastWinY_ { 0 };
    mutable std::pair<int32_t, int32_t> currentDisplayXY_ { 0, 0 };
    WindowInfo pointerLockedWindow_;
    MouseLocation pointerLockedLocation_ = { -1, 0, 0 };
    Coordinate2D pointerLockedCursorPos_ = { 0.0, 0.0 };
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H
