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

#ifndef INPUT_WINDOWS_MANAGER_H
#define INPUT_WINDOWS_MANAGER_H

#include <vector>

#include "nocopyable.h"
#include "pixel_map.h"
#include "window_manager_lite.h"

#include "i_input_windows_manager.h"
#include "input_display_bind_helper.h"
#include "input_event_data_transformation.h"
#include "knuckle_drawing_manager.h"
#include "knuckle_dynamic_drawing_manager.h"

namespace OHOS {
namespace MMI {
struct WindowInfoEX {
    WindowInfo window;
    bool flag { false };
};

struct SwitchFocusKey {
    int32_t keyCode { -1 };
    int32_t pressedKey { -1 };
};

class InputWindowsManager final : public IInputWindowsManager {
public:
    InputWindowsManager();
    ~InputWindowsManager();
    DISALLOW_COPY_AND_MOVE(InputWindowsManager);

    void Init(UDSServer& udsServer);
    void SetMouseFlag(bool state);
    bool GetMouseFlag();
    void JudgMouseIsDownOrUp(bool dragState);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId);
    bool HandleWindowInputType(const WindowInfo &window, std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateCaptureMode(const DisplayGroupInfo &displayGroupInfo);
    void UpdateDisplayInfo(DisplayGroupInfo &displayGroupInfo);
    void UpdateDisplayInfoExtIfNeed(DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt);
    void UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo);
    void SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId);
    void UpdateWindowPointerVisible(int32_t pid);
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    int32_t GetWindowPid(int32_t windowId, const std::vector<WindowInfo> &windowsInfo) const;
    int32_t GetWindowPid(int32_t windowId) const;
    int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode);
    bool GetMouseIsCaptureMode() const;
    void DeviceStatusChanged(int32_t deviceId, const std::string &sysUid, const std::string devStatus);
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t AppendExtraData(const ExtraData& extraData);
    bool IsWindowVisible(int32_t pid);
    void ClearExtraData();
    ExtraData GetExtraData() const;
    const std::vector<WindowInfo>& GetWindowGroupInfoByDisplayId(int32_t displayId) const;
    std::pair<double, double> TransformWindowXY(const WindowInfo &window, double logicX, double logicY) const;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    std::vector<std::pair<int32_t, TargetInfo>> GetPidAndUpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
    std::vector<std::pair<int32_t, TargetInfo>> UpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
    bool IsKeyPressed(int32_t pressedKey, std::vector<KeyEvent::KeyItem> &keyItems);
    bool IsOnTheWhitelist(std::shared_ptr<KeyEvent> keyEvent);
    void HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid);

#ifdef OHOS_BUILD_ENABLE_POINTER
    MouseLocation GetMouseInfo();
    CursorPosition GetCursorPos();
    CursorPosition ResetCursorPos();
    void SetGlobalDefaultPointerStyle();
    void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData = true);
    const DisplayGroupInfo& GetDisplayGroupInfo();
    int32_t SetHoverScrollState(bool state);
    bool GetHoverScrollState() const;
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false);
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
        bool isUiExtension = false) const;
    void SetUiExtensionInfo(bool isUiExtension, int32_t uiExtensionPid, int32_t uiExtensionWindoId);
    void DispatchPointer(int32_t pointerAction, int32_t windowId = -1);
    void SendPointerEvent(int32_t pointerAction);
    PointerStyle GetLastPointerStyle() const;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool IsNeedRefreshLayer(int32_t windowId);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif //OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void AdjustDisplayCoordinate(const DisplayInfo& displayInfo, double& physicalX, double& physicalY) const;
    bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId);
    void ReverseRotateScreen(const DisplayInfo& info, const double x, const double y, Coordinate2D& cursorPos) const;
    void RotateScreen(const DisplayInfo& info, PhysicalCoordinate& coord) const;
    bool TransformTipPoint(struct libinput_event_tablet_tool* tip, PhysicalCoordinate& coord, int32_t& displayId) const;
    bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, PhysicalCoordinate& coord) const;
    const DisplayInfo *GetDefaultDisplayInfo() const;
    void ReverseXY(int32_t &x, int32_t &y);
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_ANCO
    void UpdateWindowInfoExt(const WindowGroupInfo &windowGroupInfo, const DisplayGroupInfo &displayGroupInfo);
    void UpdateShellWindow(const WindowInfo &window);
    void UpdateDisplayInfoExt(const DisplayGroupInfo &displayGroupInfo);
    bool IsInAncoWindow(const WindowInfo &window, int32_t x, int32_t y) const;
    bool IsAncoWindow(const WindowInfo &window) const;
    bool IsAncoWindowFocus(const WindowInfo &window) const;
    void SimulatePointerExt(std::shared_ptr<PointerEvent> pointerEvent);
    void DumpAncoWindows(std::string& out) const;
#endif // OHOS_BUILD_ENABLE_ANCO

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool UpdateDisplayId(int32_t& displayId);
    void DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
    const DisplayInfo* GetPhysicalDisplay(int32_t id) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
    void UpdatePointerChangeAreas();
#endif // OHOS_BUILD_ENABLE_POINTER
    std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId);
    void GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType, std::vector<int32_t> &windowIds);
    void AddTargetWindowIds(int32_t pointerItemId, int32_t sourceType, int32_t windowId);
    void ClearTargetWindowId(int32_t pointerId);
    bool IsTransparentWin(void* pixelMap, int32_t logicalX, int32_t logicalY);
    int32_t SetCurrentUser(int32_t userId);
    DisplayMode GetDisplayMode() const;

#ifdef OHOS_BUILD_ENABLE_ANCO
    int32_t AncoAddChannel(sptr<IAncoChannel> channel);
    int32_t AncoRemoveChannel(sptr<IAncoChannel> channel);
#endif // OHOS_BUILD_ENABLE_ANCO

private:
    void CheckFoldChange(std::shared_ptr<PointerEvent> pointerEvent);
    void OnFoldStatusChanged(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;
    void PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo);
    void PrintDisplayInfo();
    void PrintWindowGroupInfo(const WindowGroupInfo &windowGroupInfo);
    void CheckFocusWindowChange(const DisplayGroupInfo &displayGroupInfo);
    void CheckZorderWindowChange(const std::vector<WindowInfo> &oldWindowsInfo,
        const std::vector<WindowInfo> &newWindowsInfo);
    void UpdateDisplayIdAndName();
    void UpdatePointerAction(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsNeedDrawPointer(PointerEvent::PointerItem &pointerItem) const;
    void UpdateDisplayInfoByIncrementalInfo(const WindowInfo &window, DisplayGroupInfo &displayGroupInfo);
    void UpdateWindowsInfoPerDisplay(const DisplayGroupInfo &displayGroupInfo);
    std::pair<int32_t, int32_t> TransformSampleWindowXY(int32_t logicX, int32_t logicY) const;
    bool IsValidZorderWindow(const WindowInfo &window, const std::shared_ptr<PointerEvent>& pointerEvent);
    void UpdateTopBottomArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateLeftRightArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateInnerAngleArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void CoordinateCorrection(int32_t width, int32_t height, int32_t &integerX, int32_t &integerY);
    void GetWidthAndHeight(const DisplayInfo* displayInfo, int32_t &width, int32_t &height);
    void SetPrivacyModeFlag(SecureFlag privacyMode, std::shared_ptr<InputEvent> event);
    void FoldScreenRotation(std::shared_ptr<PointerEvent> pointerEvent);
    void PrintChangedWindowByEvent(int32_t eventType, const WindowInfo &newWindowInfo);
    void PrintChangedWindowBySync(const DisplayGroupInfo &newDisplayInfo);
    bool IsMouseDrawing(int32_t currentAction);
    bool ParseConfig();
    bool ParseJson(const std::string &configFile);
    void SendUIExtentionPointerEvent(int32_t logicalX, int32_t logicalY,
        const WindowInfo& windowInfo, std::shared_ptr<PointerEvent> pointerEvent);
    void DispatchUIExtentionPointerEvent(int32_t logicalX, int32_t logicalY,
        std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_POINTER
    void GetPointerStyleByArea(WindowArea area, int32_t pid, int32_t winId, PointerStyle& pointerStyle);
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow);
    void NotifyPointerToWindow();
    void OnSessionLost(SessionPtr session);
    void InitPointerStyle();
    int32_t UpdatePoinerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle);
    int32_t UpdateSceneBoardPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
        bool isUiExtension = false);
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
    std::optional<WindowInfo> SelectWindowInfo(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent);
    void CheckUIExtentionWindowPointerHotArea(int32_t logicalX, int32_t logicalY,
        const std::vector<WindowInfo>& windowInfos, int32_t& windowId);
    std::optional<WindowInfo> GetWindowInfo(int32_t logicalX, int32_t logicalY);
    bool IsInsideDisplay(const DisplayInfo& displayInfo, int32_t physicalX, int32_t physicalY);
    void FindPhysicalDisplay(const DisplayInfo& displayInfo, int32_t& physicalX,
        int32_t& physicalY, int32_t& displayId);
    void InitMouseDownInfo();
    bool SelectPointerChangeArea(const WindowInfo &windowInfo, PointerStyle &pointerStyle,
        int32_t logicalX, int32_t logicalY);
    void UpdatePointerChangeAreas(const DisplayGroupInfo &displayGroupInfo);
#endif // OHOS_BUILD_ENABLE_POINTER

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
void PointerDrawingManagerOnDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
bool NeedUpdatePointDrawFlag(const std::vector<WindowInfo> &windows);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool SkipAnnotationWindow(uint32_t flag, int32_t toolType);
    bool SkipNavigationWindow(WindowInputType windowType, int32_t toolType);
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void PullEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow);
    void DispatchTouch(int32_t pointerAction);
    const DisplayInfo* FindPhysicalDisplayInfo(const std::string& uniq) const;
    void GetPhysicalDisplayCoord(struct libinput_event_touch* touch,
        const DisplayInfo& info, EventTouch& touchInfo);
    void SetAntiMisTake(bool state);
    void SetAntiMisTakeStatus(bool state);
    void CheckUIExtentionWindowDefaultHotArea(int32_t logicalX, int32_t logicalY,
        const std::vector<WindowInfo>& windowInfos, int32_t& windowId);
    void GetUIExtentionWindowInfo(std::vector<WindowInfo> &uiExtentionWindowInfo, int32_t windowId,
        WindowInfo **touchWindow, bool &isUiExtentionWindow);
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, const WindowInfo &window) const;
    bool InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, PointerStyle &pointerStyle) const;
    template <class T>
    void CreateAntiMisTakeObserver(T& item);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    int32_t UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#ifdef OHOS_BUILD_ENABLE_CROWN
    int32_t UpdateCrownTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_CROWN

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    void UpdateDisplayMode();
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

private:
    UDSServer* udsServer_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_POINTER
    bool isUiExtension_ { false };
    int32_t uiExtensionPid_ { -1 };
    int32_t uiExtensionWindowId_ { -1 };
    int32_t firstBtnDownWindowId_ { -1 };
    int32_t lastLogicX_ { -1 };
    int32_t lastLogicY_ { -1 };
    WindowInfo lastWindowInfo_;
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
    std::map<int32_t, std::map<int32_t, PointerStyle>> pointerStyle_;
    std::map<int32_t, std::map<int32_t, PointerStyle>> uiExtensionPointerStyle_;
    WindowInfo mouseDownInfo_;
    PointerStyle globalStyle_;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    int32_t lastTouchLogicX_ { -1 };
    int32_t lastTouchLogicY_ { -1 };
    WindowInfo lastTouchWindowInfo_;
    std::shared_ptr<PointerEvent> lastTouchEvent_ { nullptr };
#endif // OHOS_BUILD_ENABLE_POINTER
    DisplayGroupInfo displayGroupInfoTmp_;
    DisplayGroupInfo displayGroupInfo_;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay_;
    PointerStyle lastPointerStyle_ {.id = -1};
    PointerStyle dragPointerStyle_ {.id = -1};
    MouseLocation mouseLocation_ = { -1, -1 };
    CursorPosition cursorPos_ {};
    std::map<int32_t, WindowInfoEX> touchItemDownInfos_;
    std::map<int32_t, std::vector<Rect>> windowsHotAreas_;
    InputDisplayBindHelper bindInfo_;
    struct CaptureModeInfo {
        int32_t windowId { -1 };
        bool isCaptureMode { false };
    } captureModeInfo_;
    ExtraData extraData_;
    bool haveSetObserver_ { false };
    bool dragFlag_ { false };
    bool isDragBorder_ { false };
    bool pointerDrawFlag_ { false };
    DisplayMode displayMode_ { DisplayMode::UNKNOWN };
    struct AntiMisTake {
        std::string switchName;
        bool isOpen { false };
    } antiMistake_;
    bool isOpenAntiMisTakeObserver_ { false };
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr_ { nullptr };
    bool mouseFlag_ {false};
    std::map<int32_t, std::vector<int32_t>> targetTouchWinIds_;
    std::map<int32_t, std::vector<int32_t>> targetMouseWinIds_;
    int32_t pointerActionFlag_ { -1 };
    int32_t currentUserId_ { -1 };
    std::shared_ptr<KnuckleDynamicDrawingManager> knuckleDynamicDrawingManager_ { nullptr };
    uint32_t lastFoldStatus_ {};
    Direction lastDirection_ = static_cast<Direction>(-1);
    std::map<int32_t, WindowInfo> lastMatchedWindow_;
    std::vector<SwitchFocusKey> vecWhiteList_;
    bool isParseConfig_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H
