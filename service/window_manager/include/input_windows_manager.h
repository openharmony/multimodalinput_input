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
#ifndef INPUT_WINDOWS_MANAGER_H
#define INPUT_WINDOWS_MANAGER_H

#include <vector>

#include "libinput.h"
#include "nocopyable.h"
#include "singleton.h"

#include "display_info.h"
#include "input_event.h"
#include "input_event_data_transformation.h"
#include "pointer_event.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
struct MouseLocation {
    int32_t physicalX { 0 };
    int32_t physicalY { 0 };
};

class InputWindowsManager final {
    DECLARE_DELAYED_SINGLETON(InputWindowsManager);
public:
    DISALLOW_COPY_AND_MOVE(InputWindowsManager);
    void Init(UDSServer& udsServer);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t GetPidAndUpdateTarget(std::shared_ptr<InputEvent> inputEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t UpdateTarget(std::shared_ptr<InputEvent> inputEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    void UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
#ifdef OHOS_BUILD_ENABLE_POINTER
    MouseLocation GetMouseInfo();
    void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y);
#endif //OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void AdjustDisplayCoordinate(const DisplayInfo& displayInfo, int32_t& physicalX, int32_t& physicalY) const;
#endif // OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool UpdateDisplayId(int32_t& displayId);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId);
    void RotateTouchScreen(DisplayInfo info, LogicalCoordinate& coord) const;
    bool TransformTipPoint(struct libinput_event_tablet_tool* tip, LogicalCoordinate& coord, int32_t& displayId) const;
    bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, LogicalCoordinate& coord) const;
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    const DisplayGroupInfo& GetDisplayGroupInfo();
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, int32_t pointerStyle);
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, int32_t &pointerStyle) const;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool IsNeedRefreshLayer(int32_t windowId);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif // OHOS_BUILD_ENABLE_POINTER
    void Dump(int32_t fd, const std::vector<std::string> &args);
    int32_t GetWindowPid(int32_t windowId, const DisplayGroupInfo& displayGroupInfo) const;
    int32_t GetWindowPid(int32_t windowId) const;
#ifdef OHOS_BUILD_ENABLE_POINTER
    void DispatchPointer(int32_t pointerAction);
    void SendPointerEvent(int32_t pointerAction);
#endif // OHOS_BUILD_ENABLE_POINTER

private:
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void PrintDisplayInfo();
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow);
    void NotifyPointerToWindow();
    void OnSessionLost(SessionPtr session);
    void UpdatePointerStyle();
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    int32_t UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_JOYSTICK
#ifdef OHOS_BUILD_ENABLE_TOUCH
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    const DisplayInfo* GetPhysicalDisplay(int32_t id) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_TOUCH
    const DisplayInfo* FindPhysicalDisplayInfo(const std::string& uniq) const;
#endif // OHOS_BUILD_ENABLE_TOUCH
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;
#ifdef OHOS_BUILD_ENABLE_POINTER
    std::optional<WindowInfo> SelectWindowInfo(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent);
    std::optional<WindowInfo> GetWindowInfo(int32_t logicalX, int32_t logicalY);
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void GetPhysicalDisplayCoord(struct libinput_event_touch* touch,
        const DisplayInfo& info, EventTouch& touchInfo);
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_POINTER
    bool IsInsideDisplay(const DisplayInfo& displayInfo, int32_t physicalX, int32_t physicalY);
    void FindPhysicalDisplay(const DisplayInfo& displayInfo, int32_t& physicalX,
        int32_t& physicalY, int32_t& displayId);
    void InitMouseDownInfo();
#endif // OHOS_BUILD_ENABLE_POINTER
    void CheckFocusWindowChange(const DisplayGroupInfo &displayGroupInfo);
    void CheckZorderWindowChange(const DisplayGroupInfo &displayGroupInfo);
private:
    UDSServer* udsServer_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t firstBtnDownWindowId_ { -1 };
    int32_t lastLogicX_ { -1 };
    int32_t lastLogicY_ { -1 };
    WindowInfo lastWindowInfo_;
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
    std::map<int32_t, std::map<int32_t, int32_t>> pointerStyle_;
    WindowInfo mouseDownInfo_;
#endif // OHOS_BUILD_ENABLE_POINTER
    DisplayGroupInfo displayGroupInfo_;
    MouseLocation mouseLocation_ = { -1, -1 }; // physical coord
    std::map<int32_t, WindowInfo> touchItemDownInfos_;
};

#define WinMgr ::OHOS::DelayedSingleton<InputWindowsManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H