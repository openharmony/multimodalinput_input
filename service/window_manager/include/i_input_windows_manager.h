/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "i_anco_channel.h"
#endif
#include "key_event.h"
#include "pointer_event.h"
#include "pointer_style.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "window_info.h"

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
    virtual int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId) = 0;
    virtual void UpdateDisplayInfo(DisplayGroupInfo &displayGroupInfo) = 0;
    virtual void UpdateDisplayInfoExtIfNeed(DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt) = 0;
    virtual void UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo) = 0;
    virtual void SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId) = 0;
    virtual int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) = 0;
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) = 0;
    virtual int32_t GetWindowPid(int32_t windowId) const = 0;
    virtual int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) = 0;
    virtual bool GetMouseIsCaptureMode() const = 0;
    virtual int32_t GetDisplayBindInfo(DisplayBindInfos &infos) = 0;
    virtual int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) = 0;
    virtual int32_t AppendExtraData(const ExtraData& extraData) = 0;
    virtual bool IsWindowVisible(int32_t pid) = 0;
    virtual ExtraData GetExtraData() const = 0;
    virtual const std::vector<WindowInfo>& GetWindowGroupInfoByDisplayId(int32_t displayId) const = 0;
    virtual std::pair<double, double> TransformWindowXY(const WindowInfo &, double, double) const = 0;
    virtual void ClearTargetWindowId(int32_t pointerId) = 0;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    virtual std::vector<std::pair<int32_t, TargetInfo>> UpdateTarget(std::shared_ptr<KeyEvent> keyEvent) = 0;
    virtual void HandleKeyEventWindowId(std::shared_ptr<KeyEvent> keyEvent) = 0;
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    virtual int32_t CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid) = 0;

#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual MouseLocation GetMouseInfo() = 0;
    virtual CursorPosition GetCursorPos() = 0;
    virtual CursorPosition ResetCursorPos() = 0;
    virtual void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData = true) = 0;
    virtual int32_t SetHoverScrollState(bool state) = 0;
    virtual bool GetHoverScrollState() const = 0;
    virtual int32_t SetPointerStyle(int32_t pid, int32_t windowId,
        PointerStyle pointerStyle, bool isUiExtension = false) = 0;
    virtual int32_t GetPointerStyle(int32_t pid, int32_t windowId,
        PointerStyle &pointerStyle, bool isUiExtension = false) const = 0;
    virtual void DispatchPointer(int32_t pointerAction, int32_t windowId = -1) = 0;
    virtual void SendPointerEvent(int32_t pointerAction) = 0;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    virtual bool IsNeedRefreshLayer(int32_t windowId) = 0;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif //OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    virtual bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId) = 0;
    virtual bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, PhysicalCoordinate& coord) const = 0;
    virtual const DisplayInfo *GetDefaultDisplayInfo() const = 0;
    virtual void ReverseXY(int32_t &x, int32_t &y) = 0;
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    virtual void DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent) = 0;
    virtual const DisplayInfo* GetPhysicalDisplay(int32_t id) const = 0;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
    virtual void UpdatePointerChangeAreas() = 0;
#endif // OHOS_BUILD_ENABLE_POINTER
    virtual std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId) = 0;
    virtual void GetTargetWindowIds(int32_t pointerItemId, int32_t sourceType, std::vector<int32_t> &windowIds) = 0;
    virtual int32_t SetCurrentUser(int32_t userId) = 0;
    virtual DisplayMode GetDisplayMode() const = 0;

#ifdef OHOS_BUILD_ENABLE_ANCO
    virtual int32_t AncoAddChannel(sptr<IAncoChannel> channel) = 0;
    virtual int32_t AncoRemoveChannel(sptr<IAncoChannel> channel) = 0;
#endif // OHOS_BUILD_ENABLE_ANCO

    static std::shared_ptr<IInputWindowsManager> GetInstance();
    static void DestroyInstance();

private:
    static std::mutex mutex_;
    static std::shared_ptr<IInputWindowsManager> instance_;
};

#define WIN_MGR ::OHOS::MMI::IInputWindowsManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // I_INPUT_WINDOWS_MANAGER_H
