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

#ifndef INPUT_WINDOWS_MANAGER_MOCK_H
#define INPUT_WINDOWS_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "nocopyable.h"

#include "i_input_windows_manager.h"

namespace OHOS {
namespace MMI {
class InputWindowsManagerMock final : public IInputWindowsManager {
public:
    InputWindowsManagerMock() = default;
    ~InputWindowsManagerMock() = default;
    DISALLOW_COPY_AND_MOVE(InputWindowsManagerMock);

    void Init(UDSServer&) override {}
    MOCK_METHOD(int32_t, GetClientFd, (std::shared_ptr<PointerEvent>));
    MOCK_METHOD(int32_t, GetClientFd, (std::shared_ptr<PointerEvent>, int32_t));
    void UpdateDisplayInfo(DisplayGroupInfo&) override {}
    void UpdateDisplayInfoExtIfNeed(DisplayGroupInfo&, bool) override {}
    void UpdateWindowInfo(const WindowGroupInfo&) override {}
    void SetWindowPointerStyle(WindowArea area, int32_t, int32_t) override {}
    MOCK_METHOD(int32_t, ClearWindowPointerStyle, (int32_t, int32_t));
    void Dump(int32_t, const std::vector<std::string>&) override {}
    MOCK_METHOD(int32_t, GetWindowPid, (int32_t), (const));
    MOCK_METHOD(int32_t, SetMouseCaptureMode, (int32_t, bool));
    MOCK_METHOD(bool, GetMouseIsCaptureMode, (), (const));
    MOCK_METHOD(int32_t, GetDisplayBindInfo, (DisplayBindInfos&));
    MOCK_METHOD(int32_t, SetDisplayBind, (int32_t, int32_t, std::string&));
    MOCK_METHOD(int32_t, AppendExtraData, (const ExtraData&));
    MOCK_METHOD(bool, IsWindowVisible, (int32_t));
    MOCK_METHOD(ExtraData, GetExtraData, (), (const));
    MOCK_METHOD(const std::vector<WindowInfo>&, GetWindowGroupInfoByDisplayId, (int32_t), (const));
    MOCK_METHOD((std::pair<double, double>), TransformWindowXY, (const WindowInfo&, double, double), (const));
    void ClearTargetWindowId(int32_t pointerId) override {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    MOCK_METHOD(int32_t, UpdateTarget, (std::shared_ptr<KeyEvent>));
    MOCK_METHOD(void, HandleKeyEventWindowId, (std::shared_ptr<KeyEvent>));
#endif // OHOS_BUILD_ENABLE_KEYBOARD

    MOCK_METHOD(int32_t, CheckWindowIdPermissionByPid, (int32_t, int32_t));

#ifdef OHOS_BUILD_ENABLE_POINTER
    MOCK_METHOD(MouseLocation, GetMouseInfo, ());
    MOCK_METHOD(CursorPosition, GetCursorPos, ());
    MOCK_METHOD(CursorPosition, ResetCursorPos, ());
    void UpdateAndAdjustMouseLocation(int32_t&, double&, double&, bool) override {}
    MOCK_METHOD(int32_t, SetHoverScrollState, (bool));
    MOCK_METHOD(bool, GetHoverScrollState, (), (const));
    MOCK_METHOD(int32_t, SetPointerStyle, (int32_t, int32_t, PointerStyle, bool));
    MOCK_METHOD(int32_t, GetPointerStyle, (int32_t, int32_t, PointerStyle&, bool), (const));
    void DispatchPointer(int32_t pointerAction, int32_t windowId = -1) override {}
    void SendPointerEvent(int32_t pointerAction) override {}
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    MOCK_METHOD(bool, IsNeedRefreshLayer, (int32_t));
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif //OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    MOCK_METHOD(bool, TouchPointToDisplayPoint, (int32_t, struct libinput_event_touch*, EventTouch&, int32_t&));
    MOCK_METHOD(bool, CalculateTipPoint, (struct libinput_event_tablet_tool*, int32_t&, PhysicalCoordinate&), (const));
    MOCK_METHOD(const DisplayInfo*, GetDefaultDisplayInfo, (), (const));
    MOCK_METHOD(void, ReverseXY, (int32_t&, int32_t&));
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void DrawTouchGraphic(std::shared_ptr<PointerEvent>) override {}
    MOCK_METHOD(int32_t, UpdateTargetPointer, (std::shared_ptr<PointerEvent>));
    MOCK_METHOD(const DisplayInfo*, GetPhysicalDisplay, (int32_t), (const));
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
    void UpdatePointerChangeAreas() override {}
#endif // OHOS_BUILD_ENABLE_POINTER

    MOCK_METHOD(std::optional<WindowInfo>, GetWindowAndDisplayInfo, (int32_t, int32_t));

    void GetTargetWindowIds(int32_t, int32_t, std::vector<int32_t>&) override {}
    MOCK_METHOD(int32_t, SetCurrentUser, (int32_t));
    MOCK_METHOD(DisplayMode, GetDisplayMode, (), (const));
#ifdef OHOS_BUILD_ENABLE_ANCO
    MOCK_METHOD(int32_t, AncoAddChannel, (sptr<IAncoChannel>));
    MOCK_METHOD(int32_t, AncoRemoveChannel, (sptr<IAncoChannel>));
#endif // OHOS_BUILD_ENABLE_ANCO

    static std::shared_ptr<InputWindowsManagerMock> GetInstance();

private:
    static std::mutex mutex_;
    static std::shared_ptr<InputWindowsManagerMock> instance_;
};

#define WIN_MGR_MOCK ::OHOS::MMI::InputWindowsManagerMock::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_MOCK_H
