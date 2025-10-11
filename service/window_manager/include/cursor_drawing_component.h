/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CURSOR_DRAWING_COMPONENT_H
#define CURSOR_DRAWING_COMPONENT_H

#include <cstdint>
#include <map>

#include "delegate_interface.h"
#include "i_pointer_drawing_manager.h"
#include "pointer_style.h"
#include "window_info.h"
#include "struct_multimodal.h"

namespace OHOS::MMI {
class CursorDrawingComponent {
public:
    static CursorDrawingComponent& GetInstance();
    void Load();
    void UnLoad();

    void DrawPointer(uint64_t displayId, int32_t physicalX, int32_t physicalY,
        const PointerStyle pointerStyle, Direction direction);
    void UpdateDisplayInfo(const OLD::DisplayInfo &displayInfo);
    void OnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo);
    void OnWindowInfo(const WinInfo &info);
    bool Init();
    void DeletePointerVisible(int32_t pid);
    int32_t SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap);
    bool GetPointerVisible(int32_t pid);
    int32_t SetPointerColor(int32_t color);
    int32_t GetPointerColor();
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle, bool isUiExtension);
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId);
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension);
    void DrawPointerStyle(const PointerStyle &pointerStyle);
    bool IsPointerVisible();
    void SetPointerLocation(int32_t x, int32_t y, uint64_t displayId);
    void SetMouseDisplayState(bool state);
    bool GetMouseDisplayState();
    int32_t SetCustomCursor(CursorPixelMap curPixelMap, int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY);
    int32_t SetCustomCursor(int32_t pid, int32_t windowId, CustomCursor cursor, CursorOptions options);
    int32_t SetMouseIcon(int32_t pid, int32_t windowId, CursorPixelMap curPixelMap);
    int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY);
    int32_t SetPointerSize(int32_t size);
    int32_t GetPointerSize();
    void GetPointerImageSize(int32_t &width, int32_t &height);
    int32_t GetCursorSurfaceId(uint64_t &surfaceId);
    PointerStyle GetLastMouseStyle();
    IconStyle GetIconStyle(const MOUSE_ICON mouseStyle);
    const std::map<MOUSE_ICON, IconStyle>& GetMouseIconPath();
    int32_t SwitchPointerStyle();
    void DrawMovePointer(uint64_t displayId, int32_t physicalX, int32_t physicalY);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void InitPointerCallback();
    void InitScreenInfo();
    int32_t EnableHardwareCursorStats(int32_t pid, bool enable);
    int32_t GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount);
    OLD::DisplayInfo GetCurrentDisplayInfo();
    void ForceClearPointerVisiableStatus();
    void InitPointerObserver();
    void OnSessionLost(int32_t pid);
    int32_t SkipPointerLayer(bool isSkip);

    void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy);
    std::shared_ptr<DelegateInterface> GetDelegateProxy();
    void DestroyPointerWindow();
    void DrawScreenCenterPointer(const PointerStyle &pointerStyle);
    void SubscribeScreenModeChange();
    void RegisterDisplayStatusReceiver();
    void InitDefaultMouseIconPath();
    int32_t UpdateMouseLayer(
        const PointerStyle &pointerStyle, uint64_t displayId, int32_t physicalX, int32_t physicalY);
    int32_t DrawNewDpiPointer();
    bool GetHardCursorEnabled();

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t GetPointerSnapshot(void *pixelMapPtr);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

#ifndef OHOS_BUILD_ENABLE_WATCH
    void NotifyPointerEventToRS(int32_t pointAction, int32_t pointCnt);
#endif // OHOS_BUILD_ENABLE_WATCH
    int32_t GetCurrentCursorInfo(bool& visible, PointerStyle& pointerStyle);
    int32_t GetUserDefinedCursorPixelMap(void *pixelMapPtr);
private:
    CursorDrawingComponent();
    ~CursorDrawingComponent();
    bool LoadLibrary();
    DISALLOW_COPY_AND_MOVE(CursorDrawingComponent);
    using GetPointerInstanceFunc = void* (*)();
    GetPointerInstanceFunc getPointerInstance_;

    std::mutex loadSoMutex_;
    std::atomic<bool> exitFlag_ { false };
    std::atomic<bool> isLoaded_ { false };
    void *soHandle_ { nullptr };
    IPointerDrawingManager* pointerInstance_ { nullptr };
    int32_t timerId_ { -1 };
    std::chrono::time_point<std::chrono::steady_clock> lastCallTime_ { std::chrono::steady_clock::now() };
};
} // namespace OHOS::MMI

#endif // CURSOR_DRAWING_COMPONENT_H