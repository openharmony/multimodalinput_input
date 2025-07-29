/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef I_POINTER_DRAWING_MANAGER_H
#define I_POINTER_DRAWING_MANAGER_H

#include "pointer_style.h"
#include "old_display_info.h"
#include "delegate_interface.h"

namespace OHOS {
namespace MMI {
class IPointerDrawingManager {
public:
    IPointerDrawingManager() = default;
    virtual ~IPointerDrawingManager() = default;

    static IPointerDrawingManager* GetInstance();
    virtual void DrawPointer(uint64_t rsId, int32_t physicalX, int32_t physicalY,
        const PointerStyle pointerStyle, Direction direction) {}
    virtual void UpdateDisplayInfo(const OLD::DisplayInfo& displayInfo) {}
    virtual void OnDisplayInfo(const OLD::DisplayGroupInfo& displayGroupInfo) {}
    virtual void OnWindowInfo(const WinInfo &info) {}
    virtual bool Init()
    {
        return true;
    }
    virtual void DeletePointerVisible(int32_t pid) {}
    virtual int32_t SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
    {
        return 0;
    }
    virtual bool GetPointerVisible(int32_t pid)
    {
        return true;
    }
    virtual int32_t SetPointerColor(int32_t color)
    {
        return 0;
    }
    virtual int32_t GetPointerColor()
    {
        return 0;
    }
    virtual int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
        bool isUiExtension = false)
    {
        return 0;
    }
    virtual int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId)
    {
        return 0;
    }
    virtual int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
        bool isUiExtension = false)
    {
        return 0;
    }
    virtual void DrawPointerStyle(const PointerStyle& pointerStyle) {}
    virtual bool IsPointerVisible()
    {
        return false;
    }
    virtual void SetPointerLocation(int32_t x, int32_t y, uint64_t rsId) {}
    virtual void SetMouseDisplayState(bool state) {}
    virtual bool GetMouseDisplayState() const
    {
        return false;
    }
    virtual int32_t SetCustomCursor(CursorPixelMap curPixelMap,
        int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY)
    {
        return 0;
    }
    virtual int32_t SetCustomCursor(int32_t pid, int32_t windowId, CustomCursor cursor, CursorOptions options)
    {
        return 0;
    }
    virtual int32_t SetMouseIcon(int32_t pid, int32_t windowId, CursorPixelMap curPixelMap)
    {
        return 0;
    }
    virtual int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
    {
        return 0;
    }
    virtual int32_t SetPointerSize(int32_t size)
    {
        return 0;
    }
    virtual int32_t GetPointerSize()
    {
        return 0;
    }
    virtual void GetPointerImageSize(int32_t &width, int32_t &height)
    {
        return;
    }

    virtual int32_t GetCursorSurfaceId(uint64_t &surfaceId);

    virtual PointerStyle GetLastMouseStyle()
    {
        return {};
    }
    virtual IconStyle GetIconStyle(const MOUSE_ICON mouseStyle)
    {
        return {};
    }
    virtual const std::map<MOUSE_ICON, IconStyle>& GetMouseIconPath()
    {
        static std::map<MOUSE_ICON, IconStyle> emptyMap;
        return emptyMap;
    }
    virtual int32_t SwitchPointerStyle()
    {
        return 0;
    }
    virtual void DrawMovePointer(uint64_t rsId, int32_t physicalX, int32_t physicalY) {}
    virtual void Dump(int32_t fd, const std::vector<std::string> &args) {}
    virtual void InitPointerCallback() {}
    virtual void InitScreenInfo() {}
    virtual int32_t EnableHardwareCursorStats(int32_t pid, bool enable)
    {
        return 0;
    }
    virtual int32_t GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
    {
        return 0;
    }
    virtual OLD::DisplayInfo GetCurrentDisplayInfo()
    {
        return {};
    }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    virtual int32_t GetPointerSnapshot(void *pixelMapPtr)
    {
        return 0;
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    virtual void ForceClearPointerVisiableStatus() {}
    virtual void InitPointerObserver() {}
    virtual void OnSessionLost(int32_t pid) {}
    virtual int32_t SkipPointerLayer(bool isSkip)
    {
        return 0;
    }
    virtual void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy) {}
    virtual std::shared_ptr<DelegateInterface> GetDelegateProxy()
    {
        return nullptr;
    }
    virtual void DestroyPointerWindow() {}
    virtual void DrawScreenCenterPointer(const PointerStyle &pointerStyle) {}
    virtual void SubscribeScreenModeChange() {}
    virtual void RegisterDisplayStatusReceiver() {}
    virtual int32_t UpdateMouseLayer(const PointerStyle& pointerStyle,
        int32_t physicalX, int32_t physicalY)
    {
        return 0;
    }
    virtual int32_t DrawNewDpiPointer()
    {
        return 0;
    }
    virtual void AttachAllSurfaceNode() {}
    virtual void DetachAllSurfaceNode() {}
    virtual int32_t CheckHwcReady()
    {
        return 0;
    }
    virtual bool GetHardCursorEnabled()
    {
        return false;
    }
#ifndef OHOS_BUILD_ENABLE_WATCH
    virtual void NotifyPointerEventToRS(int32_t pointAction, int32_t pointCnt) {}
#endif // OHOS_BUILD_ENABLE_WATCH
};
} // namespace MMI
} // namespace OHOS
#endif // I_POINTER_DRAWING_MANAGER_H
