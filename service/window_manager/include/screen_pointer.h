/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef SCREEN_POINTER_H
#define SCREEN_POINTER_H

#include <memory>
#include <vector>

#include "event_handler.h"
#include "nocopyable.h"
#include "screen_info.h"
#include "struct_multimodal.h"
#include "hardware_cursor_pointer_manager.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_surface_node.h"
#include "window_info.h"

namespace OHOS::MMI {
using hwcmgr_ptr_t = std::shared_ptr<HardwareCursorPointerManager>;
using handler_ptr_t = std::shared_ptr<OHOS::AppExecFwk::EventHandler>;
using buffer_ptr_t = sptr<OHOS::SurfaceBuffer>;
using screen_info_ptr_t = sptr<OHOS::Rosen::ScreenInfo>;
using mode_t = OHOS::Rosen::ScreenSourceMode;
using rotation_t = OHOS::Rosen::Rotation;

uint32_t GetScreenInfoWidth(const screen_info_ptr_t);
uint32_t GetScreenInfoHeight(const screen_info_ptr_t);

class ScreenPointer final {
public:
    DISALLOW_COPY_AND_MOVE(ScreenPointer);
    ScreenPointer(hwcmgr_ptr_t hwcmgr, handler_ptr_t handler, const DisplayInfo &di);
    ScreenPointer(hwcmgr_ptr_t hwcmgr, handler_ptr_t handler, screen_info_ptr_t si);
    ~ScreenPointer() = default;

    bool Init();
    bool InitSurface();
    void UpdateScreenInfo(screen_info_ptr_t si);
    bool UpdatePadding(uint32_t mainWidth, uint32_t mainHeight);
    void OnDisplayInfo(const DisplayInfo &di);

    buffer_ptr_t RequestBuffer();
    buffer_ptr_t GetCurrentBuffer();

    bool Move(int32_t x, int32_t y, ICON_TYPE align);
    bool MoveSoft(int32_t x, int32_t y, ICON_TYPE align);
    bool SetInvisible();

    uint32_t GetScreenId() const
    {
        return screenId_;
    }
    
    uint32_t GetScreenWidth() const
    {
        return width_;
    }

    uint32_t GetScreenHeight() const
    {
        return height_;
    }

    std::shared_ptr<OHOS::Rosen::RSSurfaceNode> GetSurfaceNode()
    {
        return surfaceNode_;
    }

    float GetDPI() const
    {
        return dpi_;
    }

    float GetScale() const
    {
        return scale_;
    }

    bool IsMain() const
    {
        return mode_ == mode_t::SCREEN_MAIN;
    }

    bool IsMirror() const
    {
        return mode_ == mode_t::SCREEN_MIRROR;
    }

    int32_t GetPointerSize() const;

private:
    bool InitSurfaceNode();
    bool FlushSerfaceBuffer();

    uint32_t GetImageSize() const;
    uint32_t GetOffsetX(ICON_TYPE align) const;
    uint32_t GetOffsetY(ICON_TYPE align) const;

private:
    std::mutex mtx_;

    uint32_t screenId_{0};
    uint32_t width_{0};
    uint32_t height_{0};
    mode_t mode_{mode_t::SCREEN_MAIN};
    rotation_t rotation_{rotation_t::ROTATION_0};
    float dpi_{1.0f};

    // screen scale and padding info
    float scale_{1.0f};
    int32_t paddingTop_{0};
    int32_t paddingLeft_{0};

    hwcmgr_ptr_t hwcMgr_{nullptr};
    handler_ptr_t handler_{nullptr};

    // RS Layer
    std::shared_ptr<OHOS::Rosen::RSSurfaceNode> surfaceNode_{nullptr};
    std::shared_ptr<OHOS::Rosen::RSCanvasNode> canvasNode_{nullptr};

    std::vector<buffer_ptr_t> buffers_;
    uint32_t bufferId_ {0};
};

} // namespace OHOS::MMI

#endif // SCREEN_POINTER_H