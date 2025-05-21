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

#include "screen_info.h"

#include "hardware_cursor_pointer_manager.h"
#include "pointer_renderer.h"
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

    bool Init(PointerRenderer &render);
    bool InitSurface();
    void UpdateScreenInfo(screen_info_ptr_t si);
    bool UpdatePadding(uint32_t mainWidth, uint32_t mainHeight);
    void OnDisplayInfo(const DisplayInfo &di);

    buffer_ptr_t GetDefaultBuffer();
    buffer_ptr_t GetTransparentBuffer();
    buffer_ptr_t GetCommonBuffer();
    buffer_ptr_t RequestBuffer(const RenderConfig &cfg, bool &isCommonBuffer);
    buffer_ptr_t GetCurrentBuffer();

    bool Move(int32_t x, int32_t y, ICON_TYPE align);
    bool MoveSoft(int32_t x, int32_t y, ICON_TYPE align);
    void CalculatePositionForMirror(int32_t x, int32_t y, int32_t* px, int32_t* py);
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

    void SetDPI(float dpi)
    {
        dpi_ = dpi;
    }

    float GetDPI() const
    {
        return dpi_;
    }

    float GetScale() const
    {
        if (GetIsCurrentOffScreenRendering() && (IsExtend() || IsMain())) {
            return offRenderScale_;
        } else {
            return scale_;
        }
    }

    uint32_t GetMode() const
    {
        return static_cast<uint32_t>(mode_);
    }

    bool IsMain() const
    {
        return mode_ == mode_t::SCREEN_MAIN;
    }

    bool IsMirror() const
    {
        return mode_ == mode_t::SCREEN_MIRROR;
    }

    bool IsExtend() const
    {
        return mode_ == mode_t::SCREEN_EXTEND;
    }

    bool GetIsCurrentOffScreenRendering() const
    {
        return isCurrentOffScreenRendering_;
    }

    float GetOffRenderScale() const
    {
        return offRenderScale_;
    }

    int32_t GetScreenRealDPI() const
    {
        return screenRealDPI_;
    }

    float GetRenderDPI() const;

    void SetRotation(const rotation_t rotation)
    {
        rotation_ = rotation;
    }

    rotation_t GetRotation()
    {
        return rotation_;
    }

    bool IsPositionOutScreen(int32_t x, int32_t y);

    uint32_t GetBufferId()
    {
        return bufferId_;
    }

private:
    bool InitSurfaceNode();
    bool FlushSerfaceBuffer();
    void Rotate(rotation_t rotation, int32_t& x, int32_t& y);
    void CalculateHwcPositionForMirror(int32_t& x, int32_t& y);
    void CalculateHwcPositionForExtend(int32_t& x, int32_t& y);
    bool InitDefaultBuffer(const OHOS::BufferRequestConfig &bufferCfg, PointerRenderer &render);
    bool InitTransparentBuffer(const OHOS::BufferRequestConfig &bufferCfg);
    bool InitCommonBuffer(const OHOS::BufferRequestConfig &bufferCfg);
    buffer_ptr_t CreateSurfaceBuffer(const OHOS::BufferRequestConfig &bufferCfg);

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

    RenderConfig defaultCursorCfg_;
    buffer_ptr_t transparentBuffer_{nullptr};
    buffer_ptr_t defaultBuffer_{nullptr};
    buffer_ptr_t currentBuffer_{nullptr};
    std::vector<buffer_ptr_t> commonBuffers_;
    uint32_t bufferId_ {0};

    // isCurrentOffScreenRendering
    bool isCurrentOffScreenRendering_ = false;
    float offRenderScale_{1.0f};
    int32_t screenRealDPI_{1.0f};
};

} // namespace OHOS::MMI

#endif // SCREEN_POINTER_H