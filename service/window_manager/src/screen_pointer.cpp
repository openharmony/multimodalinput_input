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
#include "screen_pointer.h"

#include "i_preference_manager.h"
#include "define_multimodal.h"
#include "transaction/rs_transaction.h"
#include "bytrace_adapter.h"
#include "dm_common.h"
#include "transaction/rs_interfaces.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ScreenPointer"

namespace OHOS::MMI {
const char* RS_SURFACE_NODE_NAME{"pointer window"};
const char* POINTER_SIZE{"pointerSize"};
constexpr int32_t RS_NODE_CANVAS_INDEX{-1};
constexpr int32_t DEFAULT_POINTER_SIZE{1};
constexpr int32_t DEVICE_INDEPENDENT_PIXELS{40};
constexpr int32_t BASELINE_DENSITY{160};
constexpr int32_t POINTER_WINDOW_INIT_SIZE{64};
constexpr int32_t BUFFER_RELEASE_WAIT_MS{1000};
constexpr int32_t NUM_TWO{2};
constexpr int32_t DEFAULT_BUFFER_SIZE{10};
constexpr int32_t DEFAULT_CURSOR_SIZE{512};
constexpr uint32_t FOCUS_POINT = DEFAULT_CURSOR_SIZE / NUM_TWO;
constexpr int32_t BUFFER_TIMEOUT{150};
constexpr int32_t STRIDE_ALIGNMENT{8};
constexpr float CALCULATE_MOUSE_ICON_BIAS{5.0f};
constexpr float INCREASE_RATIO{1.22f};
constexpr uint32_t RENDER_STRIDE{4};

uint32_t GetScreenInfoWidth(screen_info_ptr_t si)
{
    uint32_t width = 0;
    auto modeId = si->GetModeId();
    auto modes = si->GetModes();
    if (modeId < 0 || modeId >= modes.size()) {
        return 0;
    }
    return modes[modeId]->width_;
}
uint32_t GetScreenInfoHeight(screen_info_ptr_t si)
{
    uint32_t height = 0;
    auto modeId = si->GetModeId();
    auto modes = si->GetModes();
    if (modeId < 0 || modeId >= modes.size()) {
        return 0;
    }
    return modes[modeId]->height_;
}

ScreenPointer::ScreenPointer(hwcmgr_ptr_t hwcMgr, handler_ptr_t handler, const DisplayInfo &di)
    : hwcMgr_(hwcMgr), handler_(handler)
{
    screenId_ = di.id;
    width_ = di.width;
    height_ = di.height;
    dpi_ = float(di.dpi) / BASELINE_DENSITY;
    MMI_HILOGI("Construct with DisplayInfo, id=%{public}u, shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

ScreenPointer::ScreenPointer(hwcmgr_ptr_t hwcMgr, handler_ptr_t handler, screen_info_ptr_t si)
    : hwcMgr_(hwcMgr), handler_(handler)
{
    screenId_ = si->GetScreenId();
    width_ = GetScreenInfoWidth(si);
    height_ = GetScreenInfoHeight(si);
    mode_ = si->GetSourceMode();
    rotation_ = si->GetRotation();
    dpi_ = si->GetVirtualPixelRatio();
    MMI_HILOGI("Construct with ScreenInfo, id=%{public}u, shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

bool ScreenPointer::Init()
{
    if (!InitSurface()) {
        MMI_HILOGE("ScreenPointer InitSurface failed");
        return false;
    }

    // Init buffers
    OHOS::BufferRequestConfig bufferCfg = {
        .width = DEFAULT_CURSOR_SIZE,
        .height = DEFAULT_CURSOR_SIZE,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_HW_COMPOSER,
        .timeout = BUFFER_TIMEOUT,
    };
    for (int32_t i = 0; i < DEFAULT_BUFFER_SIZE && buffers_.size() < DEFAULT_BUFFER_SIZE; i++) {
        sptr<OHOS::SurfaceBuffer> buffer = OHOS::SurfaceBuffer::Create();
        if (buffer == nullptr) {
            MMI_HILOGE("SurfaceBuffer Create failed");
            return false;
        }
        OHOS::GSError ret = buffer->Alloc(bufferCfg);
        if (ret != OHOS::GSERROR_OK) {
            MMI_HILOGE("SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
            return false;
        }
        buffers_.push_back(buffer);
    }
    return true;
}

bool ScreenPointer::InitSurface()
{
    // create SurfaceNode
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = RS_SURFACE_NODE_NAME;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    CHKPF(surfaceNode_);
    MMI_HILOGE("SurfaceNode::Create success");

    // set soft cursor buffer size
    auto surface = surfaceNode_->GetSurface();
    surface->SetQueueSize(DEFAULT_BUFFER_SIZE);

    surfaceNode_->SetVisible(true);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::TOP_LEFT);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->AttachToDisplay(screenId_);
    MMI_HILOGI("AttachToDisplay %{public}d completed", screenId_);

    // create canvas node
    canvasNode_ = Rosen::RSCanvasNode::Create();
    CHKPF(canvasNode_);
    canvasNode_->SetBounds(0, 0, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
    canvasNode_->SetFrame(0, 0, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING

    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(float(rotation_));
    surfaceNode_->AddChild(canvasNode_, RS_NODE_CANVAS_INDEX);

    MMI_HILOGI("InitSurface completed");
    return true;
}

void ScreenPointer::UpdateScreenInfo(const sptr<OHOS::Rosen::ScreenInfo> si)
{
    auto id = si->GetScreenId();
    if (screenId_ != id) {
        surfaceNode_->AttachToDisplay(id);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }

    screenId_ = si->GetScreenId();
    width_ = GetScreenInfoWidth(si);
    height_ = GetScreenInfoHeight(si);
    mode_ = si->GetSourceMode();
    rotation_ = si->GetRotation();
    dpi_ = si->GetVirtualPixelRatio();
    MMI_HILOGI("Update with ScreenInfo, id=%{public}u, shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

void ScreenPointer::OnDisplayInfo(const DisplayInfo &di)
{
    if (screenId_ != uint32_t(di.id)) {
        return;
    }

    isCurrentOffScreenRendering_ = di.isCurrentOffScreenRendering;
    dpi_ = float(di.dpi) / BASELINE_DENSITY;
    rotation_ = static_cast<rotation_t>(di.direction);
    MMI_HILOGD("Update with DisplayInfo, id=%{public}u, shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
    if (isCurrentOffScreenRendering_) {
        screenRealDPI_ = di.screenRealDPI;
        offRenderScale_ = float(di.screenRealWidth) / di.width;
        MMI_HILOGI("Update with DisplayInfo, screenRealDPI=%{public}u, offRenderScale_=(%{public}f ",
            screenRealDPI_, offRenderScale_);
    }
}

bool ScreenPointer::UpdatePadding(uint32_t mainWidth, uint32_t mainHeight)
{
    if (!IsMirror()) {
        MMI_HILOGI("UpdatePadidng, reset padding, screenId=%{public}u, scale=%{public}f, "
            "paddingTop_=%{public}u, paddingLeft_=%{public}u", screenId_, scale_, paddingTop_, paddingLeft_);
        scale_ = 1.0;
        paddingTop_ = 0;
        paddingLeft_ = 0;
        return false;
    }
    if (mainWidth == 0 || mainHeight == 0) {
        MMI_HILOGE("Invalid parameters, mainWidth=%{public}u, mainHeight=%{public}u", mainWidth, mainHeight);
        return false;
    }

    // caculate padding for mirror screens
    scale_ = fmin(float(width_) / mainWidth, float(height_) / mainHeight);
    paddingTop_ = (height_ - mainHeight * scale_) / NUM_TWO;
    paddingLeft_ = (width_ - mainWidth * scale_) / NUM_TWO;
    MMI_HILOGI("UpdatePadding, screenId=%{public}u, scale=%{public}f, paddingTop_=%{public}u, paddingLeft_=%{public}u",
        screenId_, scale_, paddingTop_, paddingLeft_);
    return true;
}

sptr<OHOS::SurfaceBuffer> ScreenPointer::RequestBuffer()
{
    if (!buffers_.size()) {
        return nullptr;
    }

    bufferId_++;
    bufferId_ %= buffers_.size();
    
    return buffers_[bufferId_];
}

sptr<OHOS::SurfaceBuffer> ScreenPointer::GetCurrentBuffer()
{
    if (bufferId_ >= buffers_.size()) {
        return nullptr;
    }
    return buffers_[bufferId_];
}

bool ScreenPointer::Move(int32_t x, int32_t y, ICON_TYPE align)
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPF(hwcMgr_);

    uint32_t dx = hardRenderCfg_.GetOffsetX();
    uint32_t dy = hardRenderCfg_.GetOffsetY();
    switch (rotation_) {
        case rotation_t::ROTATION_0:
            break;
        case rotation_t::ROTATION_90:
            dy = hardRenderCfg_.GetOffsetYRotated();
            break;
        case rotation_t::ROTATION_180:
            dx = hardRenderCfg_.GetOffsetXRotated();
            dy = hardRenderCfg_.GetOffsetYRotated();
            break;
        case rotation_t::ROTATION_270:
            dx = hardRenderCfg_.GetOffsetXRotated();
            break;
    }
    int32_t px = x - dx;
    int32_t py = y - dy;
    if (IsMirror()) {
        px = paddingLeft_ + x * scale_ - dx;
        py = paddingTop_ + y * scale_ - dy;
    } else if (GetIsCurrentOffScreenRendering() && IsExtend()) {
        float renderDPI = GetRenderDPI();
        if (renderDPI == 0) {
            MMI_HILOGE("SetPosition failed, RenderDPI = %{public}f", renderDPI);
            return false;
        }
        int32_t adjustX = static_cast<int32_t>(float(FOCUS_POINT - dx) *
            (dpi_ * scale_) / renderDPI);
        int32_t adjustY = static_cast<int32_t>(float(FOCUS_POINT - dy) *
            (dpi_ * scale_) / renderDPI);
        px = x * offRenderScale_ + adjustX * offRenderScale_ - FOCUS_POINT;
        py = y * offRenderScale_ + adjustY * offRenderScale_ - FOCUS_POINT;
    }

    auto buffer = GetCurrentBuffer();
    CHKPF(buffer);
    auto bh = buffer->GetBufferHandle();
    CHKPF(bh);
    auto ret = hwcMgr_->SetPosition(screenId_, px, py, bh);
    if (ret != RET_OK) {
        MMI_HILOGE("SetPosition failed, screenId=%{public}u, pos=(%{public}d, %{public}d)", screenId_, px, py);
        return false;
    }
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    return true;
}

bool ScreenPointer::MoveSoft(int32_t x, int32_t y, ICON_TYPE align)
{
    CHKPF(surfaceNode_);
    uint32_t dx = softRenderCfg_.GetOffsetX();
    uint32_t dy = softRenderCfg_.GetOffsetY();
    switch (rotation_) {
        case rotation_t::ROTATION_0:
            break;
        case rotation_t::ROTATION_90:
            dy = softRenderCfg_.GetOffsetYRotated();
            break;
        case rotation_t::ROTATION_180:
            dx = softRenderCfg_.GetOffsetXRotated();
            dy = softRenderCfg_.GetOffsetYRotated();
            break;
        case rotation_t::ROTATION_270:
            dx = softRenderCfg_.GetOffsetXRotated();
            break;
    }
    int32_t px = x - dx;
    int32_t py = y - dy;
    if (IsMirror()) {
        px = paddingLeft_ + x * scale_ - dx;
        py = paddingTop_ + y * scale_ - dy;
    }
    int32_t tmpX = px;
    int32_t tmpY = py;
    if (rotation_ == rotation_t(DIRECTION90)) {
        px = tmpY;
        py = width_ - tmpX;
        px = height_  - px - DEFAULT_CURSOR_SIZE;
        py = width_ - py + DEFAULT_CURSOR_SIZE;
    } else if (rotation_ == rotation_t(DIRECTION180)) {
        px = width_ - px;
        py = height_ - py;
    } else if (rotation_ == rotation_t(DIRECTION270)) {
        px = height_ - tmpY;
        py = tmpX;
        px = height_ - px + DEFAULT_CURSOR_SIZE;
        py = width_ - py - DEFAULT_CURSOR_SIZE;
    }

    if (!IsMirror()) {
        int64_t nodeId = surfaceNode_->GetId();
        Rosen::RSInterfaces::GetInstance().SetHwcNodeBounds(nodeId, px, py, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
    } else {
        surfaceNode_->SetBounds(px, py, DEFAULT_BUFFER_SIZE, DEFAULT_BUFFER_SIZE);
    }
    
    return true;
}

bool ScreenPointer::SetInvisible()
{
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CHKPF(hwcMgr_);
    
    auto buffer = RequestBuffer();
    CHKPF(buffer);
    auto addr = static_cast<uint8_t*>(buffer->GetVirAddr());
    CHKPF(addr);
    uint32_t addrSize = buffer->GetWidth() * buffer->GetHeight() * RENDER_STRIDE;
    memset_s(addr, addrSize, 0, addrSize);

    auto bh = buffer->GetBufferHandle();
    CHKPF(bh);
    auto ret = hwcMgr_->SetPosition(screenId_, 0, 0, bh);
    if (ret != RET_OK) {
        MMI_HILOGE("SetLocation failed, screenId=%{public}u, loc=(%{public}d, %{public}d)", screenId_, 0, 0);
        return false;
    }
    MMI_HILOGI("SetInvisible success, screenId=%{public}u", screenId_);
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    return true;
}

float ScreenPointer::GetRenderDPI() const
{
    if (GetIsCurrentOffScreenRendering() && IsExtend()) {
        return float(GetScreenRealDPI()) / BASELINE_DENSITY;
    } else {
        return dpi_ * scale_;
    }
}

} // namespace OHOS::MMI