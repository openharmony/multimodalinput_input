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

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "transaction/rs_transaction.h"
#include "transaction/rs_interfaces.h"
#include "product_type_parser.h"
#include "product_name_definition.h"

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
constexpr uint32_t RENDER_STRIDE{4};
constexpr uint32_t POINTER_SIZE_DEFAULT { 1 };
constexpr uint32_t POINTER_SIZE_FOLD_PC { 2 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };


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

ScreenPointer::ScreenPointer(hwcmgr_ptr_t hwcMgr, handler_ptr_t handler, const OLD::DisplayInfo &di)
    : hwcMgr_(hwcMgr), handler_(handler)
{
    screenId_ = di.rsId;
    width_ = di.width;
    height_ = di.height;
    rotation_ = static_cast<rotation_t>(di.direction);
    if (rotation_ == rotation_t::ROTATION_90 ||
        rotation_ == rotation_t::ROTATION_270) {
        std::swap(width_, height_);
    }
    dpi_ = float(di.dpi) / BASELINE_DENSITY;
    MMI_HILOGI("Construct with DisplayInfo, id=%{public}" PRIu64 ", shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

ScreenPointer::ScreenPointer(hwcmgr_ptr_t hwcMgr, handler_ptr_t handler, screen_info_ptr_t si)
    : hwcMgr_(hwcMgr), handler_(handler)
{
    screenId_ = si->GetRsId();
    width_ = GetScreenInfoWidth(si);
    height_ = GetScreenInfoHeight(si);
    mode_ = si->GetSourceMode();
    rotation_ = si->GetRotation();
    dpi_ = si->GetVirtualPixelRatio();
    MMI_HILOGI("Construct with ScreenInfo, id=%{public}" PRIu64 ", shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

bool ScreenPointer::Init(PointerRenderer &render)
{
    if (!InitSurface()) {
        MMI_HILOGE("ScreenPointer InitSurface failed");
        return false;
    }

    RenderConfig defaultCursorCfg {
        .style_ = MOUSE_ICON::DEFAULT,
        .align_ = ICON_TYPE::ANGLE_NW,
        .path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg",
        .color = 0,
        .size = POINTER_SIZE_DEFAULT,
        .direction = Direction::DIRECTION0,
        .dpi = this->GetDPI() * this->GetScale(),
        .isHard = true,
    };
    if (OHOS::system::GetParameter("const.build.product", "HYM") == DEVICE_TYPE_FOLD_PC) {
        defaultCursorCfg.size = POINTER_SIZE_FOLD_PC;
    }
    defaultCursorCfg_ = defaultCursorCfg;

    // Init buffers
    OHOS::BufferRequestConfig bufferCfg = {
        .width = DEFAULT_CURSOR_SIZE,
        .height = DEFAULT_CURSOR_SIZE,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_HW_COMPOSER
            | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = BUFFER_TIMEOUT,
    };
    if (!InitDefaultBuffer(bufferCfg, render)) {
        MMI_HILOGE("ScreenPointer InitDefaultBuffer failed");
        return false;
    }
    if (!InitTransparentBuffer(bufferCfg)) {
        MMI_HILOGE("ScreenPointer InitTransparentBuffer failed");
        return false;
    }
    if (!InitCommonBuffer(bufferCfg)) {
        MMI_HILOGE("ScreenPointer InitCommonBuffer failed");
        return false;
    }
    currentBuffer_ = GetCommonBuffer();
    return true;
}

bool ScreenPointer::InitDefaultBuffer(const OHOS::BufferRequestConfig &bufferCfg, PointerRenderer &render)
{
    buffer_ptr_t buffer = CreateSurfaceBuffer(bufferCfg);
    CHKPF(buffer);
    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    CHKPF(addr);
    int32_t ret = render.Render(addr, buffer->GetWidth(), buffer->GetHeight(), defaultCursorCfg_);
    if (ret != RET_OK) {
        MMI_HILOGE("Render failed, ret:%{public}d.", ret);
        defaultBuffer_ = nullptr;
        return false;
    }
    defaultBuffer_ = buffer;
    return true;
}

bool ScreenPointer::InitTransparentBuffer(const OHOS::BufferRequestConfig &bufferCfg)
{
    buffer_ptr_t buffer = CreateSurfaceBuffer(bufferCfg);
    CHKPF(buffer);
    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    CHKPF(addr);

    uint32_t addrSize = static_cast<uint32_t>(buffer->GetWidth() * buffer->GetHeight()) * RENDER_STRIDE;
    (void)memset_s(addr, addrSize, 0, addrSize);
    transparentBuffer_ = buffer;
    return true;
}

bool ScreenPointer::InitCommonBuffer(const OHOS::BufferRequestConfig &bufferCfg)
{
    for (int32_t i = 0; (i < DEFAULT_BUFFER_SIZE) && (commonBuffers_.size() < DEFAULT_BUFFER_SIZE); i++) {
        buffer_ptr_t buffer = CreateSurfaceBuffer(bufferCfg);
        CHKPF(buffer);
        commonBuffers_.push_back(buffer);
    }
    return true;
}

buffer_ptr_t ScreenPointer::GetDefaultBuffer()
{
    currentBuffer_ = defaultBuffer_;
    return defaultBuffer_;
}

buffer_ptr_t ScreenPointer::GetTransparentBuffer()
{
    currentBuffer_ = transparentBuffer_;
    return transparentBuffer_;
}

buffer_ptr_t ScreenPointer::GetCommonBuffer()
{
    uint32_t bufferSize = static_cast<uint32_t>(commonBuffers_.size());
    if (bufferSize != DEFAULT_BUFFER_SIZE) {
        MMI_HILOGE("The buffer size is incorrect, size:%{public}u", bufferSize);
        return nullptr;
    }

    bufferId_++;
    bufferId_ %= bufferSize;
    currentBuffer_ = commonBuffers_[bufferId_];
    return commonBuffers_[bufferId_];
}

buffer_ptr_t ScreenPointer::RequestBuffer(const RenderConfig &cfg, bool &isCommonBuffer)
{
    if (cfg.style_ == MOUSE_ICON::TRANSPARENT_ICON) {
        MMI_HILOGD("The buffer transparent buffer.");
        isCommonBuffer = false;
        return GetTransparentBuffer();
    } else if (IsDefaultCfg(cfg)) {
        MMI_HILOGD("The buffer default buffer.");
        isCommonBuffer = false;
        return GetDefaultBuffer();
    }
    isCommonBuffer = true;
    return GetCommonBuffer();
}

bool ScreenPointer::IsDefaultCfg(const RenderConfig &cfg)
{
    return (cfg == defaultCursorCfg_) && (cfg.direction == defaultCursorCfg_.direction)
        && (cfg.align_ == defaultCursorCfg_.align_) && (cfg.isHard == defaultCursorCfg_.isHard);
}

buffer_ptr_t ScreenPointer::GetCurrentBuffer()
{
    return currentBuffer_;
}

buffer_ptr_t ScreenPointer::CreateSurfaceBuffer(const OHOS::BufferRequestConfig &bufferCfg)
{
    buffer_ptr_t buffer = OHOS::SurfaceBuffer::Create();
    if (buffer == nullptr) {
        MMI_HILOGE("SurfaceBuffer Create failed");
        return nullptr;
    }
    OHOS::GSError ret = buffer->Alloc(bufferCfg);
    if (ret != OHOS::GSERROR_OK) {
        MMI_HILOGE("SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return nullptr;
    }
    return buffer;
}

bool ScreenPointer::InitSurface()
{
    // create SurfaceNode
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = RS_SURFACE_NODE_NAME;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, Rosen::RSSurfaceNodeType::CURSOR_NODE);
    CHKPF(surfaceNode_);
    MMI_HILOGI("SurfaceNode::Create success");

    // set soft cursor buffer size
    auto surface = surfaceNode_->GetSurface();
    CHKPF(surface);
    surface->SetQueueSize(DEFAULT_BUFFER_SIZE);

    surfaceNode_->SetVisible(true);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::TOP_LEFT);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->AttachToDisplay(screenId_);
    surfaceNode_->SetBounds(0, 0, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
    MMI_HILOGI("AttachToDisplay %{public}" PRIu64 " completed", screenId_);

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
    CHKPV(si);
    auto id = si->GetRsId();
    if (screenId_ != id) {
        CHKPV(surfaceNode_);
        surfaceNode_->AttachToDisplay(id);
        Rosen::RSTransaction::FlushImplicitTransaction();
    }

    screenId_ = si->GetRsId();
    width_ = GetScreenInfoWidth(si);
    height_ = GetScreenInfoHeight(si);
    mode_ = si->GetSourceMode();
    rotation_ = si->GetRotation();
    dpi_ = si->GetVirtualPixelRatio();
    surfaceNode_->AttachToDisplay(screenId_);
    Rosen::RSTransaction::FlushImplicitTransaction();
    MMI_HILOGI("Update with ScreenInfo, id=%{public}" PRIu64 ", shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
}

void ScreenPointer::OnDisplayInfo(const OLD::DisplayInfo &di, bool isWindowRotation)
{
    if (screenId_ != di.rsId) {
        return;
    }

    isCurrentOffScreenRendering_ = di.isCurrentOffScreenRendering;
    dpi_ = float(di.dpi) / BASELINE_DENSITY;
    if (!IsMirror()) {
        rotation_ = static_cast<rotation_t>(di.direction);
    }
    displayDirection_ = di.displayDirection;
    isWindowRotation_ = isWindowRotation;
    MMI_HILOGD("Update with DisplayInfo, id=%{public}" PRIu64 ", shape=(%{public}u, %{public}u), mode=%{public}u, "
        "rotation=%{public}u, dpi=%{public}f", screenId_, width_, height_, mode_, rotation_, dpi_);
    if (isCurrentOffScreenRendering_) {
        screenRealDPI_ = di.screenRealDPI;
        if (di.width == 0) {
            MMI_HILOGE("The divisor cannot be 0");
            return;
        }
        offRenderScale_ = float(di.screenRealWidth) / di.width;
        MMI_HILOGD("Update with DisplayInfo, screenRealDPI=%{public}d, offRenderScale_=(%{public}f ",
            screenRealDPI_, offRenderScale_);
    }
}

bool ScreenPointer::UpdatePadding(uint32_t mainWidth, uint32_t mainHeight)
{
    if (!IsMirror()) {
        MMI_HILOGI("UpdatePadidng, reset padding, screenId=%{public}" PRIu64 ", scale=%{public}f, "
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
    if (rotation_ == rotation_t::ROTATION_90 || rotation_ == rotation_t::ROTATION_270) {
        std::swap(mainWidth, mainHeight);
    }

    // caculate padding for mirror screens
    scale_ = fmin(float(width_) / mainWidth, float(height_) / mainHeight);
    paddingTop_ = (height_ - mainHeight * scale_) / NUM_TWO;
    paddingLeft_ = (width_ - mainWidth * scale_) / NUM_TWO;
    MMI_HILOGI("UpdatePadding, screenId=%{public}" PRIu64 ", scale=%{public}f, paddingTop_=%{public}u,"
               " paddingLeft_=%{public}u", screenId_, scale_, paddingTop_, paddingLeft_);
    return true;
}

void ScreenPointer::Rotate(rotation_t rotation, int32_t& x, int32_t& y)
{
    // 坐标轴绕原点旋转 再平移
    int32_t tmpX = x;
    int32_t tmpY = y;
    int32_t width = static_cast<int32_t>(width_);
    int32_t height = static_cast<int32_t>(height_);
    if (IsMirror()) {
        height -= paddingTop_ * NUM_TWO;
        width -= paddingLeft_ * NUM_TWO;
    }
    // 主屏旋转 坐标系会一起旋转，但镜像屏此时坐标系不旋转
    if (IsMirror() && (rotation_ == rotation_t::ROTATION_90 || rotation_ == rotation_t::ROTATION_270)) {
        std::swap(width, height);
    }
    if ((IsMain() || IsMirror()) && isWindowRotation_ &&
        (displayDirection_ == DIRECTION90 || displayDirection_ == DIRECTION270)) {
        std::swap(width, height);
    }

    if (rotation == rotation_t(DIRECTION90)) {
        x = height - tmpY;
        y = tmpX;
    } else if (rotation == rotation_t(DIRECTION180)) {
        x = width - tmpX;
        y = height - tmpY;
    } else if (rotation == rotation_t(DIRECTION270)) {
        x = tmpY;
        y = width - tmpX;
    }
}

void ScreenPointer::CalculateHwcPositionForMirror(int32_t& x, int32_t& y)
{
    x = x * scale_;
    y = y * scale_;
    Direction direction = DIRECTION0;
    if (isWindowRotation_) {
        direction = static_cast<Direction>((((static_cast<Direction>(rotation_) - displayDirection_) *
            ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    } else {
        direction = static_cast<Direction>(rotation_);
    }
    Rotate(rotation_t(direction), x, y);

    x += paddingLeft_;
    y += paddingTop_;
}

void ScreenPointer::CalculateHwcPositionForExtend(int32_t& x, int32_t& y)
{
    x = x * offRenderScale_;
    y = y * offRenderScale_;
}

bool ScreenPointer::Move(int32_t x, int32_t y, ICON_TYPE align)
{
    if (isVirtualExtend_) {
        MMI_HILOGD("Virtual extend screen move, screenId=%{public}" PRIu64, screenId_);
        return true;
    }
    CHKPF(hwcMgr_);
    int32_t px = 0;
    int32_t py = 0;
    if (IsMirror()) {
        CalculateHwcPositionForMirror(x, y);
    } else if (GetIsCurrentOffScreenRendering() && !IsMirror()) {
        CalculateHwcPositionForExtend(x, y);
    }
    if (IsMain() && isWindowRotation_) {
        Direction direction = static_cast<Direction>((((DIRECTION0 - displayDirection_) *
            ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
        Rotate(rotation_t(direction), x, y);
    }
    if (IsPositionOutScreen(x, y)) {
        MMI_HILOGE("Position out of screen");
    }
    px = x - FOCUS_POINT;
    py = y - FOCUS_POINT;

    auto buffer = GetCurrentBuffer();
    CHKPF(buffer);
    auto bh = buffer->GetBufferHandle();
    CHKPF(bh);
    BytraceAdapter::StartHardPointerMove(buffer->GetWidth(), buffer->GetHeight(), bufferId_, screenId_);
    auto ret = hwcMgr_->SetPosition(screenId_, px, py, bh);
    BytraceAdapter::StopHardPointerMove();
    if (ret != RET_OK) {
        MMI_HILOGE("SetPosition failed, screenId=%{public}" PRIu64 ", pos=(%{private}d, %{private}d)",
            screenId_, px, py);
        return false;
    }
    return true;
}

bool ScreenPointer::MoveSoft(int32_t x, int32_t y, ICON_TYPE align)
{
    CHKPF(surfaceNode_);
    int32_t px = 0;
    int32_t py = 0;
    if (IsMirror()) {
        CalculateHwcPositionForMirror(x, y);
    } else if (!IsExtend() && !isWindowRotation_) {
        Rotate(rotation_, x, y);
    }
    px = x - FOCUS_POINT;
    py = y - FOCUS_POINT;

    if (!IsMirror()) {
        int64_t nodeId = surfaceNode_->GetId();
        Rosen::RSInterfaces::GetInstance().SetHwcNodeBounds(nodeId, px, py, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
    } else {
        surfaceNode_->SetBounds(px, py, DEFAULT_CURSOR_SIZE, DEFAULT_CURSOR_SIZE);
    }

    return true;
}

bool ScreenPointer::SetInvisible()
{
    if (isVirtualExtend_) {
        MMI_HILOGD("Virtual extend screen set invisible, screenId=%{public}" PRIu64, screenId_);
        return true;
    }
    CHKPF(hwcMgr_);

    auto buffer = GetTransparentBuffer();
    CHKPF(buffer);
    int32_t width = buffer->GetWidth();
    int32_t height = buffer->GetHeight();
    if ((width < 0) || (height < 0)) {
        MMI_HILOGI("The input data is incorrect, width:%{public}d, height:%{public}d.", width, height);
        return false;
    }
    auto sret = buffer->FlushCache();
    if (sret != RET_OK) {
        MMI_HILOGE("FlushCache ret: %{public}d", sret);
        return sret;
    }

    auto bh = buffer->GetBufferHandle();
    CHKPF(bh);
    auto ret = hwcMgr_->SetPosition(screenId_, 0, 0, bh);
    if (ret != RET_OK) {
        MMI_HILOGE("SetLocation failed, screenId=%{public}" PRIu64 ", loc=(%{private}d, %{private}d)", screenId_, 0, 0);
        return false;
    }
    MMI_HILOGI("SetInvisible success, screenId=%{public}" PRIu64, screenId_);
    return true;
}

float ScreenPointer::GetRenderDPI() const
{
    if (GetIsCurrentOffScreenRendering() && !IsMirror()) {
        return float(GetScreenRealDPI()) / BASELINE_DENSITY;
    } else {
        return dpi_ * scale_;
    }
}

bool ScreenPointer::IsPositionOutScreen(int32_t x, int32_t y)
{
    int32_t width = static_cast<int32_t>(width_);
    int32_t height = static_cast<int32_t>(height_);
    if (x < 0 || y < 0 || x > width || y > height) {
        MMI_HILOGE("Position out of screen, x=%{private}d, y=%{private}d, width=%{public}d, height=%{public}d",
            x, y, width, height);
        return true;
    }
    return false;
}

} // namespace OHOS::MMI