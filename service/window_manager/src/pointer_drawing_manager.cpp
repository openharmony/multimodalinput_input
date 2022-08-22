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

#include "pointer_drawing_manager.h"

#include <display_type.h>

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerDrawingManager" };
const std::string IMAGE_POINTER_DEFAULT_PATH = "/system/etc/multimodalinput/mouse_icon/";
constexpr int32_t realImageWidth = 40;
constexpr int32_t realImageHeight = 40;
} // namespace
} // namespace MMI
} // namespace OHOS

namespace OHOS {
namespace MMI {
PointerDrawingManager::PointerDrawingManager()
{
    InitStyle();
}

void PointerDrawingManager::DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
    const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Display:%{public}d,physicalX:%{public}d,physicalY:%{public}d,mouseStyle:%{public}d",
        displayId, physicalX, physicalY, mouseStyle);
    FixCursorPosition(physicalX, physicalY);
    lastPhysicalX_ = physicalX;
    lastPhysicalY_ = physicalY;
    
    AdjustMouseFocus(ICON_TYPE(mouseIcons_[mouseStyle].alignmentWay), physicalX, physicalY);
    if (pointerWindow_ != nullptr) {
        pointerWindow_->MoveTo(physicalX, physicalY);

        if (lastMouseStyle_ == mouseStyle) {
            MMI_HILOGD("The lastMouseStyle is equal with mouseStyle");
            return;
        }
        lastMouseStyle_ = mouseStyle;
        int32_t ret = InitLayer(mouseStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Init layer failed");
            return;
        }

        MMI_HILOGD("Leave, display:%{public}d,physicalX:%{public}d,physicalY:%{public}d",
            displayId, physicalX, physicalY);
        return;
    }
    
    CreatePointerWindow(displayId, physicalX, physicalY);
    CHKPV(pointerWindow_);
    int32_t ret = InitLayer(mouseStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Init layer failed");
        return;
    }

    MMI_HILOGD("Leave, display:%{public}d,physicalX:%{public}d,physicalY:%{public}d",
        displayId, physicalX, physicalY);
}

int32_t PointerDrawingManager::InitLayer(const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerWindow_, RET_ERR);
    sptr<OHOS::Surface> layer = GetLayer();
    if (layer == nullptr) {
        pointerWindow_->Destroy();
        pointerWindow_ = nullptr;
        MMI_HILOGE("Init layer is failed, get layer is nullptr");
        return RET_ERR;
    }

    sptr<OHOS::SurfaceBuffer> buffer = GetSurfaceBuffer(layer);
    if (buffer == nullptr || buffer->GetVirAddr() == nullptr) {
        pointerWindow_->Destroy();
        pointerWindow_ = nullptr;
        MMI_HILOGE("Init layer is failed, buffer or virAddr is nullptr");
        return RET_ERR;
    }

    auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
    DoDraw(addr, buffer->GetWidth(), buffer->GetHeight(), mouseStyle);
    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = buffer->GetWidth(),
            .h = buffer->GetHeight(),
        },
    };
    OHOS::SurfaceError ret = layer->FlushBuffer(buffer, -1, flushConfig);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Init layer is failed, FlushBuffer return ret:%{public}s", SurfaceErrorStr(ret).c_str());
        return RET_ERR;
    }
    MMI_HILOGD("Init layer is success");
    UpdatePointerVisible();
    return RET_OK;
}

void PointerDrawingManager::AdjustMouseFocus(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= realImageHeight;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= realImageWidth / 2;
            physicalY -= realImageHeight / 2;
            break;
        }
        case ANGLE_NW:
        default: {
            MMI_HILOGD("No need adjust mouse focus");
            break;
        }
    }
}

void PointerDrawingManager::FixCursorPosition(int32_t &physicalX, int32_t &physicalY)
{
    if (physicalX < 0) {
        physicalX = 0;
    }

    if (physicalY < 0) {
        physicalY = 0;
    }
    const int32_t cursorUnit = 16;
    if (direction_ == Direction0 || direction_ == Direction180) {
        if (physicalX > (displayWidth_ - IMAGE_WIDTH / cursorUnit)) {
            physicalX = displayWidth_ - IMAGE_WIDTH / cursorUnit;
        }
        if (physicalY > (displayHeight_ - IMAGE_HEIGHT / cursorUnit)) {
            physicalY = displayHeight_ - IMAGE_HEIGHT / cursorUnit;
        }
    } else {
        if (physicalX > (displayHeight_ - IMAGE_HEIGHT / cursorUnit)) {
            physicalX = displayHeight_ - IMAGE_HEIGHT / cursorUnit;
        }
        if (physicalY > (displayWidth_ - IMAGE_WIDTH / cursorUnit)) {
            physicalY = displayWidth_ - IMAGE_WIDTH / cursorUnit;
        }
    }
}

void PointerDrawingManager::CreatePointerWindow(int32_t displayId, int32_t physicalX, int32_t physicalY)
{
    sptr<OHOS::Rosen::WindowOption> option = new (std::nothrow) OHOS::Rosen::WindowOption();
    CHKPV(option);
    option->SetWindowType(OHOS::Rosen::WindowType::WINDOW_TYPE_POINTER);
    option->SetWindowMode(OHOS::Rosen::WindowMode::WINDOW_MODE_FLOATING);
    option->SetDisplayId(displayId);
    OHOS::Rosen::Rect rect = {
        .posX_ = physicalX,
        .posY_ = physicalY,
        .width_ = IMAGE_WIDTH,
        .height_ = IMAGE_HEIGHT,
    };
    option->SetWindowRect(rect);
    option->SetFocusable(false);
    option->SetTouchable(false);
    std::string windowName = "pointer window";
    pointerWindow_ = OHOS::Rosen::Window::Create(windowName, option, nullptr);
}

sptr<OHOS::Surface> PointerDrawingManager::GetLayer()
{
    std::shared_ptr<OHOS::Rosen::RSSurfaceNode> surfaceNode = pointerWindow_->GetSurfaceNode();
    if (surfaceNode == nullptr) {
        MMI_HILOGE("Draw pointer is failed, get node is nullptr");
        pointerWindow_->Destroy();
        pointerWindow_ = nullptr;
        return nullptr;
    }
    return surfaceNode->GetSurface();
}

sptr<OHOS::SurfaceBuffer> PointerDrawingManager::GetSurfaceBuffer(sptr<OHOS::Surface> layer) const
{
    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t releaseFence = 0;
    OHOS::BufferRequestConfig config = {
        .width = IMAGE_WIDTH,
        .height = IMAGE_HEIGHT,
        .strideAlignment = 0x8,
        .format = PIXEL_FMT_RGBA_8888,
        .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
    };

    OHOS::SurfaceError ret = layer->RequestBuffer(buffer, releaseFence, config);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        MMI_HILOGE("Request buffer ret:%{public}s", SurfaceErrorStr(ret).c_str());
        return nullptr;
    }
    return buffer;
}

void PointerDrawingManager::DoDraw(uint8_t *addr, uint32_t width, uint32_t height, const MOUSE_ICON mouseStyle)
{
    CALL_DEBUG_ENTER;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    bitmap.Build(width, height, format);
    OHOS::Rosen::Drawing::Canvas canvas;
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    DrawPixelmap(canvas, mouseIcons_[mouseStyle].iconPath);
    static constexpr uint32_t stride = 4;
    uint32_t addrSize = width * height * stride;
    errno_t ret = memcpy_s(addr, addrSize, bitmap.GetPixels(), addrSize);
    if (ret != EOK) {
        MMI_HILOGE("Memcpy data is error, ret:%{public}d", ret);
        return;
    }
}

void PointerDrawingManager::DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas, const std::string& iconPath)
{
    CALL_DEBUG_ENTER;
    std::unique_ptr<OHOS::Media::PixelMap> pixelmap = DecodeImageToPixelMap(iconPath);
    CHKPV(pixelmap);
    OHOS::Rosen::Drawing::Pen pen;
    pen.SetAntiAlias(true);
    pen.SetColor(OHOS::Rosen::Drawing::Color::COLOR_BLUE);
    OHOS::Rosen::Drawing::scalar penWidth = 1;
    pen.SetWidth(penWidth);
    canvas.AttachPen(pen);
    canvas.DrawBitmap(*pixelmap, 0, 0);
}

std::unique_ptr<OHOS::Media::PixelMap> PointerDrawingManager::DecodeImageToPixelMap(const std::string &imagePath)
{
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/png";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(imagePath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    if (pixelMap == nullptr) {
        MMI_HILOGE("The pixelMap is nullptr");
    }
    return pixelMap;
}

void PointerDrawingManager::OnDisplayInfo(int32_t displayId, WinInfo &info, int32_t width,
    int32_t height, Direction direction)
{
    CALL_DEBUG_ENTER;
    hasDisplay_ = true;
    displayId_ = displayId;
    displayWidth_ = width;
    displayHeight_ = height;
    direction_ = direction;
    windowId_ = info.windowId;
    pid_ = info.windowPid;
    DrawManager();
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice)
{
    CALL_DEBUG_ENTER;
    hasPointerDevice_ = hasPointerDevice;
    DrawManager();
}

void PointerDrawingManager::DrawManager()
{
    if (hasDisplay_ && hasPointerDevice_ && pointerWindow_ == nullptr) {
        MMI_HILOGD("Draw pointer begin");
        std::optional<int32_t> pointerStyleInfo = WinMgr->GetPointerStyle(pid_, windowId_);
        if (!pointerStyleInfo) {
            MMI_HILOGE("Get pointer style failed, pointerStyleInfo is nullptr");
            return;
        }
        int32_t mouseStyle = pointerStyleInfo.value();
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayId_, displayWidth_/2, displayHeight_/2, MOUSE_ICON(mouseStyle));
            MMI_HILOGD("Draw manager, mouseStyle:%{public}d, last physical is initial value", mouseStyle);
            return;
        }
       
        DrawPointer(displayId_, lastPhysicalX_, lastPhysicalY_, MOUSE_ICON(mouseStyle));
        MMI_HILOGD("Draw manager, mouseStyle:%{public}d", mouseStyle);
        return;
    }

    if (!hasPointerDevice_ && pointerWindow_ != nullptr) {
        MMI_HILOGD("Destroy draw pointer");
        pointerWindow_->Destroy();
        pointerWindow_ = nullptr;
    }
}

bool PointerDrawingManager::Init()
{
    CALL_DEBUG_ENTER;
    InputDevMgr->Attach(shared_from_this());
    pidInfos_.clear();
    return true;
}

std::shared_ptr<IPointerDrawingManager> IPointerDrawingManager::GetInstance()
{
    if (iPointDrawMgr_ == nullptr) {
        iPointDrawMgr_ = std::make_shared<PointerDrawingManager>();
    }
    return iPointDrawMgr_;
}

void PointerDrawingManager::DeletePidInfo(int32_t pid)
{
    CALL_DEBUG_ENTER;
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            return;
        }
    }
}

void PointerDrawingManager::UpdatePidInfo(int32_t pid, bool visible)
{
    CALL_DEBUG_ENTER;
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            break;
        }
    }
    PidInfo info = { .pid = pid, .visible = visible };
    pidInfos_.push_back(info);
}

void PointerDrawingManager::UpdatePointerVisible()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerWindow_);
    if (IsPointerVisible()) {
        pointerWindow_->Show();
    } else {
        pointerWindow_->Hide();
    }
}

bool PointerDrawingManager::IsPointerVisible()
{
    CALL_DEBUG_ENTER;
    if (pidInfos_.empty()) {
        MMI_HILOGD("Visible property is true");
        return true;
    }
    auto info = pidInfos_.back();
    MMI_HILOGD("Visible property:%{public}zu.%{public}d-%{public}d", pidInfos_.size(), info.pid, info.visible);
    return info.visible;
}

void PointerDrawingManager::DeletePointerVisible(int32_t pid)
{
    CALL_DEBUG_ENTER;
    DeletePidInfo(pid);
    UpdatePointerVisible();
}

int32_t PointerDrawingManager::SetPointerVisible(int32_t pid, bool visible)
{
    CALL_DEBUG_ENTER;
    UpdatePidInfo(pid, visible);
    UpdatePointerVisible();
    return RET_OK;
}

int32_t PointerDrawingManager::SetPointerStyle(int32_t pid, int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    auto it = mouseIcons_.find(MOUSE_ICON(pointerStyle));
    if (it == mouseIcons_.end()) {
        MMI_HILOGE("The param pointerStyle is invalid");
        return RET_ERR;
    }

    if (WinMgr->SetPointerStyle(pid, windowId, pointerStyle)) {
        MMI_HILOGE("Set pointer style failed");
        return RET_ERR;
    }

    if (!InputDevMgr->HasPointerDevice()) {
        MMI_HILOGD("The pointer device is not exist");
        return RET_OK;
    }

    if (!WinMgr->IsNeedRefreshLayer(windowId)) {
        MMI_HILOGD("Not need refresh layer, window type:%{public}d, pointer style:%{public}d", windowId, pointerStyle);
        return RET_OK;
    }

    if (pointerWindow_ != nullptr) {
        int32_t physicalX = lastPhysicalX_;
        int32_t physicalY = lastPhysicalY_;
        AdjustMouseFocus(ICON_TYPE(mouseIcons_[MOUSE_ICON(pointerStyle)].alignmentWay), physicalX, physicalY);
        pointerWindow_->MoveTo(physicalX, physicalY);

        int32_t ret = InitLayer(MOUSE_ICON(pointerStyle));
        if (ret != RET_OK) {
            MMI_HILOGE("Init layer failed");
            return RET_ERR;
        }
    }
    MMI_HILOGD("Window type:%{public}d set pointer style:%{public}d success", windowId, pointerStyle);
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerStyle(int32_t pid, int32_t windowId, int32_t &pointerStyle)
{
    CALL_DEBUG_ENTER;
    std::optional<int32_t> pointerStyleInfo = WinMgr->GetPointerStyle(pid, windowId);
    if (!pointerStyleInfo) {
        MMI_HILOGE("Get pointer style failed, pointerStyleInfo is nullptr");
        return RET_ERR;
    }

    pointerStyle = pointerStyleInfo.value();
    MMI_HILOGD("Window type:%{public}d get pointer style:%{public}d success", windowId, pointerStyle);
    return RET_OK;
}

void PointerDrawingManager::DrawPointerStyle()
{
    CALL_DEBUG_ENTER;
    if (hasDisplay_ && hasPointerDevice_) {
        if (pointerWindow_ == nullptr) {
            MMI_HILOGE("Draw pointer style failed, pointerWindow_ is null");
            return;
        }

        std::optional<int32_t> pointerStyleInfo = WinMgr->GetPointerStyle(pid_, windowId_);
        if (!pointerStyleInfo) {
            MMI_HILOGE("Draw pointer style failed, pointerStyleInfo is nullptr");
            return;
        }
        int32_t mouseStyle = pointerStyleInfo.value();

        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayId_, displayWidth_/2, displayHeight_/2, MOUSE_ICON(mouseStyle));
            MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", mouseStyle);
            return;
        }

        DrawPointer(displayId_, lastPhysicalX_, lastPhysicalY_, MOUSE_ICON(mouseStyle));
        MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", mouseStyle);
        return;
    }
}

void PointerDrawingManager::InitStyle()
{
    CALL_DEBUG_ENTER;
    mouseIcons_ = {
        {DEFAULT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default_NW.png"}},
        {EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "East_Center.png"}},
        {WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West_Center.png"}},
        {SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_Center.png"}},
        {NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_Center.png"}},
        {WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "WestEast_Center.png"}},
        {NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "NorthSouth_Center.png"}},
        {NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "NorthEast_Center.png"}},
        {NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "NorthWest_Center.png"}},
        {SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "SouthEast_Center.png"}},
        {SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "SouthWest_Center.png"}},
        {NORTH_EAST_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "NESW_Center.png"}},
        {NORTH_WEST_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "NWSE_Center.png"}},
        {CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cross_Center.png"}},
        {CURSOR_COPY, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Copy_NW.png"}},
        {CURSOR_FORBID, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Forbid_NW.png"}},
        {COLOR_SUCKER, {ANGLE_SW, IMAGE_POINTER_DEFAULT_PATH + "Colorsucker_SW.png"}},
        {HAND_GRABBING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "HandGrabbing_Center.png"}},
        {HAND_OPEN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "HandOpen_Center.png"}},
        {HAND_POINTING, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "HandPointing_NW.png"}},
        {HELP, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Help_NW.png"}},
        {CURSOR_MOVE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Move_Center.png"}},
        {RESIZE_LEFT_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ResizeLeftRight_Center.png"}},
        {RESIZE_UP_DOWN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ResizeUpDown_Center.png"}},
        {SCREENSHOT_CHOOSE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ScreenshotCross_Center.png"}},
        {SCREENSHOT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ScreenshotCursor_Center.png"}},
        {TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "TextCursor_Center.png"}},
        {ZOOM_IN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ZoomIn_Center.png"}},
        {ZOOM_OUT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ZoomOut_Center.png"}},
        {MIDDLE_BTN_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_East_Center.png"}},
        {MIDDLE_BTN_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_West_Center.png"}},
        {MIDDLE_BTN_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_South_Center.png"}},
        {MIDDLE_BTN_NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_North_Center.png"}},
        {MIDDLE_BTN_NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_NS_Center.png"}},
        {MIDDLE_BTN_NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_NE_Center.png"}},
        {MIDDLE_BTN_NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_NW_Center.png"}},
        {MIDDLE_BTN_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_SE_Center.png"}},
        {MIDDLE_BTN_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_SW_Center.png"}},
        {MIDDLE_BTN_NORTH_SOUTH_WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MiddleBin_NSWE_Center.png"}},
    };
    for (auto iter = mouseIcons_.begin(); iter != mouseIcons_.end();) {
        if ((ReadCursorStyleFile(iter->second.iconPath)) != RET_OK) {
            iter = mouseIcons_.erase(iter);
            continue;
        }
        ++iter;
    }
}
} // namespace MMI
} // namespace OHOS
