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
constexpr int32_t PAD_SCREEN_WIDTH = 2560;
constexpr int32_t PHONE_SCREEN_WIDTH = 2160;
constexpr int32_t SMALL_ICON_WIDTH = 40;
constexpr int32_t SMALL_ICON_HEIGHT = 40;
constexpr int32_t MIDDLE_ICON_WIDTH = 60;
constexpr int32_t MIDDLE_ICON_HEIGHT = 60;
constexpr int32_t LARGE_ICON_WIDTH = 80;
constexpr int32_t LARGE_ICON_HEIGHT = 80;
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
        pointerWindow_->MoveTo(physicalX + displayInfo_.x, physicalY + displayInfo_.y);
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
        UpdatePointerVisible();
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
    UpdatePointerVisible();
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
        MMI_HILOGE("Init layer is failed, Layer is nullptr");
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
        MMI_HILOGE("Init layer failed, FlushBuffer return ret:%{public}s", SurfaceErrorStr(ret).c_str());
        return RET_ERR;
    }
    MMI_HILOGD("Init layer success");
    return RET_OK;
}

void PointerDrawingManager::AdjustMouseFocus(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY)
{
    CALL_DEBUG_ENTER;
    switch (iconType) {
        case ANGLE_SW: {
            physicalY -= imageHeight_;
            break;
        }
        case ANGLE_CENTER: {
            physicalX -= imageWidth_ / 2;
            physicalY -= imageHeight_ / 2;
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
    if (displayInfo_.direction == Direction0 || displayInfo_.direction == Direction180) {
        if (physicalX > (displayInfo_.width - imageWidth_ / cursorUnit)) {
            physicalX = displayInfo_.width - imageWidth_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.height - imageHeight_ / cursorUnit)) {
            physicalY = displayInfo_.height - imageHeight_ / cursorUnit;
        }
    } else {
        if (physicalX > (displayInfo_.height - imageHeight_ / cursorUnit)) {
            physicalX = displayInfo_.height - imageHeight_ / cursorUnit;
        }
        if (physicalY > (displayInfo_.width - imageWidth_ / cursorUnit)) {
            physicalY = displayInfo_.width - imageWidth_ / cursorUnit;
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

void PointerDrawingManager::SetMouseDisplayState(bool state)
{
    CALL_DEBUG_ENTER;
    if (mouseDisplayState_ != state) {
        mouseDisplayState_ = state;
        if (mouseDisplayState_) {
            InitLayer(MOUSE_ICON(lastMouseStyle_));
        }
        UpdatePointerVisible();
    }
}

bool PointerDrawingManager::GetMouseDisplayState() const
{
    return mouseDisplayState_;
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
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
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
    decodeOpts.desiredSize = {
        .width = imageWidth_,
        .height = imageHeight_
    };

    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    if (pixelMap == nullptr) {
        MMI_HILOGE("The pixelMap is nullptr");
    }
    return pixelMap;
}

void PointerDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    hasDisplay_ = true;
    displayInfo_ = displayInfo;

    if ((displayInfo_.width >= PHONE_SCREEN_WIDTH) || (displayInfo_.height >= PHONE_SCREEN_WIDTH)) {
        if ((displayInfo_.width == PAD_SCREEN_WIDTH) || (displayInfo_.height == PAD_SCREEN_WIDTH)) {
            imageWidth_ = MIDDLE_ICON_WIDTH;
            imageHeight_ = MIDDLE_ICON_HEIGHT;
        } else {
            imageWidth_ = LARGE_ICON_WIDTH;
            imageHeight_ = LARGE_ICON_HEIGHT;
        }
    } else {
        imageWidth_ = SMALL_ICON_WIDTH;
        imageHeight_ = SMALL_ICON_HEIGHT;
    }
}

void PointerDrawingManager::OnDisplayInfo(const DisplayGroupInfo& displayGroupInfo)
{
    CALL_DEBUG_ENTER;
    for (const auto& item : displayGroupInfo.displaysInfo) {
        if (item.id == displayInfo_.id) {
            UpdateDisplayInfo(item);
            DrawManager();
            return;
        }
    }
    UpdateDisplayInfo(displayGroupInfo.displaysInfo[0]);
    lastPhysicalX_ = displayGroupInfo.displaysInfo[0].width / 2;
    lastPhysicalY_ = displayGroupInfo.displaysInfo[0].height / 2;
    MouseEventHdr->OnDisplayLost(displayInfo_.id);
    if (pointerWindow_ != nullptr) {
        pointerWindow_->Destroy();
        pointerWindow_ = nullptr;
    }
    MMI_HILOGD("displayId_:%{public}d, displayWidth_:%{public}d, displayHeight_:%{public}d",
        displayInfo_.id, displayInfo_.width, displayInfo_.height);
}

void PointerDrawingManager::OnWindowInfo(const WinInfo &info)
{
    CALL_DEBUG_ENTER;
    windowId_ = info.windowId;
    pid_ = info.windowPid;
}

void PointerDrawingManager::UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible)
{
    CALL_DEBUG_ENTER;
    hasPointerDevice_ = hasPointerDevice;
    if (hasPointerDevice_) {
        SetPointerVisible(getpid(), isPointerVisible);
    } else {
        DeletePointerVisible(getpid());
    }
    DrawManager();
}

void PointerDrawingManager::DrawManager()
{
    if (hasDisplay_ && hasPointerDevice_ && pointerWindow_ == nullptr) {
        MMI_HILOGD("Draw pointer begin");
        int32_t mouseStyle = -1;
        int32_t ret = WinMgr->GetPointerStyle(pid_, windowId_, mouseStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Get pointer style failed, pointerStyleInfo is nullptr");
            return;
        }
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.id, displayInfo_.width / 2, displayInfo_.height / 2, MOUSE_ICON(mouseStyle));
            MMI_HILOGD("Draw manager, mouseStyle:%{public}d, last physical is initial value", mouseStyle);
            return;
        }
        DrawPointer(displayInfo_.id, lastPhysicalX_, lastPhysicalY_, MOUSE_ICON(mouseStyle));
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

void PointerDrawingManager::UpdatePointerVisible()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerWindow_);
    if (IsPointerVisible() && mouseDisplayState_) {
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
    auto it = pidInfos_.begin();
    for (; it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            break;
        }
    }
    if (it != pidInfos_.end()) {
        if (IsPointerVisible()) {
            InitLayer(MOUSE_ICON(lastMouseStyle_));
        }
        UpdatePointerVisible();
    }
}

int32_t PointerDrawingManager::SetPointerVisible(int32_t pid, bool visible)
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
    if (visible) {
        InitLayer(MOUSE_ICON(lastMouseStyle_));
    }
    UpdatePointerVisible();
    return RET_OK;
}

void PointerDrawingManager::SetPointerLocation(int32_t pid, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    FixCursorPosition(x, y);
    lastPhysicalX_ = x;
    lastPhysicalY_ = y;
    if (pointerWindow_ != nullptr) {
        pointerWindow_->MoveTo(x, y);
        SetPointerVisible(pid, true);
    }
}

int32_t PointerDrawingManager::SetPointerStyle(int32_t pid, int32_t windowId, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    auto it = mouseIcons_.find(MOUSE_ICON(pointerStyle));
    if (it == mouseIcons_.end()) {
        MMI_HILOGE("The param pointerStyle is invalid");
        return RET_ERR;
    }

    int32_t ret = WinMgr->SetPointerStyle(pid, windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed");
        return ret;
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
        pointerWindow_->MoveTo(physicalX + displayInfo_.x, physicalY + displayInfo_.y);

        lastMouseStyle_ = pointerStyle;
        int32_t ret = InitLayer(MOUSE_ICON(pointerStyle));
        if (ret != RET_OK) {
            MMI_HILOGE("Init layer failed");
            return RET_ERR;
        }
    }
    UpdatePointerVisible();
    MMI_HILOGD("Window id:%{public}d set pointer style:%{public}d success", windowId, pointerStyle);
    return RET_OK;
}

int32_t PointerDrawingManager::GetPointerStyle(int32_t pid, int32_t windowId, int32_t &pointerStyle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = WinMgr->GetPointerStyle(pid, windowId, pointerStyle);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pointer style failed, pointerStyleInfo is nullptr");
        return ret;
    }
    MMI_HILOGD("Window id:%{public}d get pointer style:%{public}d success", windowId, pointerStyle);
    return RET_OK;
}

void PointerDrawingManager::DrawPointerStyle()
{
    CALL_DEBUG_ENTER;
    if (hasDisplay_ && hasPointerDevice_) {
        int32_t mouseStyle = -1;
        int32_t ret = WinMgr->GetPointerStyle(pid_, windowId_, mouseStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Draw pointer style failed, pointerStyleInfo is nullptr");
            return;
        }
        if (lastPhysicalX_ == -1 || lastPhysicalY_ == -1) {
            DrawPointer(displayInfo_.id, displayInfo_.width / 2, displayInfo_.height / 2, MOUSE_ICON(mouseStyle));
            MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", mouseStyle);
            return;
        }

        DrawPointer(displayInfo_.id, lastPhysicalX_, lastPhysicalY_, MOUSE_ICON(mouseStyle));
        MMI_HILOGD("Draw pointer style, mouseStyle:%{public}d", mouseStyle);
    }
}

void PointerDrawingManager::InitStyle()
{
    CALL_DEBUG_ENTER;
    mouseIcons_ = {
        {DEFAULT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.png"}},
        {EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "East.png"}},
        {WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West.png"}},
        {SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South.png"}},
        {NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North.png"}},
        {WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West_East.png"}},
        {NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_South.png"}},
        {NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East.png"}},
        {NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West.png"}},
        {SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_East.png"}},
        {SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_West.png"}},
        {NORTH_EAST_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East_South_West.png"}},
        {NORTH_WEST_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West_South_East.png"}},
        {CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cross.png"}},
        {CURSOR_COPY, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Copy.png"}},
        {CURSOR_FORBID, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Forbid.png"}},
        {COLOR_SUCKER, {ANGLE_SW, IMAGE_POINTER_DEFAULT_PATH + "Colorsucker.png"}},
        {HAND_GRABBING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Grabbing.png"}},
        {HAND_OPEN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Open.png"}},
        {HAND_POINTING, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Hand_Pointing.png"}},
        {HELP, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Help.png"}},
        {CURSOR_MOVE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Move.png"}},
        {RESIZE_LEFT_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Left_Right.png"}},
        {RESIZE_UP_DOWN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Up_Down.png"}},
        {SCREENSHOT_CHOOSE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cross.png"}},
        {SCREENSHOT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cursor.png"}},
        {TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Text_Cursor.png"}},
        {ZOOM_IN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_In.png"}},
        {ZOOM_OUT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_Out.png"}},
        {MIDDLE_BTN_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_East.png"}},
        {MIDDLE_BTN_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_West.png"}},
        {MIDDLE_BTN_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South.png"}},
        {MIDDLE_BTN_NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North.png"}},
        {MIDDLE_BTN_NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_South.png"}},
        {MIDDLE_BTN_NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_East.png"}},
        {MIDDLE_BTN_NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_West.png"}},
        {MIDDLE_BTN_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_East.png"}},
        {MIDDLE_BTN_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_West.png"}},
        {MIDDLE_BTN_NORTH_SOUTH_WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH +
            "MID_Btn_North_South_West_East.png"}},
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
