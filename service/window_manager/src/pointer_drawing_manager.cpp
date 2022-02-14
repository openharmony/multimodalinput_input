/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <display_type.h>
#include <ui/rs_surface_node.h>
#include "pointer_drawing_manager.h"
#include "libmmi_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "pixel_map.h"
#include "log.h"
#include "image/bitmap.h"

namespace OHOS::MMI {
    static const std::string IMAGE_POINTER_JPEG_PATH = "/system/etc/multimodalinput/mouse_icon/angle.png";
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MouseDrawingManager" };
}
}

using namespace OHOS::Media;


OHOS::MMI::MouseDrawingManager::MouseDrawingManager() {}

OHOS::MMI::MouseDrawingManager::~MouseDrawingManager() {}

std::unique_ptr<OHOS::Media::PixelMap> OHOS::MMI::MouseDrawingManager::DecodeImageToPixelMap(std::string imagePath)
{
    using namespace OHOS::MMI;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(imagePath, opts, errorCode);
    MMI_LOGE("CreateImageSource errorCode:%{public}u.", errorCode);

    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    MMI_LOGE("get the image decode:%{public}u", ret);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        MMI_LOGE("pixelMap is nullptr:%{public}u .", errorCode);
    }
    return pixelMap;
}

void OHOS::MMI::MouseDrawingManager::DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY)
{
    MMI_LOGD("enter, displayId:%{public}d, globalX:%{public}d, globalY:%{public}d", displayId, globalX, globalY);
    if (drawWindow_ == nullptr) {
        std::string windowName = "pointer window";
        sptr<OHOS::Rosen::WindowOption> option = new OHOS::Rosen::WindowOption();
        option->SetWindowType(OHOS::Rosen::WindowType::WINDOW_TYPE_POINTER);
        option->SetWindowMode(OHOS::Rosen::WindowMode::WINDOW_MODE_FLOATING);
        option->SetDisplayId(displayId);
        OHOS::Rosen::Rect rect;
        rect.posX_ = globalX;
        rect.posY_ = globalY;
        rect.width_ = IMAGE_SIZE;
        rect.height_ = IMAGE_SIZE;
        option->SetWindowRect(rect);
        option->SetFocusable(false);
        option->SetTouchable(false);
        drawWindow_ = OHOS::Rosen::Window::Create(windowName, option, nullptr);

        std::shared_ptr<OHOS::Rosen::RSSurfaceNode> surfaceNode = drawWindow_->GetSurfaceNode();
        if (surfaceNode == nullptr) {
            MMI_LOGE("draw pointer is faild, get surface node is nullptr");
            drawWindow_->Destroy();
            drawWindow_ = nullptr; 
            return;
        }
        sptr<OHOS::Surface> surface = surfaceNode->GetSurface();
        if (surface == nullptr) {
            MMI_LOGE("draw pointer is faild, get surface node is nullptr");
            drawWindow_->Destroy();
            drawWindow_ = nullptr; 
            return;
        }

        sptr<OHOS::SurfaceBuffer> buffer;
        int32_t releaseFence;
        OHOS::BufferRequestConfig config = {
            .width = IMAGE_SIZE,  // small
            .height = IMAGE_SIZE, // small
            .strideAlignment = 0x8,
            .format = PIXEL_FMT_RGBA_8888,
            .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
        };

        OHOS::SurfaceError ret = surface->RequestBuffer(buffer, releaseFence, config);
        MMI_LOGD("request buffer ret:%{public}s", SurfaceErrorStr(ret).c_str());

        if (buffer == nullptr) {
            MMI_LOGE("request buffer failed: buffer is nullptr");
            drawWindow_->Destroy();
            drawWindow_ = nullptr; 
            return;
        }
        if (buffer->GetVirAddr() == nullptr) {
            MMI_LOGE("get virAddr failed: virAddr is nullptr");
            drawWindow_->Destroy();
            drawWindow_ = nullptr; 
            return;
        }

        auto addr = static_cast<uint8_t *>(buffer->GetVirAddr());
        MMI_LOGD("buffer width:%{public}d, height:%{public}d", buffer->GetWidth(), buffer->GetHeight());

        DoDraw(addr, buffer->GetWidth(), buffer->GetHeight());
        MMI_LOGD("DoDraw end");
        OHOS::BufferFlushConfig flushConfig = {
            .damage = {
                .w = buffer->GetWidth(),
                .h = buffer->GetHeight(),
        },
        };
        ret = surface->FlushBuffer(buffer, -1, flushConfig);
        MMI_LOGD("draw pointer FlushBuffer ret:%{public}s", SurfaceErrorStr(ret).c_str());
    } else {
        drawWindow_->MoveTo(globalX, globalY);
    }
    drawWindow_->Show();
    MMI_LOGD("leave");
}

void OHOS::MMI::MouseDrawingManager::DoDraw(uint8_t *addr, uint32_t width, uint32_t height)
{
    MMI_LOGD("enter");
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUYE };
    bitmap.Build(width, height, format);

    OHOS::Rosen::Drawing::Canvas canvas;
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);

    DrawPixelmap(canvas);

    constexpr uint32_t stride = 4;
    int32_t addrSize = width * height * stride;
    auto ret = memcpy_s(addr, addrSize, bitmap.GetPixels(), addrSize);
    CHK(ret == EOK, MEMCPY_SEC_FUN_FAIL);
    MMI_LOGD("leave");
}

void OHOS::MMI::MouseDrawingManager::DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas)
{
    MMI_LOGD("enter");
    OHOS::MMI::MouseDrawingManager mdm;
    std::unique_ptr<OHOS::Media::PixelMap> pixelmap = mdm.DecodeImageToPixelMap(IMAGE_POINTER_JPEG_PATH);
    CHKP(pixelmap);
    OHOS::Rosen::Drawing::Pen pen;
    pen.SetAntiAlias(true);
    pen.SetColor(OHOS::Rosen::Drawing::Color::COLOR_BLUE);
    pen.SetWidth(1);
    canvas.AttachPen(pen);
    canvas.DrawBitmap(*pixelmap, 0, 0);
    MMI_LOGD("leave");
}

void OHOS::MMI::MouseDrawingManager::TellDisplayInfo(int32_t displayId, int32_t width, int32_t height) 
{
    MMI_LOGD("enter");
    hasDisplay_ = true;
    displayId_ = displayId;
    displayWidth_ = width;
    displayHeight_ = height;
    Init();
}

void OHOS::MMI::MouseDrawingManager::TellDeviceInfo(bool hasPointerDevice) 
{
    MMI_LOGD("enter");
    hasPointerDevice_ = hasPointerDevice;
    Init();
}

void OHOS::MMI::MouseDrawingManager::Init() 
{
    if (hasDisplay_ && hasPointerDevice_ && drawWindow_ == nullptr) {
        MMI_LOGD("init draw pointer");
        DrawPointer(displayId_, displayWidth_/2, displayHeight_/2);
        return;
    }

    if (!hasPointerDevice_ && drawWindow_ != nullptr) {
        MMI_LOGD("destroy draw pointer");
        drawWindow_->Destroy();
        drawWindow_ = nullptr; 
    }
}