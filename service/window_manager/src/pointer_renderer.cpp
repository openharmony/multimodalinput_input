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

#include "pointer_renderer.h"

#include <regex>
#include <sstream>

#include "define_multimodal.h"
#include "image_source.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerRenderer"

constexpr uint32_t RENDER_STRIDE{4};
constexpr int32_t DEVCIE_INDEPENDENT_PIXELS{40};
constexpr float INCREASE_RATIO{1.22f};
constexpr int32_t MIN_POINTER_COLOR{0x000000};
constexpr int32_t MAX_POINTER_COLOR{0xFFFFFF};
constexpr float CALCULATE_IMAGE_MIDDLE{2.0f};
constexpr uint32_t FOCUS_POINT{256};
constexpr float CALCULATE_MOUSE_ICON_BIAS{5.0f};

namespace OHOS::MMI {

int32_t RenderConfig::GetImageSize() const
{
    return pow(INCREASE_RATIO, size - 1) * dpi * DEVCIE_INDEPENDENT_PIXELS;
}

std::string RenderConfig::ToString() const
{
    std::ostringstream oss;
    oss << "{style=" << style << ", align=" << align << ", path" << path << ", color=" << color
        << ", size=" << size << ", rotation=" << rotation << ", dpi=" << dpi
        << ", isHard=" << isHard << ", ImageSize=" << GetImageSize() << "}";
    return oss.str();
}

int32_t PointerRenderer::Render(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg)
{
    CHKPR(addr, RET_ERR);
    MMI_HILOGI("shape=(%{public}d, %{public}d), cfg=%{public}s", width, height, cfg.ToString().data());

    uint32_t addrSize = width * height * RENDER_STRIDE;
    if (cfg.style == MOUSE_ICON::TRANSPARENT_ICON) {
        memset_s(addr, addrSize, 0, addrSize);
        return RET_OK;
    }

    // construct bitmap
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format {
        OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE,
    };
    bitmap.Build(width, height, format);

    // construct canvas and bind to bitmap
    OHOS::Rosen::Drawing::Canvas canvas;
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);

    // load cursor image
    auto image = LoadPointerImage(cfg);
    CHKPR(image, RET_ERR);

    // draw image on canvas
    int32_t dx = 0;
    int32_t dy = 0;
    if (cfg.isHard) {
        dx = GetOffsetX(cfg);
        dy = GetOffsetY(cfg);
    }
    canvas.DrawImage(*image, dx, dy, Rosen::Drawing::SamplingOptions());

    // copy bitmap pixels to addr
    errno_t ret = memcpy_s(addr, addrSize, bitmap.GetPixels(), addrSize);
    if (ret != EOK) {
        return RET_ERR;
    }
    return RET_OK;
}

image_ptr_t PointerRenderer::LoadPointerImage(const RenderConfig &cfg)
{
    auto pixelmap = LoadCursorSvgWithColor(cfg);
    return ExtractDrawingImage(pixelmap);
}

static void ChangeSvgCursorColor(std::string& str, int32_t color)
{
    std::string targetColor = IntToHexRGB(color);
    StringReplace(str, "#000000", targetColor);
    if (color == MAX_POINTER_COLOR) {
        // stroke=\"#FFFFFF" fill="#000000" stroke-linejoin="round" transform="xxx"
        std::regex re("(<path.*)(stroke=\"#[a-fA-F0-9]{6}\")(.*path>)");
        str = std::regex_replace(str, re, "$1stroke=\"#000000\"$3");
    }
}

pixelmap_ptr_t PointerRenderer::LoadCursorSvgWithColor(const RenderConfig &cfg)
{
    std::string svgContent;
    if (!ReadFile(cfg.path, svgContent)) {
        MMI_HILOGE("read file failed");
        return nullptr;
    }

    const bool isPartColor = (cfg.style == CURSOR_COPY) || (cfg.style == CURSOR_FORBID) || (cfg.style == HELP);
    if (isPartColor) {
        ChangeSvgCursorColor(svgContent, cfg.color);
    }
    OHOS::Media::SourceOptions opts;
    std::unique_ptr<std::istream> isp(std::make_unique<std::istringstream>(svgContent));
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(std::move(isp), opts, ret);
    if (!imageSource || ret != ERR_OK) {
        MMI_HILOGE("Get ImageSource failed, ret=%{public}d", ret);
    }
    CHKPP(imageSource);

    int32_t imgSize = cfg.GetImageSize();
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {.width = imgSize, .height = imgSize};
    if (!isPartColor) {
        decodeOpts.SVGOpts.fillColor = {.isValidColor = true, .color = cfg.color};
        if (cfg.color == MAX_POINTER_COLOR) {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MIN_POINTER_COLOR};
        } else {
            decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MAX_POINTER_COLOR};
        }
    }

    pixelmap_ptr_t pmap = imageSource->CreatePixelMap(decodeOpts, ret);
    return pmap;
}

class PixelMapContext {
public:
    explicit PixelMapContext(pixelmap_ptr_t pixelMap) : pixelMap_(pixelMap) {}
    ~PixelMapContext()
    {
        pixelMap_ = nullptr;
    }

private:
    pixelmap_ptr_t pixelMap_{nullptr};
};

static void PixelMapReleaseProc(const void * /* pixels */, void *context)
{
    PixelMapContext *ctx = static_cast<PixelMapContext *>(context);
    if (ctx != nullptr) {
        delete ctx;
    }
}


static Rosen::Drawing::ColorType PixelFormatToColorType(Media::PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case Media::PixelFormat::RGB_565:
            return Rosen::Drawing::ColorType::COLORTYPE_RGB_565;
        case Media::PixelFormat::RGBA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888;
        case Media::PixelFormat::BGRA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888;
        case Media::PixelFormat::ALPHA_8:
            return Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8;
        case Media::PixelFormat::RGBA_F16:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16;
        case Media::PixelFormat::UNKNOWN:
        case Media::PixelFormat::ARGB_8888:
        case Media::PixelFormat::RGB_888:
        case Media::PixelFormat::NV21:
        case Media::PixelFormat::NV12:
        case Media::PixelFormat::CMYK:
        default:
            return Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN;
    }
}

static Rosen::Drawing::AlphaType AlphaTypeToAlphaType(Media::AlphaType alphaType)
{
    switch (alphaType) {
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL;
        default:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
    }
}

static std::shared_ptr<Rosen::Drawing::ColorSpace> ConvertToColorSpace(Media::ColorSpace colorSpace)
{
    switch (colorSpace) {
        case Media::ColorSpace::DISPLAY_P3:
            return Rosen::Drawing::ColorSpace::CreateRGB(
                Rosen::Drawing::CMSTransferFuncType::SRGB, Rosen::Drawing::CMSMatrixType::DCIP3);
        case Media::ColorSpace::LINEAR_SRGB:
            return Rosen::Drawing::ColorSpace::CreateSRGBLinear();
        case Media::ColorSpace::SRGB:
            return Rosen::Drawing::ColorSpace::CreateSRGB();
        default:
            return Rosen::Drawing::ColorSpace::CreateSRGB();
    }
}

image_ptr_t PointerRenderer::ExtractDrawingImage(pixelmap_ptr_t pixelMap)
{
    CHKPP(pixelMap);
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    Rosen::Drawing::ImageInfo drawingImageInfo {
        imageInfo.size.width,
        imageInfo.size.height,
        PixelFormatToColorType(imageInfo.pixelFormat),
        AlphaTypeToAlphaType(imageInfo.alphaType),
        ConvertToColorSpace(imageInfo.colorSpace),
    };
    Rosen::Drawing::Pixmap imagePixmap(drawingImageInfo, reinterpret_cast<const void*>(pixelMap->GetPixels()),
        pixelMap->GetRowBytes());
    PixelMapContext *releaseContext = new (std::nothrow) PixelMapContext(pixelMap);
    CHKPP(releaseContext);
    auto image = Rosen::Drawing::Image::MakeFromRaster(imagePixmap, PixelMapReleaseProc, releaseContext);
    if (image == nullptr) {
        MMI_HILOGE("ExtractDrawingImage image fail");
        delete releaseContext;
    }
    return image;
}

float PointerRenderer::GetOffsetX(const RenderConfig &cfg)
{
    int32_t width = cfg.GetImageSize();
    switch (cfg.align) {
        case ANGLE_E:
            return FOCUS_POINT;
        case ANGLE_S:
            return FOCUS_POINT - width / CALCULATE_IMAGE_MIDDLE;
        case ANGLE_W:
            return FOCUS_POINT - width;
        case ANGLE_N:
            return FOCUS_POINT - width / CALCULATE_IMAGE_MIDDLE;
        case ANGLE_SE:
            return FOCUS_POINT - width;
        case ANGLE_NE:
            return FOCUS_POINT - width;
        case ANGLE_SW:
            return FOCUS_POINT;
        case ANGLE_NW:
            return FOCUS_POINT;
        case ANGLE_CENTER:
            return FOCUS_POINT - width / CALCULATE_IMAGE_MIDDLE;
        case ANGLE_NW_RIGHT:
            return FOCUS_POINT - CALCULATE_MOUSE_ICON_BIAS;
        default:
            MMI_HILOGW("No need calculate physicalX offset");
            return FOCUS_POINT;
    }
}

float PointerRenderer::GetOffsetY(const RenderConfig &cfg)
{
    int32_t height = cfg.GetImageSize();
    switch (cfg.align) {
        case ANGLE_E:
            return FOCUS_POINT - height / CALCULATE_IMAGE_MIDDLE;
        case ANGLE_S:
            return FOCUS_POINT;
        case ANGLE_W:
            return FOCUS_POINT - height;
        case ANGLE_N:
            return FOCUS_POINT - height;
        case ANGLE_SE:
            return FOCUS_POINT - height;
        case ANGLE_NE:
            return FOCUS_POINT;
        case ANGLE_SW:
            return FOCUS_POINT - height;
        case ANGLE_NW:
            return FOCUS_POINT;
        case ANGLE_CENTER:
            return FOCUS_POINT - height / CALCULATE_IMAGE_MIDDLE;
        case ANGLE_NW_RIGHT:
            return FOCUS_POINT;
        default:
            MMI_HILOGW("No need calculate physicalY offset");
            return FOCUS_POINT;
    }
}

} // namespace OHOS::MMI