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

#ifndef POINTER_RENDERER_H
#define POINTER_RENDERER_H

#include "struct_multimodal.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_surface_node.h"

namespace OHOS::MMI {
using image_ptr_t = std::shared_ptr<Rosen::Drawing::Image>;
using pixelmap_ptr_t = std::shared_ptr<OHOS::Media::PixelMap>;
constexpr int32_t DEFAULT_IMG_SIZE{ 10 };

class RenderConfig {
public:
    MOUSE_ICON style_;
    ICON_TYPE align_;
    std::string path_;
    uint32_t color { 0 };
    uint32_t size { 0 };
    uint32_t direction { 0 };
    uint32_t displayDirection { 0 };
    float dpi { 0 };
    bool isHard { false };
    int32_t rotationAngle { 0 };
    uint32_t rotationFocusX { 0 };
    uint32_t rotationFocusY { 0 };
    pixelmap_ptr_t userIconPixelMap { nullptr };
    int32_t userIconHotSpotX { 0 };
    int32_t userIconHotSpotY { 0 };
    bool userIconFollowSystem { false };
    int32_t x { 0 };
    int32_t y { 0 };
    uint64_t screenId { 0 };
    bool isBlur { false };
    int32_t GetImageSize() const;
    float AdjustIncreaseRatio(float dpi) const;
    std::string ToString() const;
    int32_t GetOffsetX() const;
    int32_t GetOffsetY() const;

    RenderConfig() = default;
    ~RenderConfig() = default;

    bool operator == (const RenderConfig& rhs) const
    {
        return style_ == rhs.style_ && GetImageSize() == rhs.GetImageSize() && color == rhs.color;
    }

    bool operator != (const RenderConfig& rhs) const
    {
        return style_ != rhs.style_ || GetImageSize() != rhs.GetImageSize() || color != rhs.color;
    }
};

class PointerRenderer {
public:
    PointerRenderer() = default;
    ~PointerRenderer() = default;

    int32_t Render(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg);
    int32_t DynamicRender(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg);
    image_ptr_t UserIconScale(uint32_t width, uint32_t height, const RenderConfig &cfg);
    void LoadPointerToCache(const std::map<MOUSE_ICON, IconStyle> &mouseIcons);
private:
    int32_t BlurRender(uint8_t *addr, uint32_t addrSize, uint32_t width, uint32_t height,
        const RenderConfig &cfg);
    void DrawDefaultPointer(const RenderConfig &cfg);
    void DrawBlurPointer(uint32_t width, uint32_t height, const RenderConfig &lastCfg, const RenderConfig &cfg);
    void AdjustDeltaForDirection(int32_t &dx, int32_t &dy, uint32_t direction, uint32_t displayDirection);
    bool IsPositionOutCanvas(int32_t x, int32_t y, int32_t imageSize, uint32_t width, uint32_t height);
    bool HasPointerCfg(const RenderConfig &cfg);
    void SetPointerCfg(const RenderConfig &cfg);
    const RenderConfig& GetPointerCfg(const RenderConfig &defaultCfg);
    std::vector<image_ptr_t> GetPointerImage(const RenderConfig &cfg);
    void LoadDefaultPointerImage(const RenderConfig &cfg);
    void ApplyAlpha(uint8_t *pixel, const int32_t len, bool isPixelPremul, const float pecent);
    void SetAlpha(pixelmap_ptr_t pixelMap, const float pecent);
    image_ptr_t LoadPointerImage(const RenderConfig &cfg);
    bool GetPointerFromCache(const RenderConfig &cfg, std::string& svgContent);
    pixelmap_ptr_t LoadCursorSvgWithColor(const RenderConfig &cfg);
    image_ptr_t ExtractDrawingImage(pixelmap_ptr_t pixelMap);
    int32_t DrawImage(OHOS::Rosen::Drawing::Canvas &canvas, const RenderConfig &cfg);
    std::vector<std::tuple<RenderConfig, image_ptr_t>> imgMaps_;
    image_ptr_t FindImg(const RenderConfig &cfg)
    {
        for (auto& data : imgMaps_) {
            if (std::get<0>(data) == cfg) {
                return std::get<1>(data);
            }
        }
        return nullptr;
    }
    void PushImg(const RenderConfig &cfg, image_ptr_t img)
    {
        if (imgMaps_.size() >= DEFAULT_IMG_SIZE) {
            imgMaps_.erase(imgMaps_.begin());
        }
        imgMaps_.push_back({cfg, img});
    }
    std::map<MOUSE_ICON, std::string> mouseIcons_;
    mutable std::mutex cacheMutex_;
    std::map<uint64_t, RenderConfig> screenConfigs_;
    bool defaultInit_ { false };
    std::map<uint64_t, std::vector<image_ptr_t>> screenImages_;

    OHOS::Rosen::Drawing::Bitmap defaultBitmap_;
    OHOS::Rosen::Drawing::BitmapFormat defaultFormat_ {
        OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE,
    };
    OHOS::Rosen::Drawing::Canvas defaultCanvas_;
};
} // namespace OHOS::MMI

#endif // POINTER_RENDERER_H