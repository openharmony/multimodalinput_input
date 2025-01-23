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

struct RenderConfig {
    MOUSE_ICON style;
    ICON_TYPE align;
    std::string path;
    uint32_t color { 0 };
    uint32_t size { 0 };
    uint32_t direction { 0 };
    float dpi { 0 };
    bool isHard { false };
    int32_t rotationAngle { 0 };
    uint32_t rotationFocusX { 0 };
    uint32_t rotationFocusY { 0 };
    pixelmap_ptr_t userIconPixelMap { nullptr };
    int32_t userIconHotSpotX { 0 };
    int32_t userIconHotSpotY { 0 };

    int32_t GetImageSize() const;
    std::string ToString() const;
    bool operator == (const RenderConfig& rhs) const
    {
        return style == rhs.style && GetImageSize() == rhs.GetImageSize() && color == rhs.color;
    }
    bool operator != (const RenderConfig& rhs) const
    {
        return style != rhs.style || GetImageSize() != rhs.GetImageSize() || color != rhs.color;
    }
};

class PointerRenderer {
public:
    PointerRenderer() = default;
    ~PointerRenderer() = default;

    int32_t Render(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg);
    int32_t DynamicRender(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg);
private:
    image_ptr_t LoadPointerImage(const RenderConfig &cfg);
    pixelmap_ptr_t LoadCursorSvgWithColor(const RenderConfig &cfg);
    image_ptr_t ExtractDrawingImage(pixelmap_ptr_t pixelMap);
    float GetOffsetX(const RenderConfig &cfg);
    float GetOffsetY(const RenderConfig &cfg);
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
};
} // namespace OHOS::MMI

#endif // POINTER_RENDERER_H