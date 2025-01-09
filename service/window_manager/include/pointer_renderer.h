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

struct RenderConfig {
    MOUSE_ICON style;   // 光标样式
    ICON_TYPE align;    // 光标对齐方式
    std::string path;   // 光标路径
    uint32_t color;     // 光标颜色
    uint32_t size;      // 光标大小
    uint32_t rotation;  // 光标朝向
    float dpi;          // 屏幕 DPI
    bool isHard;        // 是否是硬光标

    int32_t GetImageSize() const;
    std::string ToString() const;
};

class PointerRenderer {
public:
    PointerRenderer() = default;
    ~PointerRenderer() = default;

    int32_t Render(uint8_t *addr, uint32_t width, uint32_t height, const RenderConfig &cfg);

private:
    image_ptr_t LoadPointerImage(const RenderConfig &cfg);
    pixelmap_ptr_t LoadCursorSvgWithColor(const RenderConfig &cfg);
    image_ptr_t ExtractDrawingImage(pixelmap_ptr_t pixelMap);
    float GetOffsetX(const RenderConfig &cfg);
    float GetOffsetY(const RenderConfig &cfg);
};

} // namespace OHOS::MMI

#endif // POINTER_RENDERER_H