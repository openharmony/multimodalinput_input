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

#ifndef POINTER_DRAWING_MANAGER_H
#define POINTER_DRAWING_MANAGER_H

#include <iostream>

#include <ui/rs_surface_node.h>

#include "draw/canvas.h"
#include "nocopyable.h"
#include "pixel_map.h"
#include "window.h"

#include "device_observer.h"
#include "i_pointer_drawing_manager.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
class PointerDrawingManager : public IPointerDrawingManager,
                              public IDeviceObserver,
                              public std::enable_shared_from_this<PointerDrawingManager> {
public:
    PointerDrawingManager() = default;
    virtual ~PointerDrawingManager() = default;
    DISALLOW_COPY_AND_MOVE(PointerDrawingManager);
    void DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY);
    void OnDisplayInfo(int32_t displayId, int32_t width, int32_t height);
    void UpdatePointerDevice(bool hasPointerDevice);
    bool Init();

public:
    static const int32_t IMAGE_WIDTH = 64;
    static const int32_t IMAGE_HEIGHT = 64;

private:
    void CreatePointerWindow(int32_t displayId, int32_t globalX, int32_t globalY);
    sptr<OHOS::Surface> GetLayer();
    sptr<OHOS::SurfaceBuffer> GetSurfaceBuffer(sptr<OHOS::Surface> layer) const;
    void DoDraw(uint8_t *addr, uint32_t width, uint32_t height);
    void DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas);
    void DrawManager();
    void FixCursorPosition(int32_t &globalX, int32_t &globalY);
    std::unique_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);

private:
    sptr<OHOS::Rosen::Window> pointerWindow_ = nullptr;
    bool hasDisplay_ = false;
    int32_t displayId_ = -1;
    int32_t displayWidth_ = 0;
    int32_t displayHeight_ = 0;
    bool hasPointerDevice_ = false;
    int32_t lastGlobalX_ = -1;
    int32_t lastGlobalY_ = -1;
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_DRAWING_MANAGER_H