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
#include "singleton.h"
#include "../../../common/include/device_observer.h"
#include "struct_multimodal.h"
#include "pixel_map.h"
#include "window.h"
#include "draw/canvas.h"

#define IMAGE_SIZE 64
namespace OHOS {
namespace MMI {
class PointerDrawingManager : public DelayedSingleton<PointerDrawingManager>, public DeviceObserver {
public:
    PointerDrawingManager();
    ~PointerDrawingManager();
    std::unique_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(std::string imagePath);
    void DrawPointer(int32_t displayId, int32_t globalX, int32_t globalY);
    void TellDisplayInfo(int32_t displayId, int32_t width, int32_t height);
    void UpdatePointerDevice(bool hasPointerDevice);
    bool Init();

private:
    void DoDraw(uint8_t *addr, uint32_t width, uint32_t height);
    void DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas);
    void DrawManager();

private:
    sptr<OHOS::Rosen::Window> drawWindow_;
    bool hasDisplay_ { false };
    int32_t displayId_;
    int32_t displayWidth_;
    int32_t displayHeight_;
    bool hasPointerDevice_ { false };
};
} // namespace MMI
} // namespace OHOS
#define PointerDrawMgr OHOS::MMI::PointerDrawingManager::GetInstance()
#endif // POINTER_DRAWING_MANAGER_H