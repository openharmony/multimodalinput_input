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
#include <list>

#include <ui/rs_surface_node.h>

#include "draw/canvas.h"
#include "nocopyable.h"
#include "pixel_map.h"
#include "window.h"

#include "device_observer.h"
#include "i_pointer_drawing_manager.h"
#include "mouse_event_normalize.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
class PointerDrawingManager : public IPointerDrawingManager,
                              public IDeviceObserver,
                              public std::enable_shared_from_this<PointerDrawingManager> {
public:
    static const int32_t IMAGE_WIDTH = 64;
    static const int32_t IMAGE_HEIGHT = 64;

public:
    PointerDrawingManager();
    DISALLOW_COPY_AND_MOVE(PointerDrawingManager);
    ~PointerDrawingManager() = default;
    void DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
        const MOUSE_ICON mouseStyle = MOUSE_ICON::DEFAULT) override;
    void UpdateDisplayInfo(const DisplayInfo& displayInfo) override;
    void OnDisplayInfo(const DisplayGroupInfo& displayGroupInfo) override;
    void OnWindowInfo(const WinInfo &info) override;
    void UpdatePointerDevice(bool hasPointerDevicee, bool isPointerVisible) override;
    bool Init() override;
    void DeletePointerVisible(int32_t pid) override;
    int32_t SetPointerVisible(int32_t pid, bool visible) override;
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, int32_t pointerStyle) override;
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, int32_t &pointerStyle) override;
    void DrawPointerStyle() override;
    bool IsPointerVisible() override;
    void SetPointerLocation(int32_t pid, int32_t x, int32_t y) override;
    void SetMouseDisplayState(bool state) override;
    bool GetMouseDisplayState() const override;
    void AdjustMouseFocus(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);

private:
    void CreatePointerWindow(int32_t displayId, int32_t physicalX, int32_t physicalY);
    sptr<OHOS::Surface> GetLayer();
    sptr<OHOS::SurfaceBuffer> GetSurfaceBuffer(sptr<OHOS::Surface> layer) const;
    void DoDraw(uint8_t *addr, uint32_t width, uint32_t height, const MOUSE_ICON mouseStyle = MOUSE_ICON::DEFAULT);
    void DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas, const std::string& iconPath);
    void DrawManager();
    void FixCursorPosition(int32_t &physicalX, int32_t &physicalY);
    std::unique_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);
    void UpdatePointerVisible();
    void InitStyle();
    int32_t InitLayer(const MOUSE_ICON mouseStyle);

private:
    struct PidInfo {
        int32_t pid { 0 };
        bool visible { false };
    };
    sptr<OHOS::Rosen::Window> pointerWindow_ { nullptr };
    bool hasDisplay_ { false };
    DisplayInfo displayInfo_ {};
    bool hasPointerDevice_ { false };
    int32_t lastPhysicalX_ { -1 };
    int32_t lastPhysicalY_ { -1 };
    int32_t lastMouseStyle_ { -1 };
    int32_t pid_ { 0 };
    int32_t windowId_ { 0 };
    int32_t imageWidth_ { 0 };
    int32_t imageHeight_ { 0 };
    std::map<MOUSE_ICON, IconStyle> mouseIcons_;
    std::list<PidInfo> pidInfos_;
    bool mouseDisplayState_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_DRAWING_MANAGER_H