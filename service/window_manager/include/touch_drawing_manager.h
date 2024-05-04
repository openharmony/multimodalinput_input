/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TOUCH_DRAWING_MANAGER_H
#define TOUCH_DRAWING_MANAGER_H

#include <ui/rs_canvas_node.h>
#include <ui/rs_surface_node.h>
#include <transaction/rs_transaction.h>

#include "draw/canvas.h"
#include "nocopyable.h"
#include "pointer_event.h"
#include "window_info.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
struct Bubble {
    int32_t innerCircleRadius { 0 };
    int32_t outerCircleRadius { 0 };
    float outerCircleWidth { 0 };
};

class TouchDrawingManager {
    DECLARE_DELAYED_SINGLETON(TouchDrawingManager);
public:
    DISALLOW_COPY_AND_MOVE(TouchDrawingManager);
    void TouchDrawHandler(const std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);
    void GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
        int32_t &physicalX, int32_t &physicalY);

private:
    void StartTouchDraw(const std::shared_ptr<PointerEvent> pointerEvent);
    void CreateTouchWindow(const int32_t displayId);
    void CreateCanvasNode();
    int32_t DrawGraphic(const std::shared_ptr<PointerEvent> pointerEvent);
    bool IsValidAction(const int32_t action);

private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode_;
    DisplayInfo displayInfo_ {};
    uint64_t screenId_ { 0 };
    Bubble bubble_;
    Rosen::Drawing::Brush brush_;
    Rosen::Drawing::Pen pen_;
};
#define TOUCH_DRAWING_MGR ::OHOS::DelayedSingleton<TouchDrawingManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_DRAWING_MANAGER_H
