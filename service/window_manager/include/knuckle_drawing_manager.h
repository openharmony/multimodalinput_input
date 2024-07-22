/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef KNUCKLE_DRAWING_MANAGER_H
#define KNUCKLE_DRAWING_MANAGER_H

#include "draw/canvas.h"
#include "nocopyable.h"
#include "singleton.h"
#include "transaction/rs_transaction.h"
#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_surface_node.h"

#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
struct PointerInfo {
    float x { 0.0F };
    float y { 0.0F };
};

class KnuckleDrawingManager {
public:
    void KnuckleDrawHandler(std::shared_ptr<PointerEvent> touchEvent);
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);
    KnuckleDrawingManager();
    ~KnuckleDrawingManager() = default;
    static void RotationCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode, const DisplayInfo& displayInfo);
    static bool CheckRotatePolicy(const DisplayInfo& displayInfo);
private:
    bool IsValidAction(int32_t action);
    void CreateTouchWindow(int32_t displayId);
    void StartTouchDraw(std::shared_ptr<PointerEvent> touchEvent);
    void CreateCanvasNode();
    int32_t DrawGraphic(std::shared_ptr<PointerEvent> touchEvent);
    int32_t GetPointerPos(std::shared_ptr<PointerEvent> touchEvent);
    bool IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent);
    bool IsSingleKnuckleDoubleClick(std::shared_ptr<PointerEvent> touchEvent);

private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode_ { nullptr };
    std::vector<PointerInfo> pointerInfos_;
    Rosen::Drawing::Paint paint_;
    Rosen::Drawing::Path path_;
    DisplayInfo displayInfo_ {};
    uint64_t screenId_ { 0 };
    bool isActionUp_ { false };
    PointerInfo lastDownPointer_ {};
    int64_t lastUpTime_ { 0 };
    bool isRotate_ { false };
    int32_t scaleW_ { 0 };
    int32_t scaleH_ { 0 };
    int64_t firstDownTime_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_DRAWING_MANAGER_H
