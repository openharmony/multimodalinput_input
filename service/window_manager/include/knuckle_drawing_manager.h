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
#include "pointer_event.h"
#include "singleton.h"
#include "transaction/rs_transaction.h"
#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_surface_node.h"
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
    void RotationCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode, DisplayInfo displayInfo);
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

//glow pointer
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

#ifndef KNUCKLE_GLOW_TRACE_SYSTEM_H
#define KNUCKLE_GLOW_TRACE_SYSTEM_H

#include <vector>

#include "draw/canvas.h"
#include "image/bitmap.h"
#include "include/core/SkPath.h"
#include "knuckle_divergent_point.h"
#include "knuckle_glow_point.h"
#include "pipeline/rs_recording_canvas.h"
#include "render/rs_pixel_map_util.h"

namespace OHOS {
namespace MMI {
class KnuckleGlowTraceSystem {
public:
    KnuckleGlowTraceSystem(int32_t pointSize, std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
        int32_t maxDivergenceNum);
    ~KnuckleGlowTraceSystem() = default;
    void Clear();
    void Update();
    void Draw(Rosen::ExtendRecordingCanvas* canvas);
    void ResetDivergentPoints(double pointX, double pointY);
    void AddGlowPoints(const Rosen::Drawing::Path &path, int64_t timeInterval);

private:
    std::vector<std::shared_ptr<KnuckleGlowPoint>> glowPoints_;
    std::vector<std::shared_ptr<KnuckleDivergentPoint>> divergentPoints_;
    int32_t maxDivergenceNum_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GLOW_TRACE_SYSTEM_H




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

#ifndef KNUCKLE_GIVERGENT_POINT_H
#define KNUCKLE_GIVERGENT_POINT_H

#include "image/bitmap.h"
#include "draw/canvas.h"
#include "utils/matrix.h"
#include "render/rs_pixel_map_util.h"
#include "pipeline/rs_recording_canvas.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_LIFESPAN = -1;
} // namespace

class KnuckleDivergentPoint {
public:
    explicit KnuckleDivergentPoint(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);
    ~KnuckleDivergentPoint() = default;
    void Update();
    void Clear();
    void Draw(Rosen::ExtendRecordingCanvas* canvas);
    void Reset(double pointX, double pointY);
    bool IsEnded() const;

private:
    double moveVelocityX_ { 0.f };
    double moveVelocityY_ { 0.f };
    double pointX_ { 0.f };
    double pointY_ { 0.f };
    int32_t lifespan_ { DEFAULT_LIFESPAN };
    std::shared_ptr<OHOS::Media::PixelMap> traceShadow_ { nullptr };
    Rosen::Drawing::Matrix traceMatrix_;
    OHOS::Rosen::Drawing::Brush brush_;
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GIVERGENT_POINT_H



/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef KNUCKLE_GLOW_POINT_H
#define KNUCKLE_GLOW_POINT_H

#include "draw/canvas.h"
#include "image/bitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkPaint.h"
#include "pipeline/rs_recording_canvas.h"
#include "render/rs_pixel_map_util.h"
#include "utils/matrix.h"

namespace OHOS {
namespace MMI {
class KnuckleGlowPoint {
public:
    explicit KnuckleGlowPoint(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);
    ~KnuckleGlowPoint() = default;
    void Update();
    void Draw(Rosen::ExtendRecordingCanvas* canvas);
    void Reset(double pointX, double pointY, float lifespanOffset);
    bool IsEnded() const;

private:
    void UpdateMatrix();
    int64_t GetNanoTime() const;

    double lifespan_ { -1.f };
    double pointX_ { 0.f };
    double pointY_ { 0.f };
    int64_t lastUpdateTimeMillis_  { 0 };
    float traceSize_  { 0.f };

    Rosen::Drawing::Matrix traceMatrix_;
    std::shared_ptr<OHOS::Media::PixelMap> traceShadow_ { nullptr };
    OHOS::Rosen::Drawing::Brush brush_;
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GLOW_POINT_H

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

#ifndef KNUCKLE_DYNAMIC_DRAWING_MANAGER_H
#define KNUCKLE_DYNAMIC_DRAWING_MANAGER_H

#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_surface_node.h"
#include "transaction/rs_transaction.h"

#include "draw/canvas.h"
#include "include/core/SkPath.h"
#include "include/core/SkPaint.h"
#include "knuckle_drawing_manager.h"
#include "knuckle_glow_trace_system.h"
#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class KnuckleDynamicDrawingManager {
public:
    KnuckleDynamicDrawingManager();
    ~KnuckleDynamicDrawingManager() = default;
    void KnuckleDynamicDrawHandler(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);

private:
    void StartTouchDraw(std::shared_ptr<PointerEvent> pointerEvent);
    void CreateTouchWindow(const int32_t displayId);
    void CreateCanvasNode();
    int32_t DrawGraphic(std::shared_ptr<PointerEvent> pointerEvent);

    bool CheckPointerAction(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessUpAndCancelEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessDownEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void ProcessMoveEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void InitPointerPathPaint();
    void UpdateTrackColors();
    std::shared_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);
    bool IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent);

private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode_ { nullptr };
    DisplayInfo displayInfo_ {};
    uint64_t screenId_ { 0 };
    Rosen::Drawing::Brush brush_;
    Rosen::Drawing::Pen pen_;
    std::vector<Rosen::Drawing::Point> traceControlPoints_;

    int32_t pointCounter_ { 0 };
    bool isDrawing_ { true };
    std::shared_ptr<KnuckleGlowTraceSystem> glowTraceSystem_ { nullptr };
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr_ { nullptr };
    Rosen::Drawing::Path pointerPath_;
    SkPaint pointerPathPaint_;
    int64_t lastUpdateTimeMillis_ { 0 };
    int64_t isInDrawingTime_ { 0 };

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap_ { nullptr };
    bool isStop_ { false };
    bool isRotate_ { false };
    int32_t lastDownX_ { 0 };
    int32_t lastDownY_ { 0 };
    int64_t lastUpTime_ { 0 };
    int32_t scaleW_ { 0 };
    int32_t scaleH_ { 0 };
    int64_t firstDownTime_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_DYNAMIC_DRAWING_MANAGER_H

