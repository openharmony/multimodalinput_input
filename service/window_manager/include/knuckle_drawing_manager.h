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

struct ScreenReadState {
    std::string switchName;
    std::string state;
};

class KnuckleDrawingManager {
public:
    void KnuckleDrawHandler(std::shared_ptr<PointerEvent> touchEvent, int32_t displayId = -1);
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);
    KnuckleDrawingManager();
    ~KnuckleDrawingManager() = default;
    void RotationCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode, const DisplayInfo& displayInfo);
    std::string GetScreenReadState();
private:
    bool IsValidAction(int32_t action);
    void CreateTouchWindow(int32_t displayId);
    void StartTouchDraw(std::shared_ptr<PointerEvent> touchEvent);
    int32_t DrawGraphic(std::shared_ptr<PointerEvent> touchEvent);
    int32_t GetPointerPos(std::shared_ptr<PointerEvent> touchEvent);
    bool IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent);
    bool IsSingleKnuckleDoubleClick(std::shared_ptr<PointerEvent> touchEvent);
    int32_t DestoryWindow();
    void CreateObserver();
    template <class T>
    void CreateScreenReadObserver(T& item);
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    void CreateBrushWorkCanvasNode();
    void CreateTrackCanvasNode();
    void InitParticleEmitter();
    void UpdateEmitter();
    void DrawTrackCanvas();
    void DrawBrushCanvas();
    int32_t ClearTrackCanvas();
    int32_t ClearBrushCanvas();
    void ActionUpAnimation();
    uint32_t GetDeltaColor(uint32_t deltaSource, uint32_t deltaTarget);
    uint32_t DrawTrackColorBlue(int32_t pathValue);
    uint32_t DrawTrackColorPink(int32_t pathValue);
    uint32_t DrawTrackColorOrangeRed(int32_t pathValue);
    uint32_t DrawTrackColorYellow(int32_t pathValue);
    int32_t ProcessUpEvent(bool isNeedUpAnimation);
#else
    void CreateCanvasNode();
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    std::shared_ptr<Rosen::RSCanvasDrawingNode> brushCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasDrawingNode> trackCanvasNode_ { nullptr };
#else
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode_ { nullptr };
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    std::vector<PointerInfo> pointerInfos_;
    Rosen::Drawing::Paint paint_;
    Rosen::Drawing::Path path_;
    DisplayInfo displayInfo_ {};
    uint64_t screenId_ { 0 };
    bool isActionUp_ { false };
    bool isNeedInitParticleEmitter_ { true };
    PointerInfo lastDownPointer_ {};
    int64_t lastUpTime_ { 0 };
    bool isRotate_ { false };
    int32_t scaleW_ { 0 };
    int32_t scaleH_ { 0 };
    int64_t firstDownTime_ { 0 };
    bool hasScreenReadObserver_ { false };
    ScreenReadState screenReadState_ { };
    int32_t pointerNum_ { 0 };
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    std::vector<Rosen::Drawing::Path> pathInfos_;
    float pathLength_ { 0.0f };
    float brushPathLength_ { 0.0f };
    uint32_t trackColorR_ { 0x00 };
    uint32_t trackColorG_ { 0x00 };
    uint32_t trackColorB_ { 0x00 };
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_DRAWING_MANAGER_H
