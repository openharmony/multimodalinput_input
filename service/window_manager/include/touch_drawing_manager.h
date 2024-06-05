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

#include "draw/canvas.h"
#include "nocopyable.h"
#include "singleton.h"
#include "transaction/rs_transaction.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_surface_node.h"
#include "utils/rect.h"

#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "recording/recording_canvas.h"
#include "ui/rs_canvas_drawing_node.h"
#endif // USE_ROSEN_DRAWING

#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {

class TouchDrawingManager {
private:
struct Bubble {
    int32_t innerCircleRadius { 0 };
    int32_t outerCircleRadius { 0 };
    float outerCircleWidth { 0 };
};
struct DevMode {
    std::string SwitchName;
    bool isShow { false };
};
#ifndef USE_ROSEN_DRAWING
    using RosenCanvas = Rosen::RSRecordingCanvas;
#else
    using RosenCanvas = Rosen::Drawing::RecordingCanvas;
#endif

    DECLARE_DELAYED_SINGLETON(TouchDrawingManager);
public:
    DISALLOW_COPY_AND_MOVE(TouchDrawingManager);
    void TouchDrawHandler(const std::shared_ptr<PointerEvent>& pointerEvent);
    void UpdateLabels();
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);
    void GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
        int32_t &physicalX, int32_t &physicalY);
    void SetPointerPositionState(bool state);
    void UpdateBubbleData();
    void Dump(int32_t fd, const std::vector<std::string> &args);

private:
    void CreateObserver();
    void AddCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode, bool isTrackerNode);
    void ConvertPointerEvent(const std::shared_ptr<PointerEvent>& pointerEvent);
    void CreateTouchWindow();
    void DrawBubbleHandler();
    void DrawBubble();
    void DrawPointerPositionHandler(const std::shared_ptr<PointerEvent>& pointerEvent);
    void DrawTracker(int32_t x, int32_t y, int32_t pointerId);
    void DrawCrosshairs(RosenCanvas *canvas, int32_t x, int32_t y);
    void DrawLabels();
    void DrawRectItem(RosenCanvas* canvas, const std::string &text,
        Rosen::Drawing::Rect &rect, const Rosen::Drawing::Color &color);
    void UpdatePointerPosition();
    void RecordLabelsInfo(const std::shared_ptr<PointerEvent>& pointerEvent);
    void UpdateLastPointerItem(PointerEvent::PointerItem &pointerItem);
    void UpdateVelocity();
    void RemovePointerPosition();
    void RemoveBubble();
    void ClearTracker();
    void ClearLabels();
    template <class T>
    void CreateBubbleObserver(T& item);
    template <class T>
    void CreatePointerObserver(T& item);
    template <class T>
    std::string FormatNumber(T number, int32_t precision);
    bool IsValidAction(const int32_t action);
private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> bubbleCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> trackerCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> crosshairCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> labelsCanvasNode_ { nullptr };
    DisplayInfo displayInfo_ {};
    Bubble bubble_;
    Rosen::Drawing::Brush bubbleBrush_;
    Rosen::Drawing::Pen bubblePen_;
    Rosen::Drawing::Brush textBrush_;
    Rosen::Drawing::Brush rectBrush_;
    Rosen::Drawing::Pen pathPen_;
    Rosen::Drawing::Pen pointPen_;
    Rosen::Drawing::Pen linePen_;
    Rosen::Drawing::Pen crosshairsPen_;
    Rosen::Drawing::Point firstPt_;
    Rosen::Drawing::Point currentPt_;
    Rosen::Drawing::Point lastPt_;
    DevMode bubbleMode_;
    DevMode pointerMode_;
    int32_t currentPointerId_ { 0 };
    int32_t maxPointerCount_ { 0 };
    int32_t currentPointerCount_ { 0 };
    int32_t rectTopPosition_ { 0 };
    int64_t lastActionTime_ { 0 };
    double xVelocity_ { 0.0 };
    double yVelocity_ { 0.0 };
    double xShowVelocity_ { 0.0 };
    double yShowVelocity_ { 0.0 };
    double pressure_ { 0.0 };
    double itemRectW_ { 0.0 };
    bool hasBubbleObserver_{ false };
    bool hasPointerObserver_{ false };
    bool isFirstDownAction_ { false };
    bool isDownAction_ { false };
    bool isFirstDraw_ { true };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::list<PointerEvent::PointerItem> lastPointerItem_ { };
    PointerEvent::PointerItem firstPointerItem_;
    RosenCanvas *trackerCanvas_ { nullptr };
    int32_t scaleW_ { 0 };
    int32_t scaleH_ { 0 };
};
#define TOUCH_DRAWING_MGR ::OHOS::DelayedSingleton<TouchDrawingManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_DRAWING_MANAGER_H
