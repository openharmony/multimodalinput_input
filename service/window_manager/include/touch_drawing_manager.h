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
class DelegateInterface;
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
    void TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateLabels();
    void UpdateDisplayInfo(const DisplayInfo& displayInfo);
    void GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
        int32_t &physicalX, int32_t &physicalY);
    int32_t UpdateBubbleData();
    void RotationScreen();
    void Dump(int32_t fd, const std::vector<std::string> &args);
    bool IsWindowRotation();
    void SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
    {
        delegateProxy_ = proxy;
    }
private:
    void CreateObserver();
    void AddCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode, bool isTrackerNode);
    void RotationCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode);
    void ResetCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode);
    void RotationCanvas(RosenCanvas *canvas, Direction direction);
    void CreateTouchWindow();
    void DestoryTouchWindow();
    void DrawBubbleHandler();
    void DrawBubble();
    void DrawPointerPositionHandler();
    void DrawTracker(int32_t x, int32_t y, int32_t pointerId);
    void DrawCrosshairs(RosenCanvas *canvas, int32_t x, int32_t y);
    void DrawLabels();
    void DrawRectItem(RosenCanvas* canvas, const std::string &text,
        Rosen::Drawing::Rect &rect, const Rosen::Drawing::Color &color);
    void UpdatePointerPosition();
    void RecordLabelsInfo();
    void UpdateLastPointerItem(PointerEvent::PointerItem &pointerItem);
    void RemovePointerPosition();
    void ClearTracker();
    void InitLabels();
    template <class T>
    void CreateBubbleObserver(T& item);
    template <class T>
    void CreatePointerObserver(T& item);
    template <class T>
    std::string FormatNumber(T number, int32_t precision);
    bool IsValidAction(const int32_t action);
    void Snapshot();
private:
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> bubbleCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> trackerCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> crosshairCanvasNode_ { nullptr };
    std::shared_ptr<Rosen::RSCanvasNode> labelsCanvasNode_ { nullptr };
    DisplayInfo displayInfo_ {};
    Bubble bubble_;
    Rosen::Drawing::Point firstPt_;
    Rosen::Drawing::Point currentPt_;
    Rosen::Drawing::Point lastPt_;
    DevMode bubbleMode_;
    DevMode pointerMode_;
    int32_t currentPointerId_ { 0 };
    int32_t maxPointerCount_ { 0 };
    int32_t currentPointerCount_ { 0 };
    int32_t rectTopPosition_ { 0 };
    int32_t scaleW_ { 0 };
    int32_t scaleH_ { 0 };
    int64_t lastActionTime_ { 0 };
    double xVelocity_ { 0.0 };
    double yVelocity_ { 0.0 };
    double pressure_ { 0.0 };
    double itemRectW_ { 0.0 };
    bool hasBubbleObserver_{ false };
    bool hasPointerObserver_{ false };
    bool isFirstDownAction_ { false };
    bool isDownAction_ { false };
    bool isFirstDraw_ { true };
    bool isChangedRotation_ { false };
    bool isChangedMode_ { false };
    bool stopRecord_ { false };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::shared_ptr<DelegateInterface> delegateProxy_ {nullptr};
    std::list<PointerEvent::PointerItem> lastPointerItem_ { };
    std::mutex mutex_;
};
#define TOUCH_DRAWING_MGR ::OHOS::DelayedSingleton<TouchDrawingManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_DRAWING_MANAGER_H
