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

#include "knuckle_dynamic_drawing_manager.h"

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"

#include "mmi_log.h"
#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "recording/recording_canvas.h"
#include "ui/rs_canvas_drawing_node.h"
#endif // USE_ROSEN_DRAWING
#include "parameters.h"
#include "render/rs_pixel_map_util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDynamicDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
const std::string IMAGE_POINTER_PENTAGRAM_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string PENT_ICON_PATH = IMAGE_POINTER_PENTAGRAM_PATH + "Default.svg";
constexpr int32_t DENSITY_BASELINE { 160 };
constexpr int32_t INDEPENDENT_INNER_PIXELS { 20 };
constexpr int32_t INDEPENDENT_OUTER_PIXELS { 21 };
constexpr int32_t INDEPENDENT_WIDTH_PIXELS { 2 };
constexpr int32_t CALCULATE_MIDDLE { 2 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t MAX_POINTER_COLOR { 0x00ffff };
constexpr int32_t TIME_DIMENSION { 1000 };
constexpr int32_t PATH_COLOR { 0xFFCCCCCC };
constexpr int32_t MIN_POINT_SIZE { 1 };
constexpr float PAINT_STROKE_WIDTH { 10.0f };
constexpr float DOUBLE { 2.0f };
constexpr int32_t POINT_TOTAL_SIZE { 5 };
constexpr int32_t POINT_SYSTEM_SIZE { 200 };
constexpr int32_t MAX_DIVERGENCE_NUM { 10 };
constexpr int32_t DEFAULT_POINTER_SIZE { 1 };
constexpr int32_t DESIRED_SIZE { 80 };
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW { 450000 };
constexpr int64_t WAIT_DOUBLE_CLICK_INTERVAL_TIME { 100000 };
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG { 96.0f };
constexpr float VPR_CONFIG { 3.25f };
constexpr int32_t POW_SQUARE { 2 };
constexpr int32_t IN_DRAWING_TIME { 23000 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
constexpr std::string_view SCREEN_READ_ENABLE { "1" };
} // namespace

KnuckleDynamicDrawingManager::KnuckleDynamicDrawingManager()
{
    InitPointerPathPaint();
}

std::shared_ptr<OHOS::Media::PixelMap> KnuckleDynamicDrawingManager::DecodeImageToPixelMap(const std::string &imagePath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(imagePath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = DESIRED_SIZE,
        .height = DESIRED_SIZE
    };
 
    decodeOpts.SVGOpts.fillColor = {.isValidColor = true, .color = MAX_POINTER_COLOR};
    decodeOpts.SVGOpts.strokeColor = {.isValidColor = true, .color = MAX_POINTER_COLOR};

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}

void KnuckleDynamicDrawingManager::InitPointerPathPaint()
{
    CALL_DEBUG_ENTER;
    pixelMap_ = DecodeImageToPixelMap(PENT_ICON_PATH);
    CHKPV(pixelMap_);
    if (glowTraceSystem_ == nullptr) {
        glowTraceSystem_ = std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap_, MAX_DIVERGENCE_NUM);
    }
    pointerPathPaint_.setStyle(SkPaint::Style::kStroke_Style);
    pointerPathPaint_.setStrokeJoin(SkPaint::Join::kRound_Join);
    pointerPathPaint_.setStrokeCap(SkPaint::Cap::kRound_Cap);
    pointerPathPaint_.setStrokeWidth(PAINT_STROKE_WIDTH);
    pointerPathPaint_.setAntiAlias(true);
}

void KnuckleDynamicDrawingManager::UpdateTrackColors()
{
    CALL_DEBUG_ENTER;
    pointerPathPaint_.setColor(PATH_COLOR);
}

void KnuckleDynamicDrawingManager::KnuckleDynamicDrawHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (!IsSingleKnuckle(pointerEvent)) {
        return;
    }
    auto displayId = pointerEvent->GetTargetDisplayId();
    CreateTouchWindow(displayId);
    if (CheckPointerAction(pointerEvent)) {
        StartTouchDraw(pointerEvent);
    }
}

bool KnuckleDynamicDrawingManager::IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(touchEvent);
    auto id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    auto itemToolType = item.GetToolType();
    if (itemToolType != PointerEvent::TOOL_TYPE_KNUCKLE ||
        touchEvent->GetPointerIds().size() != 1 || isRotate_) {
        if (!traceControlPoints_.empty()) {
            isStop_ = true;
            isDrawing_ = true;
            DestoryWindow();
        } else if (isRotate_) {
            isRotate_ = false;
            if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) {
                return true;
            }
        }
        return false;
    }
    return true;
}

bool KnuckleDynamicDrawingManager::CheckPointerAction(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(knuckleDrawMgr_);
    if (knuckleDrawMgr_->GetScreenReadState() == SCREEN_READ_ENABLE) {
        DestoryWindow();
    }
    size_t size = pointerEvent->GetPointerIds().size();
    if (size > MIN_POINT_SIZE) {
        pointerPath_.Reset();
        CHKPF(glowTraceSystem_);
        glowTraceSystem_->Clear();
        return false;
    }
    switch (pointerEvent->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_PULL_UP:
            ProcessUpAndCancelEvent(pointerEvent);
            break;
        case PointerEvent::POINTER_ACTION_DOWN:
        case PointerEvent::POINTER_ACTION_PULL_DOWN:
            ProcessDownEvent(pointerEvent);
            return true;
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_PULL_MOVE:
            if (!isStop_ && !traceControlPoints_.empty()) {
                ProcessMoveEvent(pointerEvent);
                return true;
            }
            return false;
        default:
            return false;
    }
    return true;
}

void KnuckleDynamicDrawingManager::StartTouchDraw(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    int32_t ret = DrawGraphic(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGD("Can't get enough pointers to draw");
        return;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDynamicDrawingManager::ProcessUpAndCancelEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(glowTraceSystem_);
    CHKPV(pointerEvent);
    lastUpTime_ = pointerEvent->GetActionTime();
    if (pointerPath_.IsValid()) {
        auto id = pointerEvent->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        pointerEvent->GetPointerItem(id, pointerItem);
        int32_t physicalX = pointerItem.GetDisplayX();
        int32_t physicalY = pointerItem.GetDisplayY();
        glowTraceSystem_->ResetDivergentPoints(physicalX, physicalY);
    }
    isDrawing_ = true;
    DestoryWindow();
}

void KnuckleDynamicDrawingManager::ProcessDownEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    if (traceControlPoints_.empty()) {
        for (int32_t i = 0; i < POINT_TOTAL_SIZE; i++) {
            Rosen::Drawing::Point point = Rosen::Drawing::Point();
            traceControlPoints_.emplace_back(point);
        }
    }
    int64_t intervalTime = pointerEvent->GetActionTime() - lastUpTime_;
    firstDownTime_ = pointerEvent->GetActionTime();
    bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= DOUBLE_CLICK_INTERVAL_TIME_SLOW;

    UpdateTrackColors();
    lastUpdateTimeMillis_ = pointerEvent->GetActionTime();
    pointCounter_ = 0;
    auto id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(id, pointerItem);
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayY();
    float downToPrevDownDistance = static_cast<float>(sqrt(pow(lastDownX_ - physicalX, POW_SQUARE) +
        pow(lastDownY_ - physicalY, POW_SQUARE)));
    bool isDistanceReady = downToPrevDownDistance < DOUBLE_CLICK_DISTANCE_LONG_CONFIG * POW_SQUARE;
    if (isTimeIntervalReady && isDistanceReady) {
        MMI_HILOGE("Take a screenshot");
        isDrawing_ = true;
        isStop_ = true;
        return;
    }
    lastDownX_ = physicalX;
    lastDownY_ = physicalY;
    traceControlPoints_[pointCounter_].Set(physicalX, physicalY);
    isStop_ = false;
}

void KnuckleDynamicDrawingManager::ProcessMoveEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    pointCounter_++;
    if (pointCounter_ >= POINT_TOTAL_SIZE) {
        MMI_HILOGE("traceControlPoints_ index out of size");
        return;
    }
    auto id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(id, pointerItem);
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayY();
    traceControlPoints_[pointCounter_].Set(physicalX, physicalY);
    int pointIndex4 = 4;
    bool draw = (pointerEvent->GetActionTime() - firstDownTime_) > WAIT_DOUBLE_CLICK_INTERVAL_TIME;
    if (pointCounter_ == pointIndex4) {
        int pointIndex0 = 0;
        int pointIndex1 = 1;
        int pointIndex2 = 2;
        int pointIndex3 = 3;

        traceControlPoints_[pointIndex3].Set(
            (traceControlPoints_[pointIndex2].GetX() + traceControlPoints_[pointIndex4].GetX()) / DOUBLE,
            (traceControlPoints_[pointIndex2].GetY() + traceControlPoints_[pointIndex4].GetY()) / DOUBLE);
        // Add a cubic Bezier from pt[0] to pt[3] with control pointspt[1] and pt[2]
        pointerPath_.MoveTo (traceControlPoints_[pointIndex0].GetX(), traceControlPoints_[pointIndex0].GetY());
        pointerPath_.CubicTo(traceControlPoints_[pointIndex1].GetX(), traceControlPoints_[pointIndex1].GetY(),
            traceControlPoints_[pointIndex2].GetX(), traceControlPoints_[pointIndex2].GetY(),
            traceControlPoints_[pointIndex3].GetX(), traceControlPoints_[pointIndex3].GetY());
        traceControlPoints_[pointIndex0].Set(traceControlPoints_[pointIndex3].GetX(),
            traceControlPoints_[pointIndex3].GetY());
        traceControlPoints_[pointIndex1].Set (traceControlPoints_[pointIndex4].GetX(),
            traceControlPoints_[pointIndex4].GetY());
        pointCounter_ = 1;
        // Add glowing particles onto the last path segment that was drawn
        int64_t now = pointerEvent->GetActionTime();
        if (draw) {
            glowTraceSystem_->AddGlowPoints(pointerPath_, (now - lastUpdateTimeMillis_) / TIME_DIMENSION);
        }
        pointerPath_.Reset();
        lastUpdateTimeMillis_ = now;
    }
    if (draw) {
        glowTraceSystem_->ResetDivergentPoints(physicalX, physicalY);
        isDrawing_ = false;
    }
}

void KnuckleDynamicDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    if (displayInfo_.direction != displayInfo.direction) {
        MMI_HILOGD("DisplayInfo direction change");
        isRotate_ = true;
    }
    scaleW_ = displayInfo.width > displayInfo.height ? displayInfo.width : displayInfo.height;
    scaleH_ = displayInfo.width > displayInfo.height ? displayInfo.width : displayInfo.height;
    displayInfo_ = displayInfo;
}

void KnuckleDynamicDrawingManager::SetKnuckleDrawingManager(std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr)
{
    CALL_DEBUG_ENTER;
    knuckleDrawMgr_ = knuckleDrawMgr;
}

int32_t KnuckleDynamicDrawingManager::DrawGraphic(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, RET_ERR);
    CHKPR(canvasNode_, RET_ERR);
    glowTraceSystem_->Update();
    if ((pointerEvent->GetActionTime() - isInDrawingTime_) > IN_DRAWING_TIME) {
        isInDrawingTime_ = pointerEvent->GetActionTime();
    } else {
        return RET_ERR;
    }
#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING

    CHKPR(canvas, RET_ERR);

    if (!isDrawing_) {
        glowTraceSystem_->Draw(canvas);
    }
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    canvasNode_->FinishRecording();
    return RET_OK;
}

void KnuckleDynamicDrawingManager::CreateTouchWindow(const int32_t displayId)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGD("surfaceNode_ is already exist");
        return;
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "knuckle dynamic window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    CHKPV(surfaceNode_);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->SetBounds(0, 0, scaleW_, scaleH_);
    surfaceNode_->SetFrame(0, 0, scaleW_, scaleH_);

#ifndef USE_ROSEN_DRAWING
    surfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING

    screenId_ = static_cast<uint64_t>(displayId);
    surfaceNode_->SetRotation(0);

    CreateCanvasNode();
    surfaceNode_->AddChild(canvasNode_, DEFAULT_VALUE);
    if (displayInfo_.displayMode == DisplayMode::MAIN) {
        screenId_ = FOLD_SCREEN_MAIN_ID;
    }
    MMI_HILOGI("screenId_: %{public}" PRIu64, screenId_);
    surfaceNode_->AttachToDisplay(screenId_);
    CHKPV(knuckleDrawMgr_);
    if (knuckleDrawMgr_->CheckRotatePolicy(displayInfo_)) {
        knuckleDrawMgr_->RotationCanvasNode(canvasNode_, displayInfo_);
    }
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDynamicDrawingManager::CreateCanvasNode()
{
    CALL_DEBUG_ENTER;
    canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    CHKPV(canvasNode_);
    canvasNode_->SetBounds(0, 0, scaleW_, scaleH_);
    canvasNode_->SetFrame(0, 0, scaleW_, scaleH_);

#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING
    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(0);
}

void KnuckleDynamicDrawingManager::DestoryWindow()
{
    CALL_DEBUG_ENTER;
    traceControlPoints_.clear();
    pointerPath_.Reset();
    glowTraceSystem_->Clear();
    CHKPV(canvasNode_);
#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
    CHKPV(canvas);
    canvas->Clear();
    canvasNode_->FinishRecording();
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    canvasNode_.reset();
    CHKPV(surfaceNode_);
    surfaceNode_.reset();
    Rosen::RSTransaction::FlushImplicitTransaction();
}
} // namespace MMI
} // namespace OHOS
