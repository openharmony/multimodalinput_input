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

#include "knuckle_drawing_manager.h"

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "ui/rs_canvas_drawing_node.h"
#endif // USE_ROSEN_DRAWING

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_VALUE = -1;
constexpr int32_t MAX_POINTER_NUM = 5;
constexpr int32_t MID_POINT = 2;
constexpr int32_t POINT_INDEX0 = 0;
constexpr int32_t POINT_INDEX1 = 1;
constexpr int32_t POINT_INDEX2 = 2;
constexpr int32_t POINT_INDEX3 = 3;
constexpr int32_t POINT_INDEX4 = 4;
constexpr int32_t PAINT_STROKE_WIDTH = 10;
constexpr int32_t PAINT_PATH_RADIUS = 10;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW = 450000;
constexpr int64_t WAIT_DOUBLE_CLICK_INTERVAL_TIME = 100000;
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG = 96.0f;
constexpr float VPR_CONFIG = 3.25f;
constexpr int32_t POW_SQUARE = 2;
} // namespace

KnuckleDrawingManager::KnuckleDrawingManager()
{
    paint_.SetColor(Rosen::Drawing::Color::COLOR_CYAN);
    paint_.SetAntiAlias(true);
    float outerCircleTransparency = 1.0f;
    paint_.SetAlphaF(outerCircleTransparency);
    paint_.SetStyle(Rosen::Drawing::Paint::PaintStyle::PAINT_STROKE);
    paint_.SetJoinStyle(Rosen::Drawing::Pen::JoinStyle::ROUND_JOIN);
    paint_.SetCapStyle(Rosen::Drawing::Pen::CapStyle::ROUND_CAP);
    paint_.SetPathEffect(Rosen::Drawing::PathEffect::CreateCornerPathEffect(PAINT_PATH_RADIUS));
    displayInfo_.x = 0;
    displayInfo_.y = 0;
    displayInfo_.id = 0;
    displayInfo_.dpi = 0;
    displayInfo_.width = 0;
    displayInfo_.height = 0;
    displayInfo_.direction = Direction::DIRECTION0;
    displayInfo_.displayDirection = Direction::DIRECTION0;
}

void KnuckleDrawingManager::KnuckleDrawHandler(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);

    if (!IsSingleKnuckle(touchEvent)) {
        return;
    }
    int32_t displayId = touchEvent->GetTargetDisplayId();
    CreateTouchWindow(displayId);
    int32_t touchAction = touchEvent->GetPointerAction();
    if (IsValidAction(touchAction) && IsSingleKnuckleDoubleClick(touchEvent)) {
        StartTouchDraw(touchEvent);
    }
}

bool KnuckleDrawingManager::IsSingleKnuckle(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    if (item.GetToolType() != PointerEvent::TOOL_TYPE_KNUCKLE ||
        touchEvent->GetPointerIds().size() != 1 || isRotate_) {
        if (!pointerInfos_.empty()) {
            pointerInfos_.clear();
#ifndef USE_ROSEN_DRAWING
            auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
                BeginRecording(displayInfo_.width, displayInfo_.height));
#else
            auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
                BeginRecording(displayInfo_.width, displayInfo_.height));
#endif // USE_ROSEN_DRAWING
            canvas->Clear();
            auto canvasNode = static_cast<Rosen::RSCanvasDrawingNode*>(canvasNode_.get());
            canvasNode->ResetSurface();
            canvasNode_->FinishRecording();
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
        isRotate_ = false;
        return false;
    }
    MMI_HILOGI("touch tool type is single knuckle");
    return true;
}

bool KnuckleDrawingManager::IsSingleKnuckleDoubleClick(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(touchEvent);
    int32_t touchAction = touchEvent->GetPointerAction();
    if (touchAction == PointerEvent::POINTER_ACTION_DOWN) {
        firstDownTime_ = touchEvent->GetActionTime();
        int64_t intervalTime = touchEvent->GetActionTime() - lastUpTime_;
        bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= DOUBLE_CLICK_INTERVAL_TIME_SLOW;
        int32_t id = touchEvent->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        touchEvent->GetPointerItem(id, pointerItem);
        int32_t physicalX = pointerItem.GetDisplayX();
        int32_t physicalY = pointerItem.GetDisplayY();
        float downToPrevDownDistance = static_cast<float>(sqrt(pow(lastDownPointer_.x - physicalX, POW_SQUARE) +
            pow(lastDownPointer_.y - physicalY, POW_SQUARE)));
        bool isDistanceReady = downToPrevDownDistance < DOUBLE_CLICK_DISTANCE_LONG_CONFIG * POW_SQUARE;
        if (isTimeIntervalReady && isDistanceReady) {
            return false;
        }
        lastDownPointer_.x = physicalX;
        lastDownPointer_.y = physicalY;
    } else if (touchAction == PointerEvent::POINTER_ACTION_UP) {
        lastUpTime_ = touchEvent->GetActionTime();
    }
    return true;
}

bool KnuckleDrawingManager::IsValidAction(const int32_t action)
{
    CALL_DEBUG_ENTER;
    if (action == PointerEvent::POINTER_ACTION_DOWN || action == PointerEvent::POINTER_ACTION_PULL_DOWN ||
        (action == PointerEvent::POINTER_ACTION_MOVE && (!pointerInfos_.empty())) ||
        (action == PointerEvent::POINTER_ACTION_PULL_MOVE && (!pointerInfos_.empty())) ||
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP) {
        return true;
    }
    MMI_HILOGE("action is not down or move or up, action:%{public}d", action);
    return false;
}

void KnuckleDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    if (displayInfo_.direction != displayInfo.direction) {
        MMI_HILOGE("displayInfo direction change");
        isRotate_ = true;
    }
    displayInfo_ = displayInfo;
}

void KnuckleDrawingManager::StartTouchDraw(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t ret = DrawGraphic(touchEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Draw graphic failed, ret:%{public}d", ret);
        return;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{
    switch (direction) {
        case DIRECTION0: {
            MMI_HILOGD("direction is DIRECTION0");
            break;
        }
        case DIRECTION90: {
            int32_t temp = physicalY;
            physicalY = width - physicalX;
            physicalX = temp;
            MMI_HILOGD("direction is DIRECTION90, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        case DIRECTION180: {
            physicalX = width - physicalX;
            physicalY = height - physicalY;
            MMI_HILOGD("direction is DIRECTION180, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        case DIRECTION270: {
            int32_t temp = physicalX;
            physicalX = height - physicalY;
            physicalY = temp;
            MMI_HILOGD("direction is DIRECTION270, Original touch screen physicalX:%{public}d, physicalY:%{public}d",
                physicalX, physicalY);
            break;
        }
        default: {
            MMI_HILOGW("direction is invalid, direction:%{public}d", direction);
            break;
        }
    }
}

void KnuckleDrawingManager::CreateTouchWindow(const int32_t displayId)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGD("surfaceNode is already exit");
        return;
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);

    CHKPV(surfaceNode_);
    surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->SetBounds(0, 0, displayInfo_.width, displayInfo_.height);
    surfaceNode_->SetFrame(0, 0, displayInfo_.width, displayInfo_.height);

#ifndef USE_ROSEN_DRAWING
    surfaceNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    surfaceNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING

    screenId_ = static_cast<uint64_t>(displayId);
    MMI_HILOGI("ScreenId: %{public}llu", static_cast<unsigned long long>(screenId_));
    surfaceNode_->SetRotation(0);

    CreateCanvasNode();
    surfaceNode_->AddChild(canvasNode_, DEFAULT_VALUE);
    surfaceNode_->AttachToDisplay(screenId_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDrawingManager::CreateCanvasNode()
{
    canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    CHKPV(canvasNode_);
    canvasNode_->SetBounds(0, 0, displayInfo_.width, displayInfo_.height);
    canvasNode_->SetFrame(0, 0, displayInfo_.width, displayInfo_.height);
#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING
    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(0);
}

int32_t KnuckleDrawingManager::GetPointerPos(std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPR(touchEvent, RET_ERR);
    if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        isActionUp_ = true;
        return RET_OK;
    }
    PointerInfo pointerInfo;
    int32_t pointerId = touchEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!touchEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    int32_t displayX = pointerItem.GetDisplayX();
    int32_t displayY = pointerItem.GetDisplayY();
    if (displayInfo_.displayDirection == DIRECTION0) {
        GetOriginalTouchScreenCoordinates(displayInfo_.direction, displayInfo_.width, displayInfo_.height,
            displayX, displayY);
    }
    pointerInfo.x = displayX;
    pointerInfo.y = displayY;
    pointerInfos_.push_back(pointerInfo);

    if (pointerInfos_.size() == MAX_POINTER_NUM) {
        pointerInfos_[POINT_INDEX3].x = (pointerInfos_[POINT_INDEX2].x + pointerInfos_[POINT_INDEX4].x) / MID_POINT;
        pointerInfos_[POINT_INDEX3].y = (pointerInfos_[POINT_INDEX2].y + pointerInfos_[POINT_INDEX4].y) / MID_POINT;
    } else {
        MMI_HILOGI("Can't get enough pointers to draw");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t KnuckleDrawingManager::DrawGraphic(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    CHKPR(canvasNode_, RET_ERR);
    if (GetPointerPos(touchEvent) != RET_OK) {
        MMI_HILOGE("GetPointerPos failed");
        return RET_ERR;
    }
#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
        BeginRecording(displayInfo_.width, displayInfo_.height));
#else
    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
        BeginRecording(displayInfo_.width, displayInfo_.height));
#endif // USE_ROSEN_DRAWING
    CHKPR(canvas, RET_ERR);
    if (!isActionUp_) {
        if (pointerInfos_.size() != MAX_POINTER_NUM) {
            MMI_HILOGE("Size of pointerInfos_:%{public}zu", pointerInfos_.size());
            return RET_ERR;
        }
        paint_.SetWidth(PAINT_STROKE_WIDTH);
        path_.MoveTo(pointerInfos_[POINT_INDEX0].x, pointerInfos_[POINT_INDEX0].y);
        path_.CubicTo(pointerInfos_[POINT_INDEX1].x, pointerInfos_[POINT_INDEX1].y,
            pointerInfos_[POINT_INDEX2].x, pointerInfos_[POINT_INDEX2].y,
            pointerInfos_[POINT_INDEX3].x, pointerInfos_[POINT_INDEX3].y);
        canvas->AttachPaint(paint_);
        bool starDraw = (touchEvent->GetActionTime() - firstDownTime_) > WAIT_DOUBLE_CLICK_INTERVAL_TIME;
        if (starDraw) {
            canvas->DrawPath(path_);
        }
        canvas->DetachPaint();
        pointerInfos_.erase(pointerInfos_.begin(), pointerInfos_.begin() + POINT_INDEX3);
    } else {
        MMI_HILOGD("isActionUp_ is true");
        isActionUp_ = false;
        pointerInfos_.clear();
        auto canvasNode = static_cast<Rosen::RSCanvasDrawingNode*>(canvasNode_.get());
        canvasNode->ResetSurface();
    }
    path_.Reset();
    canvasNode_->FinishRecording();
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS