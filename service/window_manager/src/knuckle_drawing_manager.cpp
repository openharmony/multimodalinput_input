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
#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "parameters.h"
#include "setting_datashare.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t MAX_POINTER_NUM { 5 };
constexpr int32_t MID_POINT { 2 };
constexpr int32_t POINT_INDEX0 { 0 };
constexpr int32_t POINT_INDEX1 { 1 };
constexpr int32_t POINT_INDEX2 { 2 };
constexpr int32_t POINT_INDEX3 { 3 };
constexpr int32_t POINT_INDEX4 { 4 };
constexpr int32_t PAINT_STROKE_WIDTH { 10 };
constexpr int32_t PAINT_PATH_RADIUS { 10 };
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW { 450000 };
constexpr int64_t WAIT_DOUBLE_CLICK_INTERVAL_TIME { 100000 };
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG { 96.0f };
constexpr float VPR_CONFIG { 3.25f };
constexpr int32_t POW_SQUARE { 2 };
constexpr int32_t ROTATION_ANGLE_0 { 0 };
constexpr int32_t ROTATION_ANGLE_90 { 90 };
constexpr int32_t ROTATION_ANGLE_180 { 180 };
constexpr int32_t ROTATION_ANGLE_270 { 270 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLDABLE = system::GetParameter("const.window.foldabledevice.rotate_policy", "");
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t SCREEN_ROTATE { 1 };
constexpr int32_t FOLDABLE_DEVICE { 2 };
constexpr char FOLDABLE_ROTATE  { '0' };
constexpr int32_t SUBSCRIPT_TWO { 2 };
constexpr int32_t SUBSCRIPT_ZERO { 0 };
constexpr std::string_view SCREEN_READING { "accessibility_screenreader_enabled" };
constexpr std::string_view SCREEN_READ_ENABLE { "1" };
} // namespace

KnuckleDrawingManager::KnuckleDrawingManager()
{
    paint_.SetColor(Rosen::Drawing::Color::COLOR_CYAN);
    paint_.SetAntiAlias(true);
    float outerCircleTransparency = 1.0f;
    paint_.SetAlphaF(outerCircleTransparency);
    paint_.SetWidth(PAINT_STROKE_WIDTH);
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
    CreateObserver();
    int32_t touchAction = touchEvent->GetPointerAction();
    if (IsValidAction(touchAction) && IsSingleKnuckleDoubleClick(touchEvent)) {
        int32_t displayId = touchEvent->GetTargetDisplayId();
        CreateTouchWindow(displayId);
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
        MMI_HILOGD("Touch tool type is:%{public}d", item.GetToolType());
        if (!pointerInfos_.empty()) {
            DestoryWindow();
        } else if (isRotate_) {
            isRotate_ = false;
            if (item.GetToolType() == PointerEvent::TOOL_TYPE_KNUCKLE) {
                return true;
            }
        }
        return false;
    }
    MMI_HILOGD("Touch tool type is single knuckle");
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
    if (screenReadState_.state == SCREEN_READ_ENABLE) {
        DestoryWindow();
    }
    if (action == PointerEvent::POINTER_ACTION_DOWN || action == PointerEvent::POINTER_ACTION_PULL_DOWN ||
        (action == PointerEvent::POINTER_ACTION_MOVE && (!pointerInfos_.empty())) ||
        (action == PointerEvent::POINTER_ACTION_PULL_MOVE && (!pointerInfos_.empty())) ||
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP) {
        return true;
    }
    MMI_HILOGE("Action is not down or move or up, action:%{public}d", action);
    return false;
}

void KnuckleDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
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

void KnuckleDrawingManager::StartTouchDraw(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t ret = DrawGraphic(touchEvent);
    if (ret != RET_OK) {
        MMI_HILOGD("Can't get enough pointers to draw");
        return;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDrawingManager::RotationCanvasNode(
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode, const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvasNode);
    if (displayInfo.direction == Direction::DIRECTION90) {
        canvasNode->SetRotation(ROTATION_ANGLE_270);
        canvasNode->SetTranslateX(0);
    } else if (displayInfo.direction == Direction::DIRECTION270) {
        canvasNode->SetRotation(ROTATION_ANGLE_90);
        canvasNode->SetTranslateX(-std::fabs(displayInfo.width - displayInfo.height));
    } else if (displayInfo.direction == Direction::DIRECTION180) {
        canvasNode->SetRotation(ROTATION_ANGLE_180);
        canvasNode->SetTranslateX(-std::fabs(displayInfo.width - displayInfo.height));
    } else {
        canvasNode->SetRotation(ROTATION_ANGLE_0);
        canvasNode->SetTranslateX(0);
    }
    canvasNode->SetTranslateY(0);
}

bool KnuckleDrawingManager::CheckRotatePolicy(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    bool isNeedRotate = false;
    switch (ROTATE_POLICY) {
        case WINDOW_ROTATE:
            isNeedRotate = true;
            break;
        case SCREEN_ROTATE:
            break;
        case FOLDABLE_DEVICE: {
            MMI_HILOGI("FOLDABLE:%{public}s", FOLDABLE.c_str());
            if ((displayInfo.displayMode == DisplayMode::MAIN && FOLDABLE[SUBSCRIPT_ZERO] == FOLDABLE_ROTATE) ||
                (displayInfo.displayMode == DisplayMode::FULL && FOLDABLE[SUBSCRIPT_TWO] == FOLDABLE_ROTATE)) {
                isNeedRotate = true;
            }
            break;
        }
        default:
            MMI_HILOGW("Unknown ROTATE_POLICY:%{public}d", ROTATE_POLICY);
            break;
    }
    return isNeedRotate;
}

void KnuckleDrawingManager::CreateTouchWindow(const int32_t displayId)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGD("surfaceNode_ is already exist");
        return;
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "knuckle window";
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
    if (CheckRotatePolicy(displayInfo_)) {
        RotationCanvasNode(canvasNode_, displayInfo_);
    }
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void KnuckleDrawingManager::CreateCanvasNode()
{
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
    pointerInfo.x = pointerItem.GetDisplayX();
    pointerInfo.y = pointerItem.GetDisplayY();
    pointerInfos_.push_back(pointerInfo);

    if (pointerInfos_.size() == MAX_POINTER_NUM) {
        pointerInfos_[POINT_INDEX3].x = (pointerInfos_[POINT_INDEX2].x + pointerInfos_[POINT_INDEX4].x) / MID_POINT;
        pointerInfos_[POINT_INDEX3].y = (pointerInfos_[POINT_INDEX2].y + pointerInfos_[POINT_INDEX4].y) / MID_POINT;
    } else {
        MMI_HILOGD("Can't get enough pointers to draw");
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
        MMI_HILOGD("GetPointerPos failed");
        return RET_ERR;
    }
    if (!isActionUp_) {
        path_.MoveTo(pointerInfos_[POINT_INDEX0].x, pointerInfos_[POINT_INDEX0].y);
        path_.CubicTo(pointerInfos_[POINT_INDEX1].x, pointerInfos_[POINT_INDEX1].y,
            pointerInfos_[POINT_INDEX2].x, pointerInfos_[POINT_INDEX2].y,
            pointerInfos_[POINT_INDEX3].x, pointerInfos_[POINT_INDEX3].y);
#ifndef USE_ROSEN_DRAWING
        auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
            BeginRecording(scaleW_, scaleH_));
#else
        auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
            BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
        CHKPR(canvas, RET_ERR);
        canvas->AttachPaint(paint_);
        bool startDraw = (touchEvent->GetActionTime() - firstDownTime_) > WAIT_DOUBLE_CLICK_INTERVAL_TIME;
        if (startDraw) {
            canvas->DrawPath(path_);
        }
        canvas->DetachPaint();
        pointerInfos_.erase(pointerInfos_.begin(), pointerInfos_.begin() + POINT_INDEX3);
    } else {
        MMI_HILOGD("isActionUp_ is true");
        isActionUp_ = false;
        return DestoryWindow();
    }
    path_.Reset();
    canvasNode_->FinishRecording();
    return RET_OK;
}

int32_t KnuckleDrawingManager::DestoryWindow()
{
    CALL_DEBUG_ENTER;
    pointerInfos_.clear();
    CHKPR(canvasNode_, RET_ERR);
#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
    CHKPR(canvas, RET_ERR);
    canvas->Clear();
    canvasNode_->FinishRecording();
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    canvasNode_.reset();
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_.reset();
    Rosen::RSTransaction::FlushImplicitTransaction();
    return RET_OK;
}

void KnuckleDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasScreenReadObserver_) {
        screenReadState_.switchName = SCREEN_READING;
        CreateScreenReadObserver(screenReadState_);
        hasScreenReadObserver_ = true;
    }
    MMI_HILOGD("screenReadState_.state: %{public}s", screenReadState_.state.c_str());
}

template <class T>
void KnuckleDrawingManager::CreateScreenReadObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetStringValue(key, item.state);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("key: %{public}s, state: %{public}s", key.c_str(), item.state.c_str());
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

std::string KnuckleDrawingManager::GetScreenReadState()
{
    return screenReadState_.state;
}
} // namespace MMI
} // namespace OHOS