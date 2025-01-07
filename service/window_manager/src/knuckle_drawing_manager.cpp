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

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "animation/rs_particle_params.h"
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
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
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "timer_manager.h"
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
#include "touch_drawing_manager.h"

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
[[ maybe_unused ]] constexpr int64_t WAIT_DOUBLE_CLICK_INTERVAL_TIME { 100000 };
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG { 96.0f };
[[ maybe_unused ]] constexpr float VPR_CONFIG { 3.25f };
constexpr int32_t POW_SQUARE { 2 };
constexpr int32_t ROTATION_ANGLE_0 { 0 };
constexpr int32_t ROTATION_ANGLE_90 { 90 };
constexpr int32_t ROTATION_ANGLE_180 { 180 };
constexpr int32_t ROTATION_ANGLE_270 { 270 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
constexpr std::string_view SCREEN_READING { "accessibility_screenreader_enabled" };
constexpr std::string_view SCREEN_READ_ENABLE { "1" };
constexpr int32_t POINTER_NUMBER_TO_DRAW { 10 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
constexpr int64_t PARTICLE_LIFE_TIME { 700 };
constexpr int32_t PARTICLE_COUNT { -1 };
constexpr int32_t DEFAULT_EMIT_RATE { 0 };
constexpr int32_t EMIT_RATE { 400 };
constexpr int32_t PATH_SIZE_EIGHT { 8 };
constexpr int32_t MAX_PATH_SIZE { 50 };
constexpr int32_t MAX_PATH_LENGTH { 500 };
constexpr float PARTICLE_RADIUS { 5.0f };
constexpr float DEFAULT_PARTICLE_POSITION_X { 0.0f };
constexpr float DEFAULT_PARTICLE_POSITION_Y { 0.0f };
constexpr float DEFAULT_EMIT_SIZE_RANGE_BEGIN { 0.0f };
constexpr float DEFAULT_EMIT_SIZE_RANGE_END { 0.0f };
constexpr float EMIT_SIZE_RANGE_BEGIN { 80.0f };
constexpr float EMIT_SIZE_RANGE_END { 80.0f };
constexpr float EMIT_VELOCITY_VALUE_RANGE_BEGIN { 50.0f };
constexpr float EMIT_VELOCITY_VALUE_RANGE_END { 100.0f };
constexpr float EMIT_VELOCITY_ANGLE_RANGE_BEGIN { -180.0f };
constexpr float EMIT_VELOCITY_ANGLE_RANGE_END { 180.0f };
constexpr float EMIT_OPACITY_RANGE_BEGIN { 0.3f };
constexpr float EMIT_OPACITY_RANGE_END { 1.0f };
constexpr float EMIT_SCALE_RANGE_BEGIN { 0.3f };
constexpr float EMIT_SCALE_RANGE_END { 1.0f };
constexpr float EMIT_SCALE_CHANGE_RANGE_BEGIN { 1.0f };
constexpr float EMIT_SCALE_CHANGE_RANGE_END { 0.0f };
constexpr float SCALE_CHANGE_VELOCITY_RANGE_BEGIN { -1.0f };
constexpr float SCALE_CHANGE_VELOCITY_RANGE_END { -1.0f };
constexpr int32_t SCALE_CHANGE_START_MILLIS { 0 };
constexpr int32_t SCALE_CHANGE_END_MILLIS { 700 };
constexpr float ALPHA_RANGE_BEGIN { 1.0f };
constexpr float ALPHA_RANGE_END { 0.0f };
constexpr float EMIT_RADIUS { 40.0f };
constexpr float TRACK_FILTER_SCALAR { 20.0f };
constexpr int32_t TRACK_PATH_LENGTH_400 { 400 };
constexpr int32_t TRACK_PATH_LENGTH_500 { 500 };
constexpr int32_t TRACK_PATH_LENGTH_900 { 900 };
constexpr int32_t TRACK_PATH_LENGTH_1000 { 1000 };
constexpr int32_t TRACK_PATH_LENGTH_1400 { 1400 };
constexpr int32_t TRACK_PATH_LENGTH_1500 { 1500 };
constexpr int32_t TRACK_PATH_LENGTH_1900 { 1900 };
constexpr int32_t TRACK_PATH_LENGTH_2000 { 2000 };
constexpr uint32_t TRACK_COLOR_BLUE { 0xFF1ED0EE };
constexpr uint32_t TRACK_COLOR_BLUE_R { 0x1E };
constexpr uint32_t TRACK_COLOR_BLUE_G { 0xD0 };
constexpr uint32_t TRACK_COLOR_BLUE_B { 0xEE };
constexpr uint32_t TRACK_COLOR_PINK { 0xFFFF42D2 };
constexpr uint32_t TRACK_COLOR_PINK_R { 0xFF };
constexpr uint32_t TRACK_COLOR_PINK_G { 0x42 };
constexpr uint32_t TRACK_COLOR_PINK_B { 0xD2 };
constexpr uint32_t TRACK_COLOR_ORANGE_RED { 0xFFFF7B47 };
constexpr uint32_t TRACK_COLOR_ORANGE_RED_R { 0xFF };
constexpr uint32_t TRACK_COLOR_ORANGE_RED_G { 0x7B };
constexpr uint32_t TRACK_COLOR_ORANGE_RED_B { 0x47 };
constexpr uint32_t TRACK_COLOR_YELLOW { 0xFFFFC628 };
constexpr uint32_t TRACK_COLOR_YELLOW_R { 0xFF };
constexpr uint32_t TRACK_COLOR_YELLOW_G { 0xC6 };
constexpr uint32_t TRACK_COLOR_YELLOW_B { 0x28 };
constexpr uint32_t ALPHA_ZERO { 0xFF };
constexpr float TRACK_WIDTH_TEN { 10.0f };
constexpr float TRACK_WIDTH_THIRTY { 30.0f };
constexpr float COLOR_TRANSITIONS_LENGTH { 400.0f };
constexpr int32_t PROTOCOL_DURATION { 200 };
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
} // namespace

KnuckleDrawingManager::KnuckleDrawingManager()
{
#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
    paint_.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
#else
    paint_.SetColor(Rosen::Drawing::Color::COLOR_CYAN);
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
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
        pointerNum_ = 0;
        firstDownTime_ = touchEvent->GetActionTime();
        int64_t intervalTime = touchEvent->GetActionTime() - lastUpTime_;
        bool isTimeIntervalReady = intervalTime > 0 && intervalTime <= DOUBLE_CLICK_INTERVAL_TIME_SLOW;
        int32_t id = touchEvent->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        touchEvent->GetPointerItem(id, pointerItem);
        auto displayXY = TOUCH_DRAWING_MGR->CalcDrawCoordinate(displayInfo_, pointerItem);
        float downToPrevDownDistance = static_cast<float>(sqrt(pow(lastDownPointer_.x - displayXY.first, POW_SQUARE) +
            pow(lastDownPointer_.y - displayXY.second, POW_SQUARE)));
        bool isDistanceReady = downToPrevDownDistance < DOUBLE_CLICK_DISTANCE_LONG_CONFIG * POW_SQUARE;
        if (isTimeIntervalReady && isDistanceReady) {
            return false;
        }
        lastDownPointer_.x = displayXY.first;
        lastDownPointer_.y = displayXY.second;
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
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP ||
        action == PointerEvent::POINTER_ACTION_CANCEL) {
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
    Direction displayDirection = static_cast<Direction>((
        ((displayInfo.direction - displayInfo.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    if (displayDirection == Direction::DIRECTION90) {
        canvasNode->SetRotation(ROTATION_ANGLE_270);
        canvasNode->SetTranslateX(0);
    } else if (displayDirection == Direction::DIRECTION270) {
        canvasNode->SetRotation(ROTATION_ANGLE_90);
        canvasNode->SetTranslateX(-std::fabs(displayInfo.width - displayInfo.height));
    } else if (displayDirection == Direction::DIRECTION180) {
        canvasNode->SetRotation(ROTATION_ANGLE_180);
        canvasNode->SetTranslateX(-std::fabs(displayInfo.width - displayInfo.height));
    } else {
        canvasNode->SetRotation(ROTATION_ANGLE_0);
        canvasNode->SetTranslateX(0);
    }
    canvasNode->SetTranslateY(0);
}

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
void KnuckleDrawingManager::InitParticleEmitter()
{
    CALL_DEBUG_ENTER;
    Rosen::Vector2f position = {DEFAULT_PARTICLE_POSITION_X, DEFAULT_PARTICLE_POSITION_Y};
    Rosen::Vector2f emitSize = {DEFAULT_EMIT_SIZE_RANGE_BEGIN, DEFAULT_EMIT_SIZE_RANGE_END};
    Rosen::Range<int64_t> lifeTime = {PARTICLE_LIFE_TIME, PARTICLE_LIFE_TIME};
    std::shared_ptr<Rosen::RSImage> image = std::make_shared<Rosen::RSImage>();
    Rosen::EmitterConfig emitterConfig(
        DEFAULT_EMIT_RATE, Rosen::ShapeType::CIRCLE, position, emitSize, PARTICLE_COUNT, lifeTime,
        Rosen::ParticleType::POINTS, PARTICLE_RADIUS, image, Rosen::Vector2f());

    Rosen::Range<float> velocityValue = {EMIT_VELOCITY_VALUE_RANGE_BEGIN, EMIT_VELOCITY_VALUE_RANGE_END};
    Rosen::Range<float> velocityAngle = {EMIT_VELOCITY_ANGLE_RANGE_BEGIN, EMIT_VELOCITY_ANGLE_RANGE_END};
    Rosen::ParticleVelocity velocity(velocityValue, velocityAngle);

    std::vector<Rosen::Change<Rosen::RSColor>> valColorChangeOverLife;
    Rosen::RSColor rsColorRangeBegin(Rosen::Drawing::Color::COLOR_WHITE);
    Rosen::RSColor rsColorRangeEnd(Rosen::Drawing::Color::COLOR_WHITE);
    Rosen::Range<Rosen::RSColor> colorVal = {rsColorRangeBegin, rsColorRangeEnd};
    Rosen::ParticleColorParaType color(
        colorVal, Rosen::DistributionType::UNIFORM, Rosen::ParticleUpdator::NONE, Rosen::Range<float>(),
        Rosen::Range<float>(), Rosen::Range<float>(), Rosen::Range<float>(), valColorChangeOverLife);

    std::vector<Rosen::Change<float>> opacityChangeOverLifes;
    Rosen::Range<float> opacityVal = {EMIT_OPACITY_RANGE_BEGIN, EMIT_OPACITY_RANGE_END};
    Rosen::ParticleParaType<float> opacity(
        opacityVal, Rosen::ParticleUpdator::NONE, Rosen::Range<float>(), opacityChangeOverLifes);

    Rosen::RSAnimationTimingCurve rSAnimationTimingCurve(Rosen::RSAnimationTimingCurve::LINEAR);
    Rosen::Change<float> scaleChange
        (EMIT_SCALE_CHANGE_RANGE_BEGIN, EMIT_SCALE_CHANGE_RANGE_END, SCALE_CHANGE_START_MILLIS, SCALE_CHANGE_END_MILLIS,
        rSAnimationTimingCurve);
    std::vector<Rosen::Change<float>> scaleChangeOverLifes;
    scaleChangeOverLifes.emplace_back(scaleChange);
    Rosen::Range<float> scaleVal = {EMIT_SCALE_RANGE_BEGIN, EMIT_SCALE_RANGE_END};
    Rosen::Range<float> scaleChangeVelocity = {SCALE_CHANGE_VELOCITY_RANGE_BEGIN, SCALE_CHANGE_VELOCITY_RANGE_END};
    Rosen::ParticleParaType<float> scale(
        scaleVal, Rosen::ParticleUpdator::CURVE, scaleChangeVelocity, scaleChangeOverLifes);

    Rosen::ParticleAcceleration acceleration;
    Rosen::ParticleParaType<float> spin;

    Rosen::ParticleParams params(emitterConfig, velocity, acceleration, color, opacity, scale, spin);
    std::vector<Rosen::ParticleParams> particleParams;
    particleParams.push_back(params);
    CHKPV(brushCanvasNode_);
    brushCanvasNode_->SetParticleParams(particleParams);
    isNeedInitParticleEmitter_ = false;
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
    surfaceNode_->SetSnapshotSkipLayer(true);
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
    CreateBrushWorkCanvasNode();
    CreateTrackCanvasNode();
    surfaceNode_->AddChild(trackCanvasNode_, DEFAULT_VALUE);
    surfaceNode_->AddChild(brushCanvasNode_, DEFAULT_VALUE);
    if (displayInfo_.displayMode == DisplayMode::MAIN) {
        screenId_ = FOLD_SCREEN_MAIN_ID;
    }
    MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
    surfaceNode_->AttachToDisplay(screenId_);
    RotationCanvasNode(brushCanvasNode_, displayInfo_);
    RotationCanvasNode(trackCanvasNode_, displayInfo_);
    brushCanvasNode_->ResetSurface(scaleW_, scaleH_);
    trackCanvasNode_->ResetSurface(scaleW_, scaleH_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}
#else
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
    surfaceNode_->SetSnapshotSkipLayer(true);
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
    MMI_HILOGI("The screenId_:%{public}" PRIu64, screenId_);
    surfaceNode_->AttachToDisplay(screenId_);
    RotationCanvasNode(canvasNode_, displayInfo_);
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
void KnuckleDrawingManager::CreateBrushWorkCanvasNode()
{
    brushCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    CHKPV(brushCanvasNode_);
    brushCanvasNode_->SetBounds(0, 0, scaleW_, scaleH_);
    brushCanvasNode_->SetFrame(0, 0, scaleW_, scaleH_);

#ifndef USE_ROSEN_DRAWING
    brushCanvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    brushCanvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING
    brushCanvasNode_->SetCornerRadius(1);
    brushCanvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    brushCanvasNode_->SetRotation(0);
    brushCanvasNode_->SetAlpha(ALPHA_RANGE_BEGIN);
}

void KnuckleDrawingManager::CreateTrackCanvasNode()
{
    trackCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    CHKPV(trackCanvasNode_);
    trackCanvasNode_->SetBounds(0, 0, scaleW_, scaleH_);
    trackCanvasNode_->SetFrame(0, 0, scaleW_, scaleH_);

#ifndef USE_ROSEN_DRAWING
    trackCanvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    trackCanvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif // USE_ROSEN_DRAWING
    trackCanvasNode_->SetCornerRadius(1);
    trackCanvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    trackCanvasNode_->SetRotation(0);
    trackCanvasNode_->SetAlpha(ALPHA_RANGE_BEGIN);
}
#else
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
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

int32_t KnuckleDrawingManager::GetPointerPos(std::shared_ptr<PointerEvent> touchEvent)
{
    CHKPR(touchEvent, RET_ERR);
    if (touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
        touchEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) {
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
    auto displayXY = TOUCH_DRAWING_MGR->CalcDrawCoordinate(displayInfo_, pointerItem);
    pointerInfo.x = displayXY.first;
    pointerInfo.y = displayXY.second;
    pointerInfos_.push_back(pointerInfo);
    pointerNum_++;

    if (pointerInfos_.size() == MAX_POINTER_NUM) {
        pointerInfos_[POINT_INDEX3].x = (pointerInfos_[POINT_INDEX2].x + pointerInfos_[POINT_INDEX4].x) / MID_POINT;
        pointerInfos_[POINT_INDEX3].y = (pointerInfos_[POINT_INDEX2].y + pointerInfos_[POINT_INDEX4].y) / MID_POINT;
    } else {
        MMI_HILOGD("Can't get enough pointers to draw");
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
void KnuckleDrawingManager::UpdateEmitter()
{
    CALL_DEBUG_ENTER;
    CHKPV(brushCanvasNode_);
    std::optional<Rosen::Vector2f> position = std::nullopt;
    position = {pointerInfos_[POINT_INDEX1].x - EMIT_RADIUS, pointerInfos_[POINT_INDEX1].y - EMIT_RADIUS};
    std::optional<Rosen::Vector2f> emitSize = std::nullopt;
    emitSize = {EMIT_SIZE_RANGE_BEGIN, EMIT_SIZE_RANGE_END};
    std::optional<int32_t> emitRate = std::nullopt;
    emitRate = EMIT_RATE;
    auto updater = std::make_shared<Rosen::EmitterUpdater>(
        0, position, emitSize, emitRate);
    std::vector<std::shared_ptr<Rosen::EmitterUpdater>> paras;
    paras.push_back(updater);
    brushCanvasNode_->SetEmitterUpdater(paras);
}

uint32_t KnuckleDrawingManager::GetDeltaColor(uint32_t deltaSource, uint32_t deltaTarget)
{
    CALL_DEBUG_ENTER;
    if (deltaTarget > deltaSource) {
        MMI_HILOGE("Invalid deltaSource or deltaTarget");
        return 0;
    } else {
        return deltaSource - deltaTarget;
    }
}

uint32_t KnuckleDrawingManager::DrawTrackColorBlue(int32_t pathValue)
{
    CALL_DEBUG_ENTER;
    if (((static_cast<int32_t>(pathLength_) / TRACK_PATH_LENGTH_2000) != 0) &&
        (pathValue < TRACK_PATH_LENGTH_400)) {
        uint32_t deltaR = GetDeltaColor(TRACK_COLOR_YELLOW_R, TRACK_COLOR_BLUE_R);
        uint32_t deltaG = GetDeltaColor(TRACK_COLOR_BLUE_G, TRACK_COLOR_YELLOW_G);
        uint32_t deltaB = GetDeltaColor(TRACK_COLOR_BLUE_B, TRACK_COLOR_YELLOW_B);
        float pathLength = path_.GetLength(false);
        trackColorR_ -= deltaR * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorG_ += deltaG * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorB_ += deltaB * pathLength / COLOR_TRANSITIONS_LENGTH;
        uint32_t colorQuad = Rosen::Drawing::Color::ColorQuadSetARGB(
            ALPHA_ZERO, trackColorR_, trackColorG_, trackColorB_);
        return colorQuad;
    } else {
        trackColorR_ = TRACK_COLOR_BLUE_R;
        trackColorG_ = TRACK_COLOR_BLUE_G;
        trackColorB_ = TRACK_COLOR_BLUE_B;
        return TRACK_COLOR_BLUE;
    }
}

uint32_t KnuckleDrawingManager::DrawTrackColorPink(int32_t pathValue)
{
    CALL_DEBUG_ENTER;
    if (pathValue < TRACK_PATH_LENGTH_900) {
        uint32_t deltaR = GetDeltaColor(TRACK_COLOR_PINK_R, TRACK_COLOR_BLUE_R);
        uint32_t deltaG = GetDeltaColor(TRACK_COLOR_BLUE_G, TRACK_COLOR_PINK_G);
        uint32_t deltaB = GetDeltaColor(TRACK_COLOR_BLUE_B, TRACK_COLOR_PINK_B);
        float pathLength = path_.GetLength(false);
        trackColorR_ += deltaR * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorG_ -= deltaG * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorB_ -= deltaB * pathLength / COLOR_TRANSITIONS_LENGTH;
        uint32_t colorQuad = Rosen::Drawing::Color::ColorQuadSetARGB(
            ALPHA_ZERO, trackColorR_, trackColorG_, trackColorB_);
        return colorQuad;
    } else {
        trackColorR_ = TRACK_COLOR_PINK_R;
        trackColorG_ = TRACK_COLOR_PINK_G;
        trackColorB_ = TRACK_COLOR_PINK_B;
        return TRACK_COLOR_PINK;
    }
}

uint32_t KnuckleDrawingManager::DrawTrackColorOrangeRed(int32_t pathValue)
{
    CALL_DEBUG_ENTER;
    if (pathValue < TRACK_PATH_LENGTH_1400) {
        uint32_t deltaR = GetDeltaColor(TRACK_COLOR_ORANGE_RED_R, TRACK_COLOR_PINK_R);
        uint32_t deltaG = GetDeltaColor(TRACK_COLOR_ORANGE_RED_G, TRACK_COLOR_PINK_G);
        uint32_t deltaB = GetDeltaColor(TRACK_COLOR_PINK_B, TRACK_COLOR_ORANGE_RED_B);
        float pathLength = path_.GetLength(false);
        trackColorR_ += deltaR * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorG_ += deltaG * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorB_ -= deltaB * pathLength / COLOR_TRANSITIONS_LENGTH;
        uint32_t colorQuad = Rosen::Drawing::Color::ColorQuadSetARGB(
            ALPHA_ZERO, trackColorR_, trackColorG_, trackColorB_);
        return colorQuad;
    } else {
        trackColorR_ = TRACK_COLOR_ORANGE_RED_R;
        trackColorG_ = TRACK_COLOR_ORANGE_RED_G;
        trackColorB_ = TRACK_COLOR_ORANGE_RED_B;
        return TRACK_COLOR_ORANGE_RED;
    }
}

uint32_t KnuckleDrawingManager::DrawTrackColorYellow(int32_t pathValue)
{
    CALL_DEBUG_ENTER;
    if (pathValue < TRACK_PATH_LENGTH_1900) {
        uint32_t deltaR = GetDeltaColor(TRACK_COLOR_YELLOW_R, TRACK_COLOR_ORANGE_RED_R);
        uint32_t deltaG = GetDeltaColor(TRACK_COLOR_YELLOW_G, TRACK_COLOR_ORANGE_RED_G);
        uint32_t deltaB = GetDeltaColor(TRACK_COLOR_ORANGE_RED_B, TRACK_COLOR_YELLOW_B);
        float pathLength = path_.GetLength(false);
        trackColorR_ += deltaR * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorG_ += deltaG * pathLength / COLOR_TRANSITIONS_LENGTH;
        trackColorB_ -= deltaB * pathLength / COLOR_TRANSITIONS_LENGTH;
        uint32_t colorQuad = Rosen::Drawing::Color::ColorQuadSetARGB(
            ALPHA_ZERO, trackColorR_, trackColorG_, trackColorB_);
        return colorQuad;
    } else {
        trackColorR_ = TRACK_COLOR_YELLOW_R;
        trackColorG_ = TRACK_COLOR_YELLOW_G;
        trackColorB_ = TRACK_COLOR_YELLOW_B;
        return TRACK_COLOR_YELLOW;
    }
}

void KnuckleDrawingManager::DrawTrackCanvas()
{
    CALL_DEBUG_ENTER;
    CHKPV(trackCanvasNode_);
#ifndef USE_ROSEN_DRAWING
    auto trackCanvas = static_cast<Rosen::RSRecordingCanvas *>(trackCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto trackCanvas = static_cast<Rosen::Drawing::RecordingCanvas *>(trackCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
    CHKPV(trackCanvas);
    pathLength_ += path_.GetLength(false);
    int32_t pathValue = static_cast<int32_t>(pathLength_) % TRACK_PATH_LENGTH_2000;
    Rosen::Drawing::Pen pen;

    if (pathValue < TRACK_PATH_LENGTH_500) {
        pen.SetColor(DrawTrackColorBlue(pathValue));
    } else if (pathValue < TRACK_PATH_LENGTH_1000) {
        pen.SetColor(DrawTrackColorPink(pathValue));
    } else if (pathValue < TRACK_PATH_LENGTH_1500) {
        pen.SetColor(DrawTrackColorOrangeRed(pathValue));
    } else {
        pen.SetColor(DrawTrackColorYellow(pathValue));
    }
    pen.SetWidth(PAINT_STROKE_WIDTH);
    Rosen::Drawing::Filter filter;
    filter.SetMaskFilter(
        Rosen::Drawing::MaskFilter::CreateBlurMaskFilter(Rosen::Drawing::BlurType::OUTER, TRACK_FILTER_SCALAR));
    pen.SetFilter(filter);
    trackCanvas->AttachPen(pen);
    trackCanvas->DrawPath(path_);
    trackCanvas->DetachPen();

    trackCanvas->AttachPaint(paint_);
    trackCanvas->DrawPath(path_);
    trackCanvas->DetachPaint();
    trackCanvasNode_->FinishRecording();
}

void KnuckleDrawingManager::DrawBrushCanvas()
{
    if (pathInfos_.size() >= PATH_SIZE_EIGHT) {
        brushPathLength_ += path_.GetLength(false);
        float pathLength = pathInfos_[0].GetLength(false);
        if (((brushPathLength_ - pathLength) > MAX_PATH_LENGTH) || (pathInfos_.size() >= MAX_PATH_SIZE)) {
            pathInfos_.erase(pathInfos_.begin());
            brushPathLength_ -= pathLength;
        }
        pathInfos_.emplace_back(path_);
        CHKPV(brushCanvasNode_);
        brushCanvasNode_->ResetSurface(scaleW_, scaleH_);

#ifndef USE_ROSEN_DRAWING
        auto canvas = static_cast<Rosen::RSRecordingCanvas *>(brushCanvasNode_->
            BeginRecording(scaleW_, scaleH_));
#else
        auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(brushCanvasNode_->
            BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
        CHKPV(canvas);
        for (size_t i = 0; (i < pathInfos_.size()) && (pathInfos_.size() != 1); ++i) {
            Rosen::Drawing::Paint paint;
            paint.SetAntiAlias(true);
            paint.SetStyle(Rosen::Drawing::Paint::PaintStyle::PAINT_STROKE);
            paint.SetJoinStyle(Rosen::Drawing::Pen::JoinStyle::ROUND_JOIN);
            paint.SetCapStyle(Rosen::Drawing::Pen::CapStyle::ROUND_CAP);

            paint.SetWidth(TRACK_WIDTH_THIRTY / (pathInfos_.size() - 1) * i + TRACK_WIDTH_TEN);
            paint.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
            canvas->AttachPaint(paint);
            canvas->DrawPath(pathInfos_[i]);
            canvas->DetachPaint();
        }
        brushCanvasNode_->FinishRecording();
    } else {
        pathInfos_.emplace_back(path_);
        brushPathLength_ += path_.GetLength(false);
    }
}

void KnuckleDrawingManager::ActionUpAnimation()
{
    CALL_DEBUG_ENTER;
    CHKPV(trackCanvasNode_);
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(PROTOCOL_DURATION);
    protocol.SetRepeatCount(1);
    auto animate = Rosen::RSNode::Animate(
        protocol,
        Rosen::RSAnimationTimingCurve::LINEAR,
        [this]() {
            trackCanvasNode_->SetAlpha(ALPHA_RANGE_END);
        });
    Rosen::RSTransaction::FlushImplicitTransaction();
}

int32_t KnuckleDrawingManager::ProcessUpEvent(bool isNeedUpAnimation)
{
    CALL_DEBUG_ENTER;
    isActionUp_ = false;
    isNeedInitParticleEmitter_ = true;
    pathInfos_.clear();
    pathLength_ = 0.0f;
    brushPathLength_ = 0.0f;
    trackColorR_ = 0x00;
    trackColorG_ = 0x00;
    trackColorB_ = 0x00;
    if (ClearBrushCanvas() != RET_OK) {
        MMI_HILOGE("ClearBrushCanvas failed");
        return RET_ERR;
    }
    if (isNeedUpAnimation) {
        ActionUpAnimation();
        int32_t repeatTime = 1;
        int32_t timerId = TimerMgr->AddTimer(PROTOCOL_DURATION, repeatTime, [this]() {
            DestoryWindow();
        });
        if (timerId < 0) {
            MMI_HILOGE("Add timer failed, timerId:%{public}d", timerId);
            DestoryWindow();
        }
    } else {
        DestoryWindow();
    }
    return RET_OK;
}

int32_t KnuckleDrawingManager::DrawGraphic(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(touchEvent, RET_ERR);
    if (GetPointerPos(touchEvent) != RET_OK) {
        MMI_HILOGD("GetPointerPos failed");
        return RET_ERR;
    }
    bool needDrawParticle = (touchEvent->GetActionTime() - firstDownTime_) > WAIT_DOUBLE_CLICK_INTERVAL_TIME;
    if (!isActionUp_) {
        if (needDrawParticle) {
            if (isNeedInitParticleEmitter_) {
                InitParticleEmitter();
            } else {
                UpdateEmitter();
            }
        }
        path_.MoveTo(pointerInfos_[POINT_INDEX0].x, pointerInfos_[POINT_INDEX0].y);
        path_.CubicTo(pointerInfos_[POINT_INDEX1].x, pointerInfos_[POINT_INDEX1].y,
            pointerInfos_[POINT_INDEX2].x, pointerInfos_[POINT_INDEX2].y,
            pointerInfos_[POINT_INDEX3].x, pointerInfos_[POINT_INDEX3].y);
        pointerInfos_.erase(pointerInfos_.begin(), pointerInfos_.begin() + POINT_INDEX3);
        if (pointerNum_ < POINTER_NUMBER_TO_DRAW) {
            MMI_HILOGE("Pointer number not enough to draw");
            return RET_ERR;
        }
        DrawTrackCanvas();
        DrawBrushCanvas();
    } else {
        MMI_HILOGE("isActionUp_ is true");
        return ProcessUpEvent(needDrawParticle);
    }
    path_.Reset();
    return RET_OK;
}
#else
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
        pointerInfos_.erase(pointerInfos_.begin(), pointerInfos_.begin() + POINT_INDEX3);
        if (pointerNum_ < POINTER_NUMBER_TO_DRAW) {
            return RET_ERR;
        }
#ifndef USE_ROSEN_DRAWING
        auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
            BeginRecording(scaleW_, scaleH_));
#else
        auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
            BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
        CHKPR(canvas, RET_ERR);
        canvas->AttachPaint(paint_);
        canvas->DrawPath(path_);
        canvas->DetachPaint();
    } else {
        MMI_HILOGD("isActionUp_ is true");
        isActionUp_ = false;
        return DestoryWindow();
    }
    path_.Reset();
    canvasNode_->FinishRecording();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
int32_t KnuckleDrawingManager::ClearTrackCanvas()
{
    CALL_DEBUG_ENTER;
    CHKPR(trackCanvasNode_, RET_ERR);
#ifndef USE_ROSEN_DRAWING
    auto trackCanvas = static_cast<Rosen::RSRecordingCanvas *>(trackCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto trackCanvas = static_cast<Rosen::Drawing::RecordingCanvas *>(trackCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
    CHKPR(trackCanvas, RET_ERR);
    trackCanvas->Clear();
    trackCanvasNode_->FinishRecording();
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_->RemoveChild(trackCanvasNode_);
    trackCanvasNode_->ResetSurface(scaleW_, scaleH_);
    trackCanvasNode_.reset();
    return RET_OK;
}

int32_t KnuckleDrawingManager::ClearBrushCanvas()
{
    CALL_DEBUG_ENTER;
    CHKPR(brushCanvasNode_, RET_ERR);
#ifndef USE_ROSEN_DRAWING
    auto brushCanvas = static_cast<Rosen::RSRecordingCanvas *>(brushCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#else
    auto brushCanvas = static_cast<Rosen::Drawing::RecordingCanvas *>(brushCanvasNode_->
        BeginRecording(scaleW_, scaleH_));
#endif // USE_ROSEN_DRAWING
    CHKPR(brushCanvas, RET_ERR);
    brushCanvas->Clear();
    brushCanvasNode_->FinishRecording();
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_->RemoveChild(brushCanvasNode_);
    brushCanvasNode_->ResetSurface(scaleW_, scaleH_);
    brushCanvasNode_.reset();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

#ifdef OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC
int32_t KnuckleDrawingManager::DestoryWindow()
{
    CALL_DEBUG_ENTER;
    pointerInfos_.clear();
    path_.Reset();
    ClearBrushCanvas();
    if (ClearTrackCanvas() != RET_OK) {
        MMI_HILOGE("ClearTrackCanvas failed");
        return RET_ERR;
    }
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_->DetachToDisplay(screenId_);
    surfaceNode_.reset();
    Rosen::RSTransaction::FlushImplicitTransaction();
    return RET_OK;
}
#else
int32_t KnuckleDrawingManager::DestoryWindow()
{
    CALL_DEBUG_ENTER;
    pointerInfos_.clear();
    path_.Reset();
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
    CHKPR(surfaceNode_, RET_ERR);
    surfaceNode_->DetachToDisplay(screenId_);
    surfaceNode_->RemoveChild(canvasNode_);
    canvasNode_->ResetSurface(scaleW_, scaleH_);
    canvasNode_.reset();
    surfaceNode_.reset();
    Rosen::RSTransaction::FlushImplicitTransaction();
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_NEW_KNUCKLE_DYNAMIC

void KnuckleDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasScreenReadObserver_) {
        screenReadState_.switchName = SCREEN_READING;
        CreateScreenReadObserver(screenReadState_);
    }
    MMI_HILOGD("screenReadState_.state:%{public}s", screenReadState_.state.c_str());
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
        MMI_HILOGI("The key:%{public}s, state:%{public}s", key.c_str(), item.state.c_str());
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.switchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
        return;
    }
    hasScreenReadObserver_ = true;
}

std::string KnuckleDrawingManager::GetScreenReadState()
{
    return screenReadState_.state;
}
} // namespace MMI
} // namespace OHOS