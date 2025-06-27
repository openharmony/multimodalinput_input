/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "touch_drawing_manager.h"

#include "bytrace_adapter.h"
#include "parameters.h"
#include "setting_datashare.h"

#include <system_ability_definition.h>
#include "input_windows_manager.h"
#include "table_dump.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
const static Rosen::Drawing::Color LABELS_DEFAULT_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(192, 255, 255, 255);
const static Rosen::Drawing::Color LABELS_RED_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(192, 255, 0, 0);
const static Rosen::Drawing::Color TRACKER_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 0, 96, 255);
const static Rosen::Drawing::Color POINTER_RED_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 255, 0, 0);
const static Rosen::Drawing::Color CROSS_HAIR_COLOR = Rosen::Drawing::Color::ColorQuadSetARGB(255, 0, 0, 192);
constexpr int32_t REPEAT_ONCE { 1 };
constexpr int32_t REPEAT_COOLING_TIME { 500 };
constexpr int32_t DENSITY_BASELINE { 160 };
constexpr int32_t INDEPENDENT_INNER_PIXELS { 20 };
constexpr int32_t INDEPENDENT_OUTER_PIXELS { 21 };
constexpr int32_t INDEPENDENT_WIDTH_PIXELS { 2 };
constexpr int32_t MULTIPLE_FACTOR { 10 };
constexpr int32_t CALCULATE_MIDDLE { 2 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t RECT_COUNT { 6 };
constexpr int32_t PHONE_RECT_TOP { 118 };
constexpr int32_t PAD_RECT_TOP { 0 };
constexpr int32_t RECT_HEIGHT { 40 };
constexpr int32_t TEXT_TOP { 30 };
constexpr int32_t PEN_WIDTH { 1 };
constexpr int32_t TOUCH_SLOP { 30 };
constexpr int32_t RECT_SPACEING { 1 };
constexpr int32_t THREE_PRECISION { 3 };
constexpr int32_t TWO_PRECISION { 2 };
constexpr int32_t ONE_PRECISION { 1 };
constexpr int32_t ROTATION_ANGLE_0 { 0 };
constexpr int32_t ROTATION_ANGLE_90 { 90 };
constexpr int32_t ROTATION_ANGLE_180 { 180 };
constexpr int32_t ROTATION_ANGLE_270 { 270 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
constexpr uint64_t FOLD_SCREEN_FULL_ID { 0 };
constexpr float TEXT_SIZE { 28.0f };
constexpr float TEXT_SCALE { 1.0f };
constexpr float TEXT_SKEW { 0.0f };
constexpr float INNER_CIRCLE_TRANSPARENCY { 0.6f };
constexpr float OUT_CIRCLE_TRANSPARENCY { 0.1f };
const std::string showCursorSwitchName { "settings.input.show_touch_hint" };
const std::string pointerPositionSwitchName { "settings.developer.show_touch_track" };
const std::string PRODUCT_TYPE = system::GetParameter("const.product.devicetype", "unknown");
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLDABLE_DEVICE_POLICY = system::GetParameter("const.window.foldabledevice.rotate_policy", "");
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr char ROTATE_WINDOW_ROTATE { '0' };
constexpr int32_t FOLDABLE_DEVICE { 2 };
constexpr int32_t ANGLE_90 { 90 };
constexpr int32_t ANGLE_360 { 360 };
const char* PRODUCT_PHONE { "phone" };
const char* PRODUCT_TYPE_PC = { "2in1" };
} // namespace

TouchDrawingManager::TouchDrawingManager()
{}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::Initialize()
{
    int32_t nRetries { 60 };
    SetupSettingObserver(nRetries);
}

void TouchDrawingManager::SetupSettingObserver(int32_t nRetries)
{
    if (HasDisplayInfo()) {
        CreateObserver();
        if (hasBubbleObserver_ && hasPointerObserver_) {
            return;
        }
    }
    if (nRetries <= 0) {
        MMI_HILOGE("Failed to setup setting observer after tens of retries");
        return;
    }
    auto timerId = TimerMgr->AddTimer(REPEAT_COOLING_TIME, REPEAT_ONCE, [this, nRetries]() {
        SetupSettingObserver(nRetries - 1);
    }, "TouchDrawingManager");
    if (timerId < 0) {
        MMI_HILOGE("AddTimer fail");
    }
}

bool TouchDrawingManager::HasDisplayInfo() const
{
    return ((scaleW_ != 0) && (scaleH_ != 0));
}

void TouchDrawingManager::RecordLabelsInfo()
{
    CHKPV(pointerEvent_);
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent_->GetPointerItem(currentPointerId_, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", currentPointerId_);
        return;
    }
    auto displayXY = WIN_MGR->CalcDrawCoordinate(displayInfo_, pointerItem);
    if (pointerItem.IsPressed()) {
        currentPt_.SetX(displayXY.first);
        currentPt_.SetY(displayXY.second);
        pressure_ = pointerItem.GetPressure();
    }
    if (isFirstDownAction_) {
        firstPt_.SetX(displayXY.first);
        firstPt_.SetY(displayXY.second);
        isFirstDownAction_ = false;
    }
    int64_t actionTime = pointerEvent_->GetActionTime();
    if (pointerEvent_->GetPointerId() == currentPointerId_ && !lastPointerItem_.empty()) {
        double diffTime = static_cast<double>(actionTime - lastActionTime_) / 1000;
        if (MMI_EQ(diffTime, 0.0)) {
            xVelocity_ = 0.0;
            yVelocity_ = 0.0;
        } else {
            auto diffX = currentPt_.GetX() - lastPt_.GetX();
            auto diffY = currentPt_.GetY() - lastPt_.GetY();
            xVelocity_ = diffX / diffTime;
            yVelocity_ = diffY / diffTime;
        }
        lastActionTime_ = actionTime;
    }
}

void TouchDrawingManager::TouchDrawHandler(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    pointerEvent_ = pointerEvent;
    CreateObserver();
    if (bubbleMode_.isShow) {
        CreateTouchWindow();
        AddCanvasNode(bubbleCanvasNode_, false);
        DrawBubbleHandler();
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP
        && pointerEvent->GetAllPointerItems().size() == 1) {
        lastPointerItem_.clear();
    }
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN
        && pointerEvent->GetAllPointerItems().size() == 1) {
        stopRecord_ = false;
    }
    if (pointerMode_.isShow && !stopRecord_) {
        CreateTouchWindow();
        AddCanvasNode(trackerCanvasNode_, true);
        AddCanvasNode(crosshairCanvasNode_, false);
        AddCanvasNode(labelsCanvasNode_, false, false);
        DrawPointerPositionHandler();
        lastPt_ = currentPt_;
    }
}

void TouchDrawingManager::UpdateDisplayInfo(const OLD::DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    isChangedRotation_ = displayInfo.direction == displayInfo_.direction ? false : true;
    isChangedMode_ = displayInfo.displayMode == displayInfo_.displayMode ? false : true;
    scaleW_ = displayInfo.validWidth > displayInfo.validHeight ? displayInfo.validWidth : displayInfo.validHeight;
    scaleH_ = displayInfo.validWidth > displayInfo.validHeight ? displayInfo.validWidth : displayInfo.validHeight;
    if (displayInfo.displaySourceMode != displayInfo_.displaySourceMode ||
        displayInfo.rsId != displayInfo_.rsId) {
        if (surfaceNode_ != nullptr) {
            surfaceNode_->ClearChildren();
            surfaceNode_.reset();
            isChangedMode_ = true;
        }
    }
    displayInfo_ = displayInfo;
    bubble_.innerCircleRadius = displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleRadius = displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleWidth = static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE;
    itemRectW_ = static_cast<double>(displayInfo_.validWidth) / RECT_COUNT;
    rectTopPosition_ = 0;
    if (IsWindowRotation()) {
        if (displayInfo_.direction == DIRECTION0 || displayInfo_.direction == DIRECTION180) {
            rectTopPosition_ = PRODUCT_TYPE == PRODUCT_PHONE ? PHONE_RECT_TOP : PAD_RECT_TOP;
        }
    } else {
        if (displayInfo_.direction == DIRECTION90 && PRODUCT_TYPE != PRODUCT_TYPE_PC) {
            rectTopPosition_ = PHONE_RECT_TOP;
        }
    }
    if (isChangedMode_) {
        if (trackerCanvasNode_ != nullptr) {
            trackerCanvasNode_.reset();
        }
        if (bubbleCanvasNode_ != nullptr) {
            bubbleCanvasNode_.reset();
        }
        if (crosshairCanvasNode_ != nullptr) {
            crosshairCanvasNode_.reset();
        }
        if (labelsCanvasNode_ != nullptr) {
            labelsCanvasNode_.reset();
        }
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
}

void TouchDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
    int32_t &physicalX, int32_t &physicalY)
{
    MMI_HILOGD("direction:%{public}d", direction);
    switch (direction) {
        case DIRECTION0: {
            break;
        }
        case DIRECTION90: {
            int32_t temp = physicalY;
            physicalY = width - physicalX;
            physicalX = temp;
            break;
        }
        case DIRECTION180: {
            physicalX = width - physicalX;
            physicalY = height - physicalY;
            break;
        }
        case DIRECTION270: {
            int32_t temp = physicalX;
            physicalX = height - physicalY;
            physicalY = temp;
            break;
        }
        default: {
            break;
        }
    }
}

int32_t TouchDrawingManager::UpdateLabels()
{
    CALL_DEBUG_ENTER;
    if (pointerMode_.isShow) {
        CreateTouchWindow();
        AddCanvasNode(labelsCanvasNode_, false, false);
        DrawLabels();
    } else {
        RemovePointerPosition();
        DestoryTouchWindow();
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    return RET_OK;
}

int32_t TouchDrawingManager::UpdateBubbleData()
{
    if (!bubbleMode_.isShow) {
        CHKPR(surfaceNode_, ERROR_NULL_POINTER);
        surfaceNode_->RemoveChild(bubbleCanvasNode_);
        bubbleCanvasNode_.reset();
        DestoryTouchWindow();
        Rosen::RSTransaction::FlushImplicitTransaction();
    }
    return RET_OK;
}

void TouchDrawingManager::RotationScreen()
{
    CALL_DEBUG_ENTER;
    if (!isChangedRotation_ && !isChangedMode_) {
        return;
    }

    if (pointerMode_.isShow) {
        RotationCanvasNode(trackerCanvasNode_);
        RotationCanvasNode(crosshairCanvasNode_);
    }
    if (bubbleMode_.isShow) {
        RotationCanvasNode(bubbleCanvasNode_);
    }

    if (pointerMode_.isShow && !isChangedMode_) {
        if (!lastPointerItem_.empty() || stopRecord_) {
            Snapshot();
        } else if (!stopRecord_) {
            UpdateLabels();
        }
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasBubbleObserver_) {
        MMI_HILOGI("Setup observer of show-touch-track");
        bubbleMode_.SwitchName = showCursorSwitchName;
        CreateBubbleObserver(bubbleMode_);
    }
    if (!hasPointerObserver_) {
        MMI_HILOGI("Setup observer of show-touch-position");
        pointerMode_.SwitchName = pointerPositionSwitchName;
        CreatePointerObserver(pointerMode_);
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
            GetBoolValue(pointerPositionSwitchName, pointerMode_.isShow);
    }
    MMI_HILOGD("The bubbleMode_:%{public}d, pointerMode_:%{public}d", bubbleMode_.isShow, pointerMode_.isShow);
}

template <class T>
void TouchDrawingManager::CreateBubbleObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item, this](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        CHKPV(delegateProxy_);
        delegateProxy_->OnPostSyncTask(std::bind(&TouchDrawingManager::UpdateBubbleData, this));
        MMI_HILOGI("The key:%{public}s, statusValue:%{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
        return;
    }
    hasBubbleObserver_ = true;
}

template <class T>
void TouchDrawingManager::CreatePointerObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item, this](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        CHKPV(delegateProxy_);
        delegateProxy_->OnPostSyncTask(std::bind(&TouchDrawingManager::UpdateLabels, this));
        MMI_HILOGI("The key:%{public}s, statusValue:%{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
        return;
    }
    hasPointerObserver_ = true;
}

template <class T>
std::string TouchDrawingManager::FormatNumber(T number, int32_t precision)
{
    std::string temp(".000");
    auto str = std::to_string(number);
    if (str.find(".") == std::string::npos) {
        str += temp;
    }
    return str.substr(0, str.find(".") + precision + 1);
}

void TouchDrawingManager::AddCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode, bool isTrackerNode,
    bool isNeedRotate)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    CHKPV(surfaceNode_);
    if (canvasNode != nullptr && screenId_ == static_cast<uint64_t>(displayInfo_.rsId)) {
        return;
    }
    MMI_HILOGI("Screen from:%{public}" PRIu64 " to :%{public}d", screenId_, displayInfo_.rsId);
    screenId_ = static_cast<uint64_t>(displayInfo_.rsId);
    canvasNode = isTrackerNode ? Rosen::RSCanvasDrawingNode::Create() : Rosen::RSCanvasNode::Create();
    canvasNode->SetBounds(0, 0, scaleW_, scaleH_);
    canvasNode->SetFrame(0, 0, scaleW_, scaleH_);
    surfaceNode_->SetBounds(0, 0, scaleW_, scaleH_);
    surfaceNode_->SetFrame(0, 0, scaleW_, scaleH_);
    if (isNeedRotate) {
        RotationCanvasNode(canvasNode);
    }
#ifndef USE_ROSEN_DRAWING
    canvasNode->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    canvasNode->SetCornerRadius(1);
    canvasNode->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    surfaceNode_->AddChild(canvasNode, DEFAULT_VALUE);
}

void TouchDrawingManager::RotationCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvasNode);
    Direction displayDirection = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    if (displayDirection == Direction::DIRECTION90) {
        canvasNode->SetRotation(ROTATION_ANGLE_270);
        canvasNode->SetTranslateX(0);
    } else if (displayDirection == Direction::DIRECTION270) {
        canvasNode->SetRotation(ROTATION_ANGLE_90);
        canvasNode->SetTranslateX(-std::fabs(displayInfo_.validWidth - displayInfo_.validHeight));
    } else if (displayDirection == Direction::DIRECTION180) {
        canvasNode->SetRotation(ROTATION_ANGLE_180);
        canvasNode->SetTranslateX(-std::fabs(displayInfo_.validWidth - displayInfo_.validHeight));
    } else {
        canvasNode->SetRotation(ROTATION_ANGLE_0);
        canvasNode->SetTranslateX(0);
    }
    canvasNode->SetTranslateY(0);
}

void TouchDrawingManager::ResetCanvasNode(std::shared_ptr<Rosen::RSCanvasNode> canvasNode)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvasNode);
    canvasNode->SetRotation(ROTATION_ANGLE_0);
    canvasNode->SetTranslateX(0);
    canvasNode->SetTranslateY(0);
}

void TouchDrawingManager::RotationCanvas(RosenCanvas *canvas, Direction direction)
{
    CHKPV(canvas);
    if (direction == Direction::DIRECTION90) {
        canvas->Translate(0, displayInfo_.validWidth);
        canvas->Rotate(ROTATION_ANGLE_270, 0, 0);
    } else if (direction == Direction::DIRECTION180) {
        canvas->Rotate(ROTATION_ANGLE_180, static_cast<float>(displayInfo_.validWidth) / CALCULATE_MIDDLE,
            static_cast<float>(displayInfo_.validHeight) / CALCULATE_MIDDLE);
    } else if (direction == Direction::DIRECTION270) {
        canvas->Translate(displayInfo_.validHeight, 0);
        canvas->Rotate(ROTATION_ANGLE_90, 0, 0);
    }
}
void TouchDrawingManager::CreateTouchWindow()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    if (surfaceNode_ != nullptr || scaleW_ == 0 || scaleH_ == 0) {
        return;
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
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
#endif
    surfaceNode_->SetRotation(0);
    screenId_ = static_cast<uint64_t>(displayInfo_.rsId);
    if (windowScreenId_ == screenId_) {
        screenId_ = displayNodeScreenId_;
    }
    surfaceNode_->AttachToDisplay(screenId_);
    MMI_HILOGI("TouchDrawingManager::CreateTouchWindow:%" PRIu64, screenId_);
    MMI_HILOGI("Setting screen:%{public}" PRIu64 ", displayNode:%{public}" PRIu64, screenId_, surfaceNode_->GetId());
}

void TouchDrawingManager::DrawBubbleHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto pointerAction = pointerEvent_->GetPointerAction();
    if (IsValidAction(pointerAction)) {
        DrawBubble();
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::DrawBubble()
{
    CHKPV(pointerEvent_);
    CHKPV(bubbleCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>(bubbleCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    auto pointerIdList = pointerEvent_->GetPointerIds();
    for (auto pointerId : pointerIdList) {
        if ((pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
            pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP ||
            pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_CANCEL) &&
            pointerEvent_->GetPointerId() == pointerId) {
            MMI_HILOGI("Continue bubble draw, pointerAction:%{public}d, pointerId:%{public}d",
                pointerEvent_->GetPointerAction(), pointerEvent_->GetPointerId());
            continue;
        }
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return;
        }
        auto displayXY = WIN_MGR->CalcDrawCoordinate(displayInfo_, pointerItem);
        Rosen::Drawing::Point centerPt(displayXY.first, displayXY.second);
        Rosen::Drawing::Pen pen;
        pen.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
        pen.SetAntiAlias(true);
        pen.SetAlphaF(OUT_CIRCLE_TRANSPARENCY);
        pen.SetWidth(bubble_.outerCircleWidth);
        canvas->AttachPen(pen);
        canvas->DrawCircle(centerPt, bubble_.outerCircleRadius);
        canvas->DetachPen();

        Rosen::Drawing::Brush brush;
        brush.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
        brush.SetAntiAlias(true);
        brush.SetAlphaF(INNER_CIRCLE_TRANSPARENCY);
        canvas->AttachBrush(brush);
        canvas->DrawCircle(centerPt, bubble_.innerCircleRadius);
        canvas->DetachBrush();
        if (pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN &&
            pointerEvent_->GetPointerId() == pointerId) {
            MMI_HILOGI("Bubble is draw success, pointerAction:%{public}d, pointerId:%{public}d, physicalX:%{private}d,"
                " physicalY:%{private}d, width:%{public}d, height:%{public}d", pointerEvent_->GetPointerAction(),
                pointerEvent_->GetPointerId(), displayXY.first, displayXY.second, scaleW_, scaleH_);
        }
    }
    bubbleCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawPointerPositionHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    UpdatePointerPosition();
    ClearTracker();
    RecordLabelsInfo();
    CHKPV(crosshairCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>(crosshairCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    auto pointerIdList = pointerEvent_->GetPointerIds();
    for (auto pointerId : pointerIdList) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return;
        }
        auto displayXY = WIN_MGR->CalcDrawCoordinate(displayInfo_, pointerItem);
        DrawTracker(displayXY.first, displayXY.second, pointerId);
        if (pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_UP) {
            DrawCrosshairs(canvas, displayXY.first, displayXY.second);
            UpdateLastPointerItem(pointerItem);
        }
    }
    DrawLabels();
    crosshairCanvasNode_->FinishRecording();
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::Snapshot()
{
    CHKPV(labelsCanvasNode_);
    std::string viewP = "P: 0 / " + std::to_string(maxPointerCount_);
    auto dx = currentPt_.GetX() - firstPt_.GetX();
    auto dy = currentPt_.GetY() - firstPt_.GetY();
    std::string viewDx = "dX: " + FormatNumber(dx, ONE_PRECISION);
    std::string viewDy = "dY: " + FormatNumber(dy, ONE_PRECISION);
    std::string viewXv = "Xv: " + FormatNumber(xVelocity_, THREE_PRECISION);
    std::string viewYv = "Yv: " + FormatNumber(yVelocity_, THREE_PRECISION);
    std::string viewPrs = "Prs: " + FormatNumber(pressure_, TWO_PRECISION);
    Rosen::Drawing::Color color = LABELS_DEFAULT_COLOR;
    auto canvas = static_cast<RosenCanvas *>(labelsCanvasNode_->BeginRecording(scaleW_, scaleH_));
    Rosen::Drawing::Rect rect;
    rect.top_ = rectTopPosition_;
    rect.bottom_ = rectTopPosition_ + RECT_HEIGHT;
    rect.left_ = 0;
    rect.right_ = itemRectW_ + rect.left_;
    Direction displayDirection = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    RotationCanvas(canvas, displayDirection);

    DrawRectItem(canvas, viewP, rect, color);
    color = std::abs(dx) < TOUCH_SLOP ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
    DrawRectItem(canvas, viewDx, rect, color);
    color = std::abs(dy) < TOUCH_SLOP ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
    DrawRectItem(canvas, viewDy, rect, color);
    DrawRectItem(canvas, viewXv, rect, LABELS_DEFAULT_COLOR);
    DrawRectItem(canvas, viewYv, rect, LABELS_DEFAULT_COLOR);
    color = isFirstDraw_ ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
    DrawRectItem(canvas, viewPrs, rect, color);
    labelsCanvasNode_->FinishRecording();
    CHKPV(crosshairCanvasNode_);
    auto crosshairCanvas = static_cast<RosenCanvas *>(crosshairCanvasNode_->BeginRecording(scaleW_, scaleH_));
    crosshairCanvas->Clear();
    crosshairCanvasNode_->FinishRecording();
    stopRecord_ = true;
}

bool TouchDrawingManager::IsWindowRotation()
{
    MMI_HILOGD("ROTATE_POLICY:%{public}d, FOLDABLE_DEVICE_POLICY:%{public}s",
        ROTATE_POLICY, FOLDABLE_DEVICE_POLICY.c_str());
    return (ROTATE_POLICY == WINDOW_ROTATE ||
        (ROTATE_POLICY == FOLDABLE_DEVICE &&
        ((displayInfo_.displayMode == DisplayMode::MAIN &&
        FOLDABLE_DEVICE_POLICY[0] == ROTATE_WINDOW_ROTATE) ||
        (displayInfo_.displayMode == DisplayMode::FULL &&
        FOLDABLE_DEVICE_POLICY[FOLDABLE_DEVICE] == ROTATE_WINDOW_ROTATE))));
}

void TouchDrawingManager::DrawTracker(int32_t x, int32_t y, int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    Rosen::Drawing::Point currentPt(x, y);
    Rosen::Drawing::Point lastPt;
    bool find = false;
    for (auto &item : lastPointerItem_) {
        if (item.GetPointerId() == pointerId) {
            auto displayXY = WIN_MGR->CalcDrawCoordinate(displayInfo_, item);
            lastPt.SetX(displayXY.first);
            lastPt.SetY(displayXY.second);
            find = true;
            break;
        }
    }
    if (currentPt == lastPt) {
        return;
    }
    CHKPV(trackerCanvasNode_);
    BytraceAdapter::StartHandleTracker(pointerId);
    auto canvas = static_cast<RosenCanvas *>(trackerCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    Rosen::Drawing::Pen pen;
    if (find) {
        pen.SetColor(TRACKER_COLOR);
        pen.SetWidth(PEN_WIDTH);
        canvas->AttachPen(pen);
        canvas->DrawLine(lastPt, currentPt);
        canvas->DetachPen();
        pen.SetColor(POINTER_RED_COLOR);
        pen.SetWidth(INDEPENDENT_WIDTH_PIXELS);
        canvas->AttachPen(pen);
        canvas->DrawPoint(currentPt);
        canvas->DetachPen();
    }
    if (!isDownAction_ && !find) {
        int32_t futureX = x + xVelocity_ * MULTIPLE_FACTOR;
        int32_t futureY = y + yVelocity_ * MULTIPLE_FACTOR;
        Rosen::Drawing::Point futurePt(futureX, futureY);
        pen.SetColor(POINTER_RED_COLOR);
        pen.SetWidth(PEN_WIDTH);
        canvas->AttachPen(pen);
        canvas->DrawLine(currentPt, futurePt);
        canvas->DetachPen();
    }
    trackerCanvasNode_->FinishRecording();
    BytraceAdapter::StopHandleTracker();
}

void TouchDrawingManager::DrawCrosshairs(RosenCanvas *canvas, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    Rosen::Drawing::Pen pen;
    pen.SetColor(CROSS_HAIR_COLOR);
    pen.SetWidth(PEN_WIDTH);
    canvas->AttachPen(pen);
    Rosen::Drawing::Point left(0, y);
    Rosen::Drawing::Point right(scaleH_, y);
    canvas->DrawLine(left, right);
    Rosen::Drawing::Point top(x, 0);
    Rosen::Drawing::Point bottom(x, scaleH_);
    canvas->DrawLine(top, bottom);
    canvas->DetachPen();
}

void TouchDrawingManager::DrawLabels()
{
    CALL_DEBUG_ENTER;
    CHKPV(labelsCanvasNode_);
    std::string viewP = "P: " + std::to_string(currentPointerCount_) + " / " + std::to_string(maxPointerCount_);
    std::string viewX = "X: " + FormatNumber(currentPt_.GetX(), ONE_PRECISION);
    std::string viewY = "Y: " + FormatNumber(currentPt_.GetY(), ONE_PRECISION);
    auto dx = currentPt_.GetX() - firstPt_.GetX();
    auto dy = currentPt_.GetY() - firstPt_.GetY();
    std::string viewDx = "dX: " + FormatNumber(dx, ONE_PRECISION);
    std::string viewDy = "dY: " + FormatNumber(dy, ONE_PRECISION);
    std::string viewXv = "Xv: " + FormatNumber(xVelocity_, THREE_PRECISION);
    std::string viewYv = "Yv: " + FormatNumber(yVelocity_, THREE_PRECISION);
    std::string viewPrs = "Prs: " + FormatNumber(pressure_, TWO_PRECISION);
    Rosen::Drawing::Color color = LABELS_DEFAULT_COLOR;
    std::lock_guard<std::mutex> lock(mutex_);
    auto canvas = static_cast<RosenCanvas *>(labelsCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    Rosen::Drawing::Rect rect;
    rect.top_ = rectTopPosition_;
    rect.bottom_ = rectTopPosition_ + RECT_HEIGHT;
    rect.left_ = 0;
    rect.right_ = itemRectW_ + rect.left_;
    Direction displayDirection = static_cast<Direction>((
        ((displayInfo_.direction - displayInfo_.displayDirection) * ANGLE_90 + ANGLE_360) % ANGLE_360) / ANGLE_90);
    RotationCanvas(canvas, displayDirection);
    DrawRectItem(canvas, viewP, rect, color);
    if (isDownAction_ || !lastPointerItem_.empty()) {
        DrawRectItem(canvas, viewX, rect, color);
        DrawRectItem(canvas, viewY, rect, color);
    } else {
        color = std::abs(dx) < TOUCH_SLOP ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
        DrawRectItem(canvas, viewDx, rect, color);
        color = std::abs(dy) < TOUCH_SLOP ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
        DrawRectItem(canvas, viewDy, rect, color);
    }
    DrawRectItem(canvas, viewXv, rect, LABELS_DEFAULT_COLOR);
    DrawRectItem(canvas, viewYv, rect, LABELS_DEFAULT_COLOR);
    color = isFirstDraw_ ? LABELS_DEFAULT_COLOR : LABELS_RED_COLOR;
    DrawRectItem(canvas, viewPrs, rect, color);
    labelsCanvasNode_->FinishRecording();
    isFirstDraw_ = false;
}

void TouchDrawingManager::DrawRectItem(RosenCanvas* canvas, const std::string &text,
    Rosen::Drawing::Rect &rect, const Rosen::Drawing::Color &color)
{
    CHKPV(canvas);
    Rosen::Drawing::Brush brush;
    brush.SetColor(color);
    canvas->AttachBrush(brush);
    canvas->DrawRect(rect);
    canvas->DetachBrush();

    std::shared_ptr<Rosen::Drawing::TextBlob> textBlob = Rosen::Drawing::TextBlob::MakeFromString(text.c_str(),
        Rosen::Drawing::Font(nullptr, TEXT_SIZE, TEXT_SCALE, TEXT_SKEW), Rosen::Drawing::TextEncoding::UTF8);
    CHKPV(textBlob);
    brush.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    canvas->AttachBrush(brush);
    canvas->DrawTextBlob(textBlob.get(), rect.left_, rectTopPosition_ + TEXT_TOP);
    canvas->DetachBrush();
    rect.left_ += itemRectW_ + RECT_SPACEING;
    rect.right_ += itemRectW_ + RECT_SPACEING;
}

void TouchDrawingManager::UpdatePointerPosition()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    int32_t pointerAction = pointerEvent_->GetPointerAction();
    int32_t pointerId = pointerEvent_->GetPointerId();
    if (pointerAction == PointerEvent::POINTER_ACTION_DOWN) {
        if (lastPointerItem_.empty()) {
            InitLabels();
        }
        maxPointerCount_ = ++currentPointerCount_;
    } else if (pointerAction == PointerEvent::POINTER_ACTION_UP) {
        isDownAction_ = false;
        isFirstDownAction_ = false;
        for (auto it = lastPointerItem_.begin(); it != lastPointerItem_.end(); it++) {
            if (it->GetPointerId() == pointerId) {
                lastPointerItem_.erase(it);
                --currentPointerCount_;
                break;
            }
        }
        if (!lastPointerItem_.empty() && (currentPointerId_ == pointerId)) {
            currentPointerId_ = lastPointerItem_.front().GetPointerId();
        }
    }
}

void TouchDrawingManager::UpdateLastPointerItem(PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    if (!pointerItem.IsPressed()) {
        return;
    }
    for (auto &item : lastPointerItem_) {
        if (item.GetPointerId() == pointerItem.GetPointerId()) {
            item = pointerItem;
            return;
        }
    }
    lastPointerItem_.emplace_back(pointerItem);
}

void TouchDrawingManager::RemovePointerPosition()
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    surfaceNode_->RemoveChild(trackerCanvasNode_);
    trackerCanvasNode_.reset();

    surfaceNode_->RemoveChild(crosshairCanvasNode_);
    crosshairCanvasNode_.reset();

    surfaceNode_->RemoveChild(labelsCanvasNode_);
    labelsCanvasNode_.reset();
    
    pointerEvent_.reset();
    Rosen::RSTransaction::FlushImplicitTransaction();
    isFirstDraw_ = true;
    pressure_ = 0.0;
}

void TouchDrawingManager::DestoryTouchWindow()
{
    if (bubbleMode_.isShow || pointerMode_.isShow) {
        return;
    }
    MMI_HILOGI("Destory touch window success, bubbleMode:%{public}d, pointerMode:%{public}d",
        bubbleMode_.isShow, pointerMode_.isShow);
    CHKPV(surfaceNode_);
    surfaceNode_->ClearChildren();
    surfaceNode_.reset();
}

void TouchDrawingManager::ClearTracker()
{
    CALL_DEBUG_ENTER;
    CHKPV(trackerCanvasNode_);
    if (lastPointerItem_.empty() && isDownAction_) {
        MMI_HILOGD("ClearTracker isDownAction_ and empty");
        auto canvasNode = static_cast<Rosen::RSCanvasDrawingNode*>(trackerCanvasNode_.get());
        canvasNode->ResetSurface(scaleW_, scaleH_);
    }
}

void TouchDrawingManager::InitLabels()
{
    isFirstDownAction_ = true;
    isDownAction_ = true;
    maxPointerCount_ = 0;
    currentPointerCount_ = 0;
    currentPointerId_ = 0;
    xVelocity_ = 0.0;
    yVelocity_ = 0.0;
}

bool TouchDrawingManager::IsValidAction(const int32_t action)
{
    if (action == PointerEvent::POINTER_ACTION_DOWN || action == PointerEvent::POINTER_ACTION_PULL_DOWN ||
        action == PointerEvent::POINTER_ACTION_MOVE || action == PointerEvent::POINTER_ACTION_PULL_MOVE ||
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP ||
        action == PointerEvent::POINTER_ACTION_CANCEL) {
        return true;
    }
    return false;
}

void TouchDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::ostringstream oss;

    std::vector<std::string> titles1 = {"currentPointerId", "maxPointerCount", "currentPointerCount",
                                        "lastActionTime", "xVelocity", "yVelocity"};

    std::vector<std::vector<std::string>> data1 = {
        {std::to_string(currentPointerId_), std::to_string(maxPointerCount_), std::to_string(currentPointerCount_),
         std::to_string(lastActionTime_), std::to_string(xVelocity_), std::to_string(yVelocity_)}
    };

    DumpFullTable(oss, "Touch Location Info", titles1, data1);
    oss << std::endl;

    std::vector<std::string> titles2 = {"pressure", "itemRectW", "hasBubbleObserver",
                                        "hasPointerObserver", "isFirstDownAction", "isDownAction", "isFirstDraw"};

    std::vector<std::vector<std::string>> data2 = {
        {std::to_string(pressure_), std::to_string(itemRectW_), std::to_string(hasBubbleObserver_),
         std::to_string(hasPointerObserver_), std::to_string(isFirstDownAction_), std::to_string(isDownAction_),
         std::to_string(isFirstDraw_)}
    };

    DumpFullTable(oss, "Touch Location Info", titles2, data2);
    oss << std::endl;

    std::vector<std::string> bubbleTitles = {"innerCircleRadius", "outerCircleRadius", "outerCircleWidth"};
    std::vector<std::vector<std::string>> bubbleData = {
        {std::to_string(bubble_.innerCircleRadius), std::to_string(bubble_.outerCircleRadius), std::to_string(bubble_.outerCircleWidth)}
    };

    DumpFullTable(oss, "Bubble Info", bubbleTitles, bubbleData);
    oss << std::endl;

    std::vector<std::string> devModeTitles = {"Name", "SwitchName", "IsShow"};
    std::vector<std::vector<std::string>> devModeData = {
        {"BubbleMode", bubbleMode_.SwitchName, std::to_string(bubbleMode_.isShow)},
        {"PointerMode", pointerMode_.SwitchName, std::to_string(pointerMode_.isShow)}
    };

    DumpFullTable(oss, "DevMode Info", devModeTitles, devModeData);
    oss << std::endl;

    std::string dumpInfo = oss.str();
    dprintf(fd, dumpInfo.c_str());
}
} // namespace MMI
} // namespace OHOS