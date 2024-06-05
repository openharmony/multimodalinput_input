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

#include "touch_drawing_manager.h"
#include "parameters.h"
#include "setting_datashare.h"
#include "text/font_mgr.h"

#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "table_dump.h"

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
constexpr int32_t ROTATION_ANGLE_90 { 90 };
constexpr int32_t ROTATION_ANGLE_180 { 180 };
constexpr int32_t ROTATION_ANGLE_270 { 270 };
constexpr uint64_t FOLD_SCREEN_MAIN_ID { 5 };
constexpr uint64_t FOLD_SCREEN_FULL_ID { 0 };
constexpr float TEXT_SIZE { 28.0f };
constexpr float TEXT_SCALE { 1.0f };
constexpr float TEXT_SKEW { 0.0f };
constexpr float CALCULATE_TEMP { 2.0f };
const std::string showCursorSwitchName { "settings.input.show_touch_hint" };
const std::string pointerPositionSwitchName { "settings.developer.show_touch_track" };
const std::string PRODUCT_TYPE = system::GetParameter("const.product.devicetype", "unknown");
const std::string PRODUCT_PHONE { "phone" };
} // namespace

TouchDrawingManager::TouchDrawingManager()
{
    bubbleBrush_.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
    bubbleBrush_.SetAntiAlias(true);
    float innerCircleTransparency = 0.6f;
    bubbleBrush_.SetAlphaF(innerCircleTransparency);

    bubblePen_.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    bubblePen_.SetAntiAlias(true);
    float outerCircleTransparency = 0.1f;
    bubblePen_.SetAlphaF(outerCircleTransparency);

    textBrush_.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    pathPen_.SetColor(TRACKER_COLOR);
    pointPen_.SetColor(POINTER_RED_COLOR);
    crosshairsPen_.SetColor(CROSS_HAIR_COLOR);
    linePen_.SetColor(POINTER_RED_COLOR);
}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::ConvertPointerEvent(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPV(pointerEvent);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
    }
    CHKPV(pointerEvent_);
    pointerEvent_->Reset();
    pointerEvent_->SetTargetDisplayId(pointerEvent->GetTargetDisplayId());
    pointerEvent_->SetPointerAction(pointerEvent->GetPointerAction());
    pointerEvent_->SetPointerId(pointerEvent->GetPointerId());
    std::list<PointerEvent::PointerItem> items = pointerEvent->GetAllPointerItems();
    for (auto item : items) {
        int32_t displayX = item.GetDisplayX();
        int32_t displayY = item.GetDisplayY();
        if (displayInfo_.displayDirection == DIRECTION0) {
            GetOriginalTouchScreenCoordinates(displayInfo_.direction, displayInfo_.width,
                displayInfo_.height, displayX, displayY);
        }
        item.SetDisplayX(displayX);
        item.SetDisplayY(displayY);
        pointerEvent_->AddPointerItem(item);
    }
}

void TouchDrawingManager::RecordLabelsInfo(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPV(pointerEvent);
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(currentPointerId_, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", currentPointerId_);
        return;
    }
    if (pointerItem.IsPressed()) {
        currentPt_.SetX(pointerItem.GetDisplayX());
        currentPt_.SetY(pointerItem.GetDisplayY());
        pressure_ = pointerItem.GetPressure();
    }
    if (isFirstDownAction_) {
        firstPt_.SetX(pointerItem.GetDisplayX());
        firstPt_.SetY(pointerItem.GetDisplayY());
        isFirstDownAction_ = false;
    }
    int64_t actionTime = pointerEvent->GetActionTime();
    if (pointerEvent->GetPointerId() == currentPointerId_ && !lastPointerItem_.empty()) {
        double diffTime = static_cast<double>(actionTime - lastActionTime_) / 1000;
        if (MMI_EQ(diffTime, 0.0)) {
            xShowVelocity_ = 0.0;
            yShowVelocity_ = 0.0;
        } else {
            auto diffX = currentPt_.GetX() - lastPt_.GetX();
            auto diffY = currentPt_.GetY() - lastPt_.GetY();
            xShowVelocity_ = diffX / diffTime;
            yShowVelocity_ = diffY / diffTime;
        }
        lastActionTime_ = actionTime;
    }
}

void TouchDrawingManager::TouchDrawHandler(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    ConvertPointerEvent(pointerEvent);
    CreateObserver();
    if (bubbleMode_.isShow) {
        CreateTouchWindow();
        AddCanvasNode(bubbleCanvasNode_, false);
        DrawBubbleHandler();
    }
    if (pointerMode_.isShow) {
        CreateTouchWindow();
        AddCanvasNode(trackerCanvasNode_, true);
        AddCanvasNode(crosshairCanvasNode_, false);
        AddCanvasNode(labelsCanvasNode_, false);
        DrawPointerPositionHandler(pointerEvent);
        lastPt_ = currentPt_;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    scaleW_ = displayInfo.width > displayInfo.height ? displayInfo.width : displayInfo.height;
    scaleH_ = displayInfo.width > displayInfo.height ? displayInfo.width : displayInfo.height;
    displayInfo_ = displayInfo;
    bubble_.innerCircleRadius = displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleRadius = displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleWidth = static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE;
    itemRectW_ = static_cast<double>(displayInfo_.width) / RECT_COUNT;
    rectTopPosition_ = 0;
    if (displayInfo_.displayDirection == DIRECTION0) {
        if (displayInfo_.direction == DIRECTION0 || displayInfo_.direction == DIRECTION180) {
            rectTopPosition_ = PRODUCT_TYPE == PRODUCT_PHONE ? PHONE_RECT_TOP : PAD_RECT_TOP;
        }
    } else {
        if (displayInfo_.direction == DIRECTION90) {
            rectTopPosition_ = PHONE_RECT_TOP;
        }
    }
}

void TouchDrawingManager::GetOriginalTouchScreenCoordinates(Direction direction, int32_t width, int32_t height,
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

void TouchDrawingManager::UpdateLabels()
{
    if (pointerMode_.isShow) {
        DrawLabels();
    } else {
        RemovePointerPosition();
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::UpdateBubbleData()
{
    if (!bubbleMode_.isShow) {
        RemoveBubble();
        Rosen::RSTransaction::FlushImplicitTransaction();
    }    
}

void TouchDrawingManager::CreateObserver()
{
    CALL_DEBUG_ENTER;
    if (!hasBubbleObserver_) {
        bubbleMode_.SwitchName = showCursorSwitchName;
        CreateBubbleObserver(bubbleMode_);
        hasBubbleObserver_ = true;
    }
    if (!hasPointerObserver_) {
        pointerMode_.SwitchName = pointerPositionSwitchName;
        CreatePointerObserver(pointerMode_);
        SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
            GetBoolValue(pointerPositionSwitchName, pointerMode_.isShow);
        hasPointerObserver_ = true;
    }
}

template <class T>
void TouchDrawingManager::CreateBubbleObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        TOUCH_DRAWING_MGR->UpdateBubbleData();
        MMI_HILOGI("key: %{public}s, statusValue: %{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).
        RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
}

template <class T>
void TouchDrawingManager::CreatePointerObserver(T &item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [&item](const std::string& key) {
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, item.isShow);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        TOUCH_DRAWING_MGR->UpdateLabels();
        MMI_HILOGI("key: %{public}s, statusValue: %{public}d", key.c_str(), item.isShow);
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.SwitchName, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("register setting observer failed, ret=%{public}d", ret);
        statusObserver = nullptr;
    }
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

void TouchDrawingManager::AddCanvasNode(std::shared_ptr<Rosen::RSCanvasNode>& canvasNode, bool isTrackerNode)
{
    CALL_DEBUG_ENTER;
    CHKPV(surfaceNode_);
    if (canvasNode != nullptr) {
        return;
    }
    canvasNode = isTrackerNode ? Rosen::RSCanvasDrawingNode::Create() : Rosen::RSCanvasNode::Create();
    CHKPV(canvasNode);
    canvasNode->SetBounds(0, 0, scaleW_, scaleH_);
    canvasNode->SetFrame(0, 0, scaleW_, scaleH_);
#ifndef USE_ROSEN_DRAWING
    canvasNode->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    canvasNode->SetCornerRadius(1);
    canvasNode->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode->SetRotation(0);
    surfaceNode_->AddChild(canvasNode, DEFAULT_VALUE);
}

void TouchDrawingManager::CreateTouchWindow()
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
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
    uint64_t screenId = static_cast<uint64_t>(pointerEvent_->GetTargetDisplayId());
    if (displayInfo_.displayMode == DisplayMode::MAIN) {
        screenId = FOLD_SCREEN_MAIN_ID;
    } else if (displayInfo_.displayMode == DisplayMode::FULL) {
        screenId = FOLD_SCREEN_FULL_ID;
    }
    surfaceNode_->AttachToDisplay(screenId);
    MMI_HILOGI("Setting screen:%{public}" PRIu64 ", displayNode:%{public}" PRIu64, screenId, surfaceNode_->GetId());
}

void TouchDrawingManager::DrawBubbleHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto pointerAction = pointerEvent_->GetPointerAction();
    if (IsValidAction(pointerAction)) {
        DrawBubble();
    }
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
            pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) &&
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
        int32_t physicalX = pointerItem.GetDisplayX();
        int32_t physicalY = pointerItem.GetDisplayY();
        Rosen::Drawing::Point centerPt(physicalX, physicalY);
        bubblePen_.SetWidth(bubble_.outerCircleWidth);
        canvas->AttachPen(bubblePen_);
        canvas->DrawCircle(centerPt, bubble_.outerCircleRadius);
        canvas->DetachPen();

        canvas->AttachBrush(bubbleBrush_);
        canvas->DrawCircle(centerPt, bubble_.innerCircleRadius);
        canvas->DetachBrush();
        if (pointerEvent_->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN &&
            pointerEvent_->GetPointerId() == pointerId) {
            MMI_HILOGI("Bubble is draw success, pointerAction:%{public}d, pointerId:%{public}d, physicalX:%{public}d,"
                " physicalY:%{public}d", pointerEvent_->GetPointerAction(), pointerEvent_->GetPointerId(),
                physicalX, physicalY);
        }
    }
    bubbleCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawPointerPositionHandler(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    UpdatePointerPosition();
    ClearTracker();
    RecordLabelsInfo(pointerEvent);
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
        int32_t displayX = pointerItem.GetDisplayX();
        int32_t displayY = pointerItem.GetDisplayY();
        DrawTracker(displayX, displayY, pointerId);
        if (pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_UP) {
            DrawCrosshairs(canvas, displayX, displayY);
            UpdateLastPointerItem(pointerItem);
        }
    }
    DrawLabels();
    crosshairCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawTracker(int32_t x, int32_t y, int32_t pointerId)
{
    CALL_DEBUG_ENTER;
    Rosen::Drawing::Point currentPt(x, y);
    Rosen::Drawing::Point lastPt;
    bool find = false;
    for (auto &item : lastPointerItem_) {
        if (item.GetPointerId() == pointerId) {
            lastPt.SetX(item.GetDisplayX());
            lastPt.SetY(item.GetDisplayY());
            find = true;
            break;
        }
    }
    if (currentPt == lastPt) {
        return;
    }
    CHKPV(trackerCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>(trackerCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    if (find) {
        pathPen_.SetWidth(PEN_WIDTH);
        canvas->AttachPen(pathPen_);
        canvas->DrawLine(lastPt, currentPt);
        canvas->DetachPen();
        pointPen_.SetWidth(INDEPENDENT_WIDTH_PIXELS);
        canvas->AttachPen(pointPen_);
        canvas->DrawPoint(currentPt);
        canvas->DetachPen();
    }
    if (!isDownAction_ && !find) {
        int32_t futureX = x + xVelocity_ * MULTIPLE_FACTOR;
        int32_t futureY = y + yVelocity_ * MULTIPLE_FACTOR;
        Rosen::Drawing::Point futurePt(futureX, futureY);
        linePen_.SetWidth(PEN_WIDTH);
        canvas->AttachPen(linePen_);
        canvas->DrawLine(currentPt, futurePt);
        canvas->DetachPen();
    }
    trackerCanvasNode_->FinishRecording();
}

void TouchDrawingManager::DrawCrosshairs(RosenCanvas *canvas, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;
    crosshairsPen_.SetWidth(PEN_WIDTH);
    canvas->AttachPen(crosshairsPen_);
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
    std::string viewXv = "Xv: " + FormatNumber(xShowVelocity_, THREE_PRECISION);
    std::string viewYv = "Yv: " + FormatNumber(yShowVelocity_, THREE_PRECISION);
    std::string viewPrs = "Prs: " + FormatNumber(pressure_, TWO_PRECISION);
    Rosen::Drawing::Color color = LABELS_DEFAULT_COLOR;
    auto canvas = static_cast<RosenCanvas *>(labelsCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    Rosen::Drawing::Rect rect;
    rect.top_ = rectTopPosition_;
    rect.bottom_ = rectTopPosition_ + RECT_HEIGHT;
    rect.left_ = 0;
    rect.right_ = itemRectW_ + rect.left_;
    if (displayInfo_.displayDirection == DIRECTION0) {
        if (displayInfo_.direction == Direction::DIRECTION90) {
            canvas->Translate(0, displayInfo_.width);
            canvas->Rotate(ROTATION_ANGLE_270, 0, 0);
        } else if (displayInfo_.direction == Direction::DIRECTION180) {
            canvas->Rotate(ROTATION_ANGLE_180, displayInfo_.width / CALCULATE_TEMP,
                displayInfo_.height / CALCULATE_TEMP);
        } else if (displayInfo_.direction == Direction::DIRECTION270) {
            canvas->Translate(displayInfo_.height, 0);
            canvas->Rotate(ROTATION_ANGLE_90, 0, 0);
        }
    }
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
    std::shared_ptr<Rosen::Drawing::TextBlob> textBlob = Rosen::Drawing::TextBlob::MakeFromString(text.c_str(),
        Rosen::Drawing::Font(nullptr, TEXT_SIZE, TEXT_SCALE, TEXT_SKEW), Rosen::Drawing::TextEncoding::UTF8);
    rectBrush_.SetColor(color);
    canvas->AttachBrush(rectBrush_);
    canvas->DrawRect(rect);
    canvas->DetachBrush();
    canvas->AttachBrush(textBrush_);
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
            ClearLabels();
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
    UpdateVelocity();
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

void TouchDrawingManager::UpdateVelocity()
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    auto pointerId = pointerEvent_->GetPointerId();
    int64_t actionTime = pointerEvent_->GetActionTime();
    if (pointerId == currentPointerId_) {
        if (!lastPointerItem_.empty()) {
            PointerEvent::PointerItem pointerItem;
            if (!pointerEvent_->GetPointerItem(pointerId, pointerItem)) {
                MMI_HILOGD("Can't find pointer item, pointer:%{public}d", pointerId);
                return;
            }
            int32_t physicalX = pointerItem.GetDisplayX();
            int32_t physicalY = pointerItem.GetDisplayY();
            double diffTime = static_cast<double>(actionTime - lastActionTime_) / 1000;
            if (MMI_EQ(diffTime, 0.0)) {
                xVelocity_ = 0.0;
                yVelocity_ = 0.0;
            } else {
                auto diffX = physicalX - lastPointerItem_.front().GetDisplayX();
                auto diffY = physicalY - lastPointerItem_.front().GetDisplayY();
                xVelocity_ = diffX / diffTime;
                yVelocity_ = diffY / diffTime;
            }
        }
    }
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
    isFirstDraw_ = true;
    pressure_ = 0.0;
}

void TouchDrawingManager::RemoveBubble()
{
    CHKPV(bubbleCanvasNode_);
    auto canvas = static_cast<RosenCanvas *>(bubbleCanvasNode_->BeginRecording(scaleW_, scaleH_));
    CHKPV(canvas);
    canvas->Clear();
    bubbleCanvasNode_->FinishRecording();
}

void TouchDrawingManager::ClearTracker()
{
    CALL_DEBUG_ENTER;
    CHKPV(trackerCanvasNode_);
    if (lastPointerItem_.empty() && isDownAction_) {
        MMI_HILOGD("ClearTracker isDownAction_ and empty");
        auto canvasNode = static_cast<Rosen::RSCanvasDrawingNode*>(trackerCanvasNode_.get());
        canvasNode->ResetSurface();
    }
}

void TouchDrawingManager::ClearLabels()
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
        action == PointerEvent::POINTER_ACTION_UP || action == PointerEvent::POINTER_ACTION_PULL_UP) {
        return true;
    }
    return false;
}

void TouchDrawingManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::ostringstream oss;
    auto titles1 = std::make_tuple("currentPointerId", "maxPointerCount", "currentPointerCount",
                                   "lastActionTime", "xVelocity", "yVelocity");

    auto data1 = std::vector{std::make_tuple(currentPointerId_, maxPointerCount_, currentPointerCount_,
                                             lastActionTime_, xVelocity_, yVelocity_)};
    DumpFullTable(oss, "Touch Location Info", titles1, data1);
    oss << std::endl;

    auto titles2 = std::make_tuple("pressure", "itemRectW", "hasBubbleObserver",
                                   "hasPointerObserver", "isFirstDownAction", "isDownAction", "isFirstDraw");

    auto data2 = std::vector{std::make_tuple(pressure_, itemRectW_, hasBubbleObserver_,
                                             hasPointerObserver_, isFirstDownAction_, isDownAction_, isFirstDraw_)};
    DumpFullTable(oss, "Touch Location Info", titles2, data2);
    oss << std::endl;

    auto bubbleTitles = std::make_tuple("innerCircleRadius", "outerCircleRadius", "outerCircleWidth");
    auto bubbleData = std::vector{
            std::make_tuple(bubble_.innerCircleRadius, bubble_.outerCircleRadius, bubble_.outerCircleWidth)};
    DumpFullTable(oss, "Bubble Info", bubbleTitles, bubbleData);
    oss << std::endl;

    auto devModeTitles = std::make_tuple("Name", "SwitchName", "IsShow");
    auto devModeData = std::vector{
            std::make_tuple("BubbleMode", bubbleMode_.SwitchName, bubbleMode_.isShow),
            std::make_tuple("PointerMode", pointerMode_.SwitchName, pointerMode_.isShow)};
    DumpFullTable(oss, "DevMode Info", devModeTitles, devModeData);
    oss << std::endl;

    std::string dumpInfo = oss.str();
    dprintf(fd, dumpInfo.c_str());
}
} // namespace MMI
} // namespace OHOS
