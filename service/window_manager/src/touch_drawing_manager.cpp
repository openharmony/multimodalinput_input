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

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "recording/recording_canvas.h"
#endif

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DENSITY_BASELINE = 160;
constexpr int32_t INDEPENDENT_INNER_PIXELS = 20;
constexpr int32_t INDEPENDENT_OUTER_PIXELS = 21;
constexpr int32_t INDEPENDENT_WIDTH_PIXELS = 2;
constexpr int32_t CALCULATE_MIDDLE = 2;
constexpr int32_t DEFAULT_VALUE = -1;
} // namespace

TouchDrawingManager::TouchDrawingManager()
{
    brush_.SetColor(Rosen::Drawing::Color::COLOR_WHITE);
    brush_.SetAntiAlias(true);
    float innerCircleTransparency = 0.6f;
    brush_.SetAlphaF(innerCircleTransparency);

    pen_.SetColor(Rosen::Drawing::Color::COLOR_BLACK);
    pen_.SetAntiAlias(true);
    float outerCircleTransparency = 0.1f;
    pen_.SetAlphaF(outerCircleTransparency);
}

TouchDrawingManager::~TouchDrawingManager() {}

void TouchDrawingManager::TouchDrawHandler(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    auto displayId = pointerEvent->GetTargetDisplayId();
    CreateTouchWindow(displayId);
    int32_t pointerAction = pointerEvent->GetPointerAction();
    if (IsValidAction(pointerAction)) {
        StartTouchDraw(pointerEvent);
    }
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

void TouchDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    displayInfo_ = displayInfo;
    bubble_.innerCircleRadius = displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleRadius = displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE;
    bubble_.outerCircleWidth = static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE;
}

void TouchDrawingManager::StartTouchDraw(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    int32_t ret = DrawGraphic(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Draw graphic failed");
        return;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    MMI_HILOGD("Draw graphic success");
}

void TouchDrawingManager::CreateTouchWindow(const int32_t displayId)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGD("surfaceNode is already.");
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
#endif

    screenId_ = static_cast<uint64_t>(displayId);
    std::cout << "ScreenId: " << screenId_ << std::endl;
    surfaceNode_->SetRotation(0);

    CreateCanvasNode();
    surfaceNode_->AddChild(canvasNode_, DEFAULT_VALUE);
    surfaceNode_->AttachToDisplay(screenId_);
    Rosen::RSTransaction::FlushImplicitTransaction();
}

void TouchDrawingManager::CreateCanvasNode()
{
    canvasNode_ = Rosen::RSCanvasNode::Create();
    CHKPV(canvasNode_);
    canvasNode_->SetBounds(0, 0, displayInfo_.width, displayInfo_.height);
    canvasNode_->SetFrame(0, 0, displayInfo_.width, displayInfo_.height);
#ifndef USE_ROSEN_DRAWING
    canvasNode_->SetBackgroundColor(SK_ColorTRANSPARENT);
#else
    canvasNode_->SetBackgroundColor(Rosen::Drawing::Color::COLOR_TRANSPARENT);
#endif
    canvasNode_->SetCornerRadius(1);
    canvasNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    canvasNode_->SetRotation(0);
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

int32_t TouchDrawingManager::DrawGraphic(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, RET_ERR);
    CHKPR(canvasNode_, RET_ERR);
#ifndef USE_ROSEN_DRAWING
    auto canvas = static_cast<Rosen::RSRecordingCanvas *>(canvasNode_->
        BeginRecording(displayInfo_.width, displayInfo_.height));
#else
    auto canvas = static_cast<Rosen::Drawing::RecordingCanvas *>(canvasNode_->
        BeginRecording(displayInfo_.width, displayInfo_.height));
#endif
    CHKPR(canvas, RET_ERR);

    auto pointerIdList = pointerEvent->GetPointerIds();
    for (auto pointerId : pointerIdList) {
        if ((pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP ||
            pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_PULL_UP) &&
            pointerEvent->GetPointerId() == pointerId) {
            continue;
        }

        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
            MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
            return RET_ERR;
        }
        int32_t physicalX = pointerItem.GetDisplayX();
        int32_t physicalY = pointerItem.GetDisplayY();
        if (displayInfo_.displayDirection == DIRECTION0) {
            GetOriginalTouchScreenCoordinates(displayInfo_.direction, displayInfo_.width,
                displayInfo_.height, physicalX, physicalY);
        }
        Rosen::Drawing::Point centerPt(physicalX, physicalY);
        pen_.SetWidth(bubble_.outerCircleWidth);
        canvas->AttachPen(pen_);
        canvas->DrawCircle(centerPt, bubble_.outerCircleRadius);
        canvas->DetachPen();

        canvas->AttachBrush(brush_);
        canvas->DrawCircle(centerPt, bubble_.innerCircleRadius);
        canvas->DetachBrush();
    }
    canvasNode_->FinishRecording();
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS