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
#include "render/rs_pixel_map_util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDynamicDrawingManager"

namespace OHOS {
namespace MMI {
namespace {
const std::string IMAGE_POINTER_PENTAGRAM_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string PENT_ICON_PATH = IMAGE_POINTER_PENTAGRAM_PATH + "Default.svg";
constexpr int32_t DENSITY_BASELINE = 160;
constexpr int32_t INDEPENDENT_INNER_PIXELS = 20;
constexpr int32_t INDEPENDENT_OUTER_PIXELS = 21;
constexpr int32_t INDEPENDENT_WIDTH_PIXELS = 2;
constexpr int32_t CALCULATE_MIDDLE = 2;
constexpr int32_t DEFAULT_VALUE = -1;
constexpr int32_t MAX_POINTER_COLOR = 0x00ffff;
constexpr int32_t TIME_DIMENSION = 1000;
constexpr int32_t PATH_COLOR = 0xFFCCCCCC;
constexpr int32_t MIN_POINT_SIZE = 1;
constexpr float PAINT_STROKE_WIDTH = 10.0f;
constexpr float DOUBLE = 2.0f;
constexpr int32_t POINT_TOTAL_SIZE = 5;
constexpr int32_t POINT_SYSTEM_SIZE = 500;
constexpr int32_t MAX_DIVERGENCE_NUM = 10;
constexpr int32_t DEFAULT_POINTER_SIZE = 1;
constexpr int32_t DESIRED_SIZE = 80;
} // namespace

KnuckleDynamicDrawingManager::KnuckleDynamicDrawingManager()
{
    InitPointerPathPaint();
}

KnuckleDynamicDrawingManager::~KnuckleDynamicDrawingManager() {}

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
    if (pixelMap == nullptr) {
        MMI_HILOGE("The pixelMap is nullptr");
    }
    pixelMap_ = pixelMap;
    return pixelMap;
}

Rosen::Drawing::AlphaType KnuckleDynamicDrawingManager::AlphaTypeToAlphaType(Media::AlphaType alphaType)
{
    CALL_DEBUG_ENTER;
    switch (alphaType) {
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL;
        case Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL;
        default:
            return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
    }
}

Rosen::Drawing::ColorType KnuckleDynamicDrawingManager::PixelFormatToColorType(Media::PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case Media::PixelFormat::RGB_565:
            return Rosen::Drawing::ColorType::COLORTYPE_RGB_565;
        case Media::PixelFormat::RGBA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888;
        case Media::PixelFormat::BGRA_8888:
            return Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888;
        case Media::PixelFormat::ALPHA_8:
            return Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8;
        case Media::PixelFormat::RGBA_F16:
            return Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16;
        case Media::PixelFormat::UNKNOWN:
        case Media::PixelFormat::ARGB_8888:
        case Media::PixelFormat::RGB_888:
        case Media::PixelFormat::NV21:
        case Media::PixelFormat::NV12:
        case Media::PixelFormat::CMYK:
        default:
            return Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN;
    }
}

std::shared_ptr<Rosen::Drawing::Bitmap> KnuckleDynamicDrawingManager::PixelMapToBitmap(
    std::shared_ptr<Media::PixelMap>& pixelMap)
{
    CALL_DEBUG_ENTER;
    auto data = pixelMap->GetPixels();
    Rosen::Drawing::Bitmap bitmap;
    Rosen::Drawing::ColorType colorType = PixelFormatToColorType(pixelMap->GetPixelFormat());
    Rosen::Drawing::AlphaType alphaType = AlphaTypeToAlphaType(pixelMap->GetAlphaType());
    Rosen::Drawing::ImageInfo imageInfo(pixelMap->GetWidth(), pixelMap->GetHeight(), colorType, alphaType);
    bitmap.Build(imageInfo);
    bitmap.SetPixels(const_cast<uint8_t*>(data));
    return std::make_shared<Rosen::Drawing::Bitmap>(bitmap);
}

void KnuckleDynamicDrawingManager::InitPointerPathPaint()
{
    CALL_DEBUG_ENTER;
    for (int32_t i = 0; i < POINT_TOTAL_SIZE; i++) {
        Rosen::Drawing::Point point = Rosen::Drawing::Point();
        traceControlPoints_.push_back(point);
    }
    pixelMap_ = DecodeImageToPixelMap(PENT_ICON_PATH);
    CHKPV(pixelMap_);
    auto bitmap = PixelMapToBitmap(pixelMap_);
    CHKPV(bitmap);
    if (glowTraceSystem_ == nullptr) {
        glowTraceSystem_ = std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, *bitmap, MAX_DIVERGENCE_NUM);
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
    MMI_HILOGI("item.GetToolType(): %{public}d", itemToolType);
    if (itemToolType != PointerEvent::TOOL_TYPE_KNUCKLE ||
        touchEvent->GetPointerIds().size() != 1) {
        if (canvasNode_ != nullptr) {
            isStop_ = true;
            traceControlPoints_.clear();
            pointerPath_.Reset();
            canvasNode_->ResetSurface();
            Rosen::RSTransaction::FlushImplicitTransaction();
        }
        return false;
    }
    return true;
}

bool KnuckleDynamicDrawingManager::CheckPointerAction(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
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
            if (!isStop_) {
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
        MMI_HILOGE("Draw graphic failed");
        return;
    }
    Rosen::RSTransaction::FlushImplicitTransaction();
    MMI_HILOGI("Draw graphic success");
}

void KnuckleDynamicDrawingManager::ProcessUpAndCancelEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (pointerPath_.IsValid()) {
        auto id = pointerEvent->GetPointerId();
        PointerEvent::PointerItem pointerItem;
        pointerEvent->GetPointerItem(id, pointerItem);
        glowTraceSystem_->ResetDivergentPoints(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    }

    pointerPath_.Reset();
    glowTraceSystem_->Clear();
    CHKPV(canvasNode_);
    canvasNode_->ResetSurface();
    Rosen::RSTransaction::FlushImplicitTransaction();
    isDrawing_ = true;
}

void KnuckleDynamicDrawingManager::ProcessDownEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    UpdateTrackColors();
    lastUpdateTimeMillis_ = pointerEvent->GetActionTime();
    pointCounter_ = 0;
    auto id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(id, pointerItem);
    traceControlPoints_[pointCounter_].Set(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    glowTraceSystem_->ResetDivergentPoints(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    isDrawing_ = false;
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
    traceControlPoints_[pointCounter_].Set(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());

    int pointIndex4 = 4;

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
        pointerPath_.CubicTo(traceControlPoints_[pointIndex1].GetX(),
            traceControlPoints_[pointIndex1].GetY(),
            traceControlPoints_[pointIndex2].GetX(),
            traceControlPoints_[pointIndex2].GetY(),
            traceControlPoints_[pointIndex3].GetX(),
            traceControlPoints_[pointIndex3].GetY());
        traceControlPoints_[pointIndex0].Set(traceControlPoints_[pointIndex3].GetX(),
            traceControlPoints_[pointIndex3].GetY());
        traceControlPoints_[pointIndex1].Set (traceControlPoints_[pointIndex4].GetX(),
            traceControlPoints_[pointIndex4].GetY());
        pointCounter_ = 1;
        // Add glowing particles onto the last path segment that was drawn
        int64_t now = pointerEvent->GetActionTime();
        double len = pointerPath_.GetLength(false);
        glowTraceSystem_->AddGlowPoints(pointerPath_, (now - lastUpdateTimeMillis_) / TIME_DIMENSION);
        pointerPath_.Reset();
        lastUpdateTimeMillis_ = now;
    }
    glowTraceSystem_->ResetDivergentPoints(pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
}

void KnuckleDynamicDrawingManager::UpdateDisplayInfo(const DisplayInfo& displayInfo)
{
    CALL_DEBUG_ENTER;
    displayInfo_ = displayInfo;
}

int32_t KnuckleDynamicDrawingManager::DrawGraphic(std::shared_ptr<PointerEvent> pointerEvent)
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
    glowTraceSystem_->Update();
    if (pointerPath_.IsValid()) {
        return RET_ERR;
    }
    if (!isDrawing_) {
        glowTraceSystem_->Draw(canvas);
    }
    canvasNode_->ResetSurface();
    canvasNode_->FinishRecording();
    return RET_OK;
}

void KnuckleDynamicDrawingManager::CreateTouchWindow(const int32_t displayId)
{
    CALL_DEBUG_ENTER;
    if (surfaceNode_ != nullptr) {
        MMI_HILOGD("surfaceNode_ is already");
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

void KnuckleDynamicDrawingManager::CreateCanvasNode()
{
    CALL_DEBUG_ENTER;
    canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
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
} // namespace MMI
} // namespace OHOS
