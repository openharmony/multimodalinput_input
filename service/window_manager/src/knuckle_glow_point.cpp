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

#include "knuckle_glow_point.h"

#include "include/core/SkColorFilter.h"
#include "mmi_log.h"
#include "platform/ohos/overdraw/rs_overdraw_controller.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowPoint"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SEC_TO_NANOSEC { 1000000000 };
constexpr int32_t NANOSECOND_TO_MILLISECOND { 1000000 };
constexpr int32_t PAINT_WIDTH { 20 };
constexpr int32_t ARGB_A { 0 };
constexpr int32_t ARGB_RGB { 255 };
constexpr double BASIC_LIFESPAN { 200.0f };
constexpr int32_t TRACE_COLOR { 255 };
constexpr float BASIC_SIZE { 100.0f };
constexpr int32_t ARGB_COLOR_ARRAY { 0x11c8ffff };
constexpr double HALF { 2.0 };
} // namespace

KnuckleGlowPoint::KnuckleGlowPoint(std::shared_ptr<OHOS::Media::PixelMap> pixelMap) : traceShadow_(pixelMap)
{
    OHOS::Rosen::Drawing::Filter filter;
    OHOS::Rosen::OverdrawColorArray colorArray = {
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        ARGB_COLOR_ARRAY,
    };
    auto protanomalyMat = OHOS::Rosen::Drawing::ColorFilter::CreateOverDrawColorFilter(colorArray.data());
    filter.SetColorFilter(protanomalyMat);
    OHOS::Rosen::Drawing::Brush brush;
    brush_.SetFilter(filter);
}

int64_t KnuckleGlowPoint::GetNanoTime() const
{
    CALL_DEBUG_ENTER;
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

void KnuckleGlowPoint::Update()
{
    CALL_DEBUG_ENTER;
    if (IsEnded()) {
        return;
    }
    int64_t currentTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    int64_t timeInterval = currentTime - lastUpdateTimeMillis_;
    if (timeInterval < 0) {
        timeInterval = 0;
    }

    lastUpdateTimeMillis_ = currentTime;
    lifespan_ -= timeInterval;
    traceSize_ = static_cast<float>((lifespan_ / BASIC_LIFESPAN) * BASIC_SIZE);
    UpdateMatrix();
}

void KnuckleGlowPoint::Draw(Rosen::ExtendRecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    CHKPV(traceShadow_);
    if (IsEnded() || pointX_ <= 0 || pointY_ <= 0) {
        return;
    }
    canvas->SetMatrix(traceMatrix_);
    canvas->AttachBrush(brush_);
    Rosen::Drawing::Rect src = Rosen::Drawing::Rect(0, 0, traceShadow_->GetWidth(), traceShadow_->GetHeight());
    Rosen::Drawing::Rect dst = Rosen::Drawing::Rect(pointX_ - traceShadow_->GetWidth() / HALF,
        pointY_ - traceShadow_->GetHeight() / HALF, pointX_ + traceShadow_->GetWidth() / HALF,
        pointY_ + traceShadow_->GetHeight());
    canvas->DrawPixelMapRect(traceShadow_, src, dst, Rosen::Drawing::SamplingOptions());
    canvas->DetachBrush();
}

void KnuckleGlowPoint::Reset(double pointX, double pointY, float lifespanOffset)
{
    CALL_DEBUG_ENTER;
    pointX_ = pointX;
    pointY_ = pointY;
    lifespan_ = BASIC_LIFESPAN - lifespanOffset;
    traceSize_ = BASIC_SIZE;
    lastUpdateTimeMillis_ = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
}

bool KnuckleGlowPoint::IsEnded() const
{
    CALL_DEBUG_ENTER;
    return lifespan_ < 0;
}

void KnuckleGlowPoint::UpdateMatrix()
{
    CALL_DEBUG_ENTER;
    CHKPV(traceShadow_);
    traceMatrix_.Reset();
    float proportion = traceSize_ / traceShadow_->GetWidth();
    traceMatrix_.PostScale(proportion, proportion, pointX_, pointY_);
}
} // namespace MMI
} // namespace OHOS
