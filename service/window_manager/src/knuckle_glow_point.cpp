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

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowPoint"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t PAINT_WIDTH = 20;
constexpr int32_t ARGB_A = 0;
constexpr int32_t ARGB_RGB = 255;
constexpr double BASIC_LIFESPAN = 400.0f;
constexpr int32_t TRACE_COLOR = 255;
constexpr float BASIC_SIZE = 100.0f;
} // namespace

KnuckleGlowPoint::KnuckleGlowPoint(const OHOS::Rosen::Drawing::Bitmap &bitmap) : traceShadow_(bitmap) {}

KnuckleGlowPoint::~KnuckleGlowPoint() {}

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
    glowPaint_.SetAlpha(static_cast<int32_t>(TRACE_COLOR * (lifespan_ / BASIC_LIFESPAN)));
    glowPaint_.SetColor(Rosen::Drawing::Color::ColorQuadSetARGB(ARGB_A, ARGB_RGB, ARGB_RGB, ARGB_RGB));
    glowPaint_.SetAntiAlias(true);
    glowPaint_.SetWidth(PAINT_WIDTH);
}

void KnuckleGlowPoint::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    if (IsEnded() || pointX_ <= 0 || pointY_ <= 0) {
        return;
    }
    Rosen::Drawing::Paint paint;
    canvas->AttachPaint(glowPaint_);
    canvas->SetMatrix(traceMatrix_);
    OHOS::Rosen::Drawing::Brush brush;
    canvas->AttachBrush(brush);
    canvas->DrawBitmap(traceShadow_, pointX_, pointY_);
    canvas->DetachBrush();
    canvas->DetachPaint();
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
    traceMatrix_.Reset();
    float proportion = traceSize_ / traceShadow_.GetWidth();
    traceMatrix_.PostScale(proportion, proportion, pointX_, pointY_);
}
} // namespace MMI
} // namespace OHOS
