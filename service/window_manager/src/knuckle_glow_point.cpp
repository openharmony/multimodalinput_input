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
#include "define_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KnuckleGlowPoint" };
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;

int KnuckleGlowPoint::TRACE_COLOR = 255;
float KnuckleGlowPoint::BASIC_SIZE = 100.0f;
float KnuckleGlowPoint::DOUBLE = 2.0f;
double KnuckleGlowPoint::BASIC_LIFESPAN = 400;
double KnuckleGlowPoint::DEFAULT_LIFESPAN = -1;

KnuckleGlowPoint::KnuckleGlowPoint(const OHOS::Rosen::Drawing::Bitmap bitMap)
{
    CALL_DEBUG_ENTER;
    mTraceShadow_ = bitMap;
}

KnuckleGlowPoint::~KnuckleGlowPoint() {};

int64_t KnuckleGlowPoint::GetNanoTime()
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
    long currentTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    long timeInterval = currentTime - mLastUpdateTimeMillis_;
    if (timeInterval < 0) {
        timeInterval = 0;
    }

    mLastUpdateTimeMillis_ = currentTime;
    mLifespan_ -= timeInterval;
    mTraceSize_ = (float)((mLifespan_ / BASIC_LIFESPAN) * BASIC_SIZE);
    UpdateMatrix();
    mGlowPaint_.SetAlpha((int) (TRACE_COLOR * (mLifespan_ / BASIC_LIFESPAN)));
    mGlowPaint_.SetColor(Rosen::Drawing::Color::ColorQuadSetARGB(0, 255, 255, 255));
    mGlowPaint_.SetAntiAlias(true);
    mGlowPaint_.SetWidth(20);
}

void KnuckleGlowPoint::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    if (IsEnded() || mPointX_ <= 0 || mPointY_ <= 0) {
        return;
    }
    Rosen::Drawing::Paint paint;
    canvas->AttachPaint(mGlowPaint_);
    canvas->SetMatrix(mTraceMatrix_);
    OHOS::Rosen::Drawing::Brush brush;
    canvas->AttachBrush(brush);
    canvas->DrawBitmap(mTraceShadow_, mPointX_, mPointY_);
    canvas->DetachBrush();
    canvas->DetachPaint();
}

void KnuckleGlowPoint::Reset(double pointx, double pointy, float lifespanoffset)
{
    CALL_DEBUG_ENTER;
    mPointX_ = pointx;
    mPointY_ = pointy;
    mLifespan_ = BASIC_LIFESPAN - lifespanoffset;
    mTraceSize_ = BASIC_SIZE;
    mLastUpdateTimeMillis_ = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
}

bool KnuckleGlowPoint::IsEnded()
{
    CALL_DEBUG_ENTER;
    return mLifespan_ < 0;
}

void KnuckleGlowPoint::UpdateMatrix()
{
    CALL_DEBUG_ENTER;
    mTraceMatrix_.Reset();
    float proportion = mTraceSize_ / (float) mTraceShadow_.GetWidth();
    mTraceMatrix_.PostScale(proportion, proportion, mPointX_, mPointY_);
}
}
}
