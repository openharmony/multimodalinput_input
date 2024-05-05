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

#include "knuckle_divergent_point.h"

#include <ctime>
#include <iostream>
#include <random>

#include "define_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KnuckleDivergentPoint" };
constexpr double PI = 3.14159265358979323846;
Rosen::Drawing::Pen KnuckleDivergentPoint::sTracePaint;
int32_t KnuckleDivergentPoint::BASIC_LIFESPAN = 15;
double KnuckleDivergentPoint::BASIC_GRAVITY_Y = 0.5;
int32_t KnuckleDivergentPoint::DEFAULT_LIFESPAN = -1;
float KnuckleDivergentPoint::DOUBLE = 2.0f;
int KnuckleDivergentPoint::TRACE_COLOR = 255;
int KnuckleDivergentPoint::DEFAULT_SIZE = 80;
int KnuckleDivergentPoint::DEFAULT_SIZE_OFFSET = 20;
int KnuckleDivergentPoint::DEFAULT_SPEED = 8;
int KnuckleDivergentPoint::DEFAULT_SPEED_OFFSET = 8;

KnuckleDivergentPoint::KnuckleDivergentPoint(OHOS::Rosen::Drawing::Bitmap bitMap)
{
    CALL_DEBUG_ENTER;
    mTraceShadow_ = bitMap;
    srand((unsigned)time(nullptr));
    float newSize = rand() % DEFAULT_SIZE + DEFAULT_SIZE_OFFSET;
    float proportion = 0;
    int width = bitMap.GetWidth();
    if (width != 0) {
        proportion = newSize / width;
    }
    mTraceMatrix_.PostTranslate(-width / DOUBLE, -(bitMap.GetHeight() / DOUBLE));
    mTraceMatrix_.PostScale(proportion, proportion);
}

KnuckleDivergentPoint::~KnuckleDivergentPoint() {};

void KnuckleDivergentPoint::Update()
{
    CALL_DEBUG_ENTER;
    if (IsEnded()) {
        return;
    }
    mLifespan_--;
    mPointX_ += mMoveVelocityX_;
    mPointY_ += mMoveVelocityY_;
    mMoveVelocityY_ += BASIC_GRAVITY_Y;
}

void KnuckleDivergentPoint::Clear()
{
    CALL_DEBUG_ENTER;
    mLifespan_ = DEFAULT_LIFESPAN;
}

void KnuckleDivergentPoint::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    CHKPV(canvas);
    if (IsEnded() || mPointX_ <= 0 || mPointY_ <= 0) {
        return;
    }

    OHOS::Rosen::Drawing::Brush brush;
    canvas->AttachBrush(brush);
    canvas->DrawBitmap(mTraceShadow_, mPointX_, mPointY_);
    canvas->DetachBrush();
}

void KnuckleDivergentPoint::Reset(double pointX, double pointY)
{
    CALL_DEBUG_ENTER;
    mPointX_ = pointX;
    mPointY_ = pointY;
    mLifespan_ = BASIC_LIFESPAN;
    std::random_device rd;
    std::default_random_engine e(rd());
    std::uniform_real_distribution<double> u(0.0, 1.0);
    double baseVelocity = u(e) * DOUBLE * PI;

    srand((unsigned)time(nullptr));
    double moveSpeed = rand() % DEFAULT_SPEED + DEFAULT_SPEED_OFFSET;
    mMoveVelocityX_ = std::cos(baseVelocity) * moveSpeed;
    mMoveVelocityY_ = std::sin(baseVelocity) * moveSpeed;
}

bool KnuckleDivergentPoint::IsEnded()
{
    CALL_DEBUG_ENTER;
    return mLifespan_ < 0;
}
}
}
