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

#include "knuckle_glow_trace_system.h"

#include "include/core/SkPathMeasure.h"
#include "define_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KnuckleGlowTraceSystem" };
}

KnuckleGlowTraceSystem::KnuckleGlowTraceSystem(int pointSize, OHOS::Rosen::Drawing::Bitmap bitMap,
    int maxDivergenceNum)
{
    CALL_DEBUG_ENTER;
    for (int i = 0; i < pointSize; ++i) {
        mDivergentPoints_.emplace_back(std::make_shared<KnuckleDivergentPoint>(bitMap));
        mGlowPoints_.emplace_back(std::make_shared<KnuckleGlowPoint>(bitMap));
    }
    mMaxDivergenceNum_ = maxDivergenceNum;
}

KnuckleGlowTraceSystem::~KnuckleGlowTraceSystem() {}

void KnuckleGlowTraceSystem::Clear()
{
    CALL_DEBUG_ENTER;
    for (auto divergentPoint : mDivergentPoints_) {
        divergentPoint->Clear();
    }
}

void KnuckleGlowTraceSystem::Update()
{
    CALL_DEBUG_ENTER;
    int particleSize = mGlowPoints_.size();
    for (int i = 0; i < particleSize; i++) {
        mGlowPoints_[i]->Update();
        mDivergentPoints_[i]->Update();
    }
}

void KnuckleGlowTraceSystem::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    for (auto divergentPoint : mDivergentPoints_) {
        if (!divergentPoint->IsEnded()) {
            divergentPoint->Draw(canvas);
        }
    }
    for (auto glowPoint : mGlowPoints_) {
        if (glowPoint != nullptr) {
            glowPoint->Draw(canvas);
        }
    }
}

void KnuckleGlowTraceSystem::ResetDivergentPoints(double pointx, double pointY)
{
    CALL_DEBUG_ENTER;
    int divergenceNum = 0;
    for (auto divergentPoint : mDivergentPoints_) {
        if (divergentPoint == nullptr) {
            MMI_HILOGE("divergentPoint null");
        }
        if (divergentPoint->IsEnded() && divergenceNum < mMaxDivergenceNum_) {
            divergenceNum++;
            MMI_HILOGE("divergentPoint->Reset");
            divergentPoint->Reset(pointx, pointY);
        }
    }
}

void KnuckleGlowTraceSystem::AddGlowPoints(Rosen::Drawing::Path path, long timeInteval)
{
    CALL_DEBUG_ENTER;
    double pathlength = path.GetLength(false);
    Rosen::Drawing::Point pathPoints;
    Rosen::Drawing::Point tangent;
    float distanceFromEnd = 0;
    float lifespanOffset = timeInteval;
    float splitRatio = (float) std::ceil(pathlength / BASIC_DISTANCE_BETWEEN_POINTS);
    float baseTime = timeInteval / splitRatio;
    for (auto glowPoint : mGlowPoints_) {
        if (glowPoint != nullptr && glowPoint->IsEnded() && distanceFromEnd <= pathlength) {
            if (path.GetPositionAndTangent(distanceFromEnd, pathPoints, tangent, true)) {
                glowPoint->Reset(pathPoints.GetX(), pathPoints.GetY(), lifespanOffset);
                distanceFromEnd += BASIC_DISTANCE_BETWEEN_POINTS;
                lifespanOffset -= baseTime;
            }
        }
    }
}
}
}
