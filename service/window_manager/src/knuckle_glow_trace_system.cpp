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

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowTraceSystem"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KnuckleGlowTraceSystem" };
}

KnuckleGlowTraceSystem::KnuckleGlowTraceSystem(int32_t pointSize, OHOS::Rosen::Drawing::Bitmap bitMap,
    int32_t maxDivergenceNum)
{
    CALL_DEBUG_ENTER;
    for (int32_t i = 0; i < pointSize; ++i) {
        divergentPoints_.emplace_back(std::make_shared<KnuckleDivergentPoint>(bitMap));
        glowPoints_.emplace_back(std::make_shared<KnuckleGlowPoint>(bitMap));
    }
    maxDivergenceNum_ = maxDivergenceNum;
}

KnuckleGlowTraceSystem::~KnuckleGlowTraceSystem() {}

void KnuckleGlowTraceSystem::Clear()
{
    CALL_DEBUG_ENTER;
    for (const auto &divergentPoint : divergentPoints_) {
        divergentPoint->Clear();
    }
}

void KnuckleGlowTraceSystem::Update()
{
    CALL_DEBUG_ENTER;
    for (size_t i = 0; i < glowPoints_.size(); i++) {
        glowPoints_[i]->Update();
        divergentPoints_[i]->Update();
    }
}

void KnuckleGlowTraceSystem::Draw(Rosen::Drawing::RecordingCanvas* canvas)
{
    CALL_DEBUG_ENTER;
    for (auto divergentPoint : divergentPoints_) {
        if (!divergentPoint->IsEnded()) {
            divergentPoint->Draw(canvas);
        }
    }
    for (auto glowPoint : glowPoints_) {
        if (glowPoint != nullptr) {
            glowPoint->Draw(canvas);
        }
    }
}

void KnuckleGlowTraceSystem::ResetDivergentPoints(double pointx, double pointY)
{
    CALL_DEBUG_ENTER;
    int32_t divergenceNum = 0;
    for (const auto &divergentPoint : divergentPoints_) {
        if (divergentPoint == nullptr) {
            MMI_HILOGE("divergentPoint is nullptr");
        }
        if (divergentPoint->IsEnded() && divergenceNum < maxDivergenceNum_) {
            divergenceNum++;
            MMI_HILOGE("reset divergentPoint");
            divergentPoint->Reset(pointx, pointY);
        }
    }
}

void KnuckleGlowTraceSystem::AddGlowPoints(Rosen::Drawing::Path path, int64_t timeInteval)
{
    CALL_DEBUG_ENTER;
    double pathlength = path.GetLength(false);
    Rosen::Drawing::Point pathPoints;
    Rosen::Drawing::Point tangent;
    float distanceFromEnd = 0;
    float lifespanOffset = timeInteval;
    float splitRatio = (float) std::ceil(pathlength / BASIC_DISTANCE_BETWEEN_POINTS);
    float baseTime = timeInteval / splitRatio;
    for (auto glowPoint : glowPoints_) {
        if (glowPoint != nullptr && glowPoint->IsEnded() && distanceFromEnd <= pathlength) {
            if (path.GetPositionAndTangent(distanceFromEnd, pathPoints, tangent, true)) {
                glowPoint->Reset(pathPoints.GetX(), pathPoints.GetY(), lifespanOffset);
                distanceFromEnd += BASIC_DISTANCE_BETWEEN_POINTS;
                lifespanOffset -= baseTime;
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS
