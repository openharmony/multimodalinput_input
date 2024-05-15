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
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowTraceSystem"

namespace OHOS {
namespace MMI {
namespace {
constexpr float BASIC_DISTANCE_BETWEEN_POINTS = 5.0f;
} // namespace

KnuckleGlowTraceSystem::KnuckleGlowTraceSystem(int32_t pointSize, const OHOS::Rosen::Drawing::Bitmap &bitmap,
    int32_t maxDivergenceNum) : maxDivergenceNum_(maxDivergenceNum)
{
    CALL_DEBUG_ENTER;
    for (int32_t i = 0; i < pointSize; ++i) {
        divergentPoints_.emplace_back(std::make_shared<KnuckleDivergentPoint>(bitmap));
        glowPoints_.emplace_back(std::make_shared<KnuckleGlowPoint>(bitmap));
    }
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

void KnuckleGlowTraceSystem::ResetDivergentPoints(double pointX, double pointY)
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
            divergentPoint->Reset(pointX, pointY);
        }
    }
}

void KnuckleGlowTraceSystem::AddGlowPoints(Rosen::Drawing::Path path, int64_t timeInterval)
{
    CALL_DEBUG_ENTER;
    double pathlength = path.GetLength(false);
    Rosen::Drawing::Point pathPoints;
    Rosen::Drawing::Point tangent;
    float distanceFromEnd = 0;
    float lifespanOffset = timeInterval;
    float splitRatio = static_cast<float>(std::ceil(pathlength / BASIC_DISTANCE_BETWEEN_POINTS));
    float baseTime = timeInterval / splitRatio;
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
