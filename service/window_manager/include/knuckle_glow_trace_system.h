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

#ifndef KNUCKLE_GLOW_TRACE_SYSTEM_H
#define KNUCKLE_GLOW_TRACE_SYSTEM_H

#include <vector>

#include "draw/canvas.h"
#include "image/bitmap.h"
#include "include/core/SkPath.h"
#include "pipeline/rs_recording_canvas.h"
#include "render/rs_pixel_map_util.h"

#include "knuckle_divergent_point.h"
#include "knuckle_glow_point.h"

namespace OHOS {
namespace MMI {
class KnuckleGlowTraceSystem {
public:
    KnuckleGlowTraceSystem(int32_t pointSize, std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
        int32_t maxDivergenceNum);
    ~KnuckleGlowTraceSystem() = default;
    void Clear();
    void Update();
    void Draw(Rosen::ExtendRecordingCanvas* canvas);
    void ResetDivergentPoints(double pointX, double pointY);
    void AddGlowPoints(const Rosen::Drawing::Path &path, int64_t timeInterval);

private:
    std::vector<std::shared_ptr<KnuckleGlowPoint>> glowPoints_;
    std::vector<std::shared_ptr<KnuckleDivergentPoint>> divergentPoints_;
    int32_t maxDivergenceNum_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GLOW_TRACE_SYSTEM_H
