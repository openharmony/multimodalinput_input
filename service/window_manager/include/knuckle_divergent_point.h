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

#ifndef KNUCKLE_GIVERGENT_POINT_H
#define KNUCKLE_GIVERGENT_POINT_H

#include "draw/canvas.h"
#include "image/bitmap.h"
#include "pipeline/rs_recording_canvas.h"
#include "render/rs_pixel_map_util.h"
#include "utils/matrix.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_LIFESPAN { -1 };
} // namespace

class KnuckleDivergentPoint {
public:
    explicit KnuckleDivergentPoint(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);
    ~KnuckleDivergentPoint() = default;
    void Update();
    void Clear();
    void Draw(Rosen::ExtendRecordingCanvas* canvas);
    void Reset(double pointX, double pointY);
    bool IsEnded() const;

private:
    double moveVelocityX_ { 0.0 };
    double moveVelocityY_ { 0.0 };
    double pointX_ { 0.0 };
    double pointY_ { 0.0 };
    int32_t lifespan_ { DEFAULT_LIFESPAN };
    std::shared_ptr<OHOS::Media::PixelMap> traceShadow_ { nullptr };
    Rosen::Drawing::Matrix traceMatrix_;
    OHOS::Rosen::Drawing::Brush brush_;
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GIVERGENT_POINT_H
