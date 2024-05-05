/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef KNUCKLE_GLOW_POINT_H
#define KNUCKLE_GLOW_POINT_H

#include "image/bitmap.h"
#include "draw/canvas.h"
#include "include/core/SkCanvas.h"
#include "utils/matrix.h"
#include "include/core/SkPaint.h"
#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "recording/recording_canvas.h"
#endif
namespace OHOS {
namespace MMI {
class KnuckleGlowPoint {
public:
    KnuckleGlowPoint(OHOS::Rosen::Drawing::Bitmap bitMap);
    ~KnuckleGlowPoint();
    void Update();
    void Draw(Rosen::Drawing::RecordingCanvas* canvas);
    void Reset(double pointX, double pointY, float lifespanOffset);
    bool IsEnded();

private:
    void UpdateMatrix();
    int64_t GetNanoTime();

    static int TRACE_COLOR;
    static float BASIC_SIZE;
    static float DOUBLE;
    static double BASIC_LIFESPAN;
    static double DEFAULT_LIFESPAN;

    double lifespan_ = DEFAULT_LIFESPAN;
    double pointX_;
    double pointY_;
    int64_t lastUpdateTimeMillis_;
    float traceSize_;

    Rosen::Drawing::Matrix traceMatrix_;
    Rosen::Drawing::Bitmap traceShadow_;
    Rosen::Drawing::Paint glowPaint_;
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_GLOW_POINT_H
