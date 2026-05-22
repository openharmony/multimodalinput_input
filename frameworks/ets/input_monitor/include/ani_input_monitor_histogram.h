/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef JS_INPUT_MONITOR_HISTOGRAM_H
#define JS_INPUT_MONITOR_HISTOGRAM_H

#include <functional>
#include <unordered_map>

#include "ani_input_monitor_consumer.h"

namespace OHOS {
namespace MMI {
class AniInputMonitorHistogram final {
private:
    struct HistogramActions {
        std::function<void(int32_t)> onError_ {};
        std::function<void(int32_t)> offError_ {};
    };

    using AniMonitorHistogramActionMap = std::unordered_map<MONITORFUNTYPE, HistogramActions>;

public:
    static void HistogramOnError(MONITORFUNTYPE funType, int32_t errorCode);
    static void HistogramOffError(MONITORFUNTYPE funType, int32_t errorCode);

private:
    static void OnTouch(bool sample);
    static void OffTouch(bool sample);
    static void OnTouchError(int32_t errorCode);
    static void OffTouchError(int32_t errorCode);
    static void OnMouse(bool sample);
    static void OffMouse(bool sample);
    static void OnMouseError(int32_t errorCode);
    static void OffMouseError(int32_t errorCode);
    static void OnPinch(bool sample);
    static void OffPinch(bool sample);
    static void OnPinchError(int32_t errorCode);
    static void OffPinchError(int32_t errorCode);
    static void OnThreeFingersSwipe(bool sample);
    static void OffThreeFingersSwipe(bool sample);
    static void OnThreeFingersSwipeError(int32_t errorCode);
    static void OffThreeFingersSwipeError(int32_t errorCode);
    static void OnFourFingersSwipe(bool sample);
    static void OffFourFingersSwipe(bool sample);
    static void OnFourFingersSwipeError(int32_t errorCode);
    static void OffFourFingersSwipeError(int32_t errorCode);
    static void OnRotate(bool sample);
    static void OffRotate(bool sample);
    static void OnRotateError(int32_t errorCode);
    static void OffRotateError(int32_t errorCode);
    static void OnThreeFingersTap(bool sample);
    static void OffThreeFingersTap(bool sample);
    static void OnThreeFingersTapError(int32_t errorCode);
    static void OffThreeFingersTapError(int32_t errorCode);
    static void OnFingerprint(bool sample);
    static void OffFingerprint(bool sample);
    static void OnFingerprintError(int32_t errorCode);
    static void OffFingerprintError(int32_t errorCode);
    static void OnSwipeInward(bool sample);
    static void OffSwipeInward(bool sample);
    static void OnSwipeInwardError(int32_t errorCode);
    static void OffSwipeInwardError(int32_t errorCode);
    static void OnTouchscreenSwipe(bool sample);
    static void OffTouchscreenSwipe(bool sample);
    static void OnTouchscreenSwipeError(int32_t errorCode);
    static void OffTouchscreenSwipeError(int32_t errorCode);
    static void OnTouchscreenPinch(bool sample);
    static void OffTouchscreenPinch(bool sample);
    static void OnTouchscreenPinchError(int32_t errorCode);
    static void OffTouchscreenPinchError(int32_t errorCode);
    static void OnKeyPressed(bool sample);
    static void OffKeyPressed(bool sample);
    static void OnKeyPressedError(int32_t errorCode);
    static void OffKeyPressedError(int32_t errorCode);

    static const AniMonitorHistogramActionMap histogramActions_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_HISTOGRAM_H
