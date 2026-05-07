/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") {}
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

#include "js_input_monitor_histogram.h"

#include "mmi_api_metrics_histograms.h"
#include "napi_constants.h"

namespace OHOS {
namespace MMI {
const JsInputMonitorHistogram::JsMonitorHistogramActionMap JsInputMonitorHistogram::histogramActions_ {
    {
        "touch", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnTouch,
            .off_ = &JsInputMonitorHistogram::OffTouch,
            .onError_ = &JsInputMonitorHistogram::OnTouchError,
            .offError_ = &JsInputMonitorHistogram::OffTouchError,
        }
    },
    {
        "mouse", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnMouse,
            .off_ = &JsInputMonitorHistogram::OffMouse,
            .onError_ = &JsInputMonitorHistogram::OnMouseError,
            .offError_ = &JsInputMonitorHistogram::OffMouseError,
        }
    },
    {
        "pinch", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnPinch,
            .off_ = &JsInputMonitorHistogram::OffPinch,
            .onError_ = &JsInputMonitorHistogram::OnPinchError,
            .offError_ = &JsInputMonitorHistogram::OffPinchError,
        }
    },
    {
        "threeFingersSwipe", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnThreeFingersSwipe,
            .off_ = &JsInputMonitorHistogram::OffThreeFingersSwipe,
            .onError_ = &JsInputMonitorHistogram::OnThreeFingersSwipeError,
            .offError_ = &JsInputMonitorHistogram::OffThreeFingersSwipeError,
        }
    },
    {
        "fourFingersSwipe", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnFourFingersSwipe,
            .off_ = &JsInputMonitorHistogram::OffFourFingersSwipe,
            .onError_ = &JsInputMonitorHistogram::OnFourFingersSwipeError,
            .offError_ = &JsInputMonitorHistogram::OffFourFingersSwipeError,
        }
    },
    {
        "rotate", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnRotate,
            .off_ = &JsInputMonitorHistogram::OffRotate,
            .onError_ = &JsInputMonitorHistogram::OnRotateError,
            .offError_ = &JsInputMonitorHistogram::OffRotateError,
        }
    },
    {
        "threeFingersTap", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnThreeFingersTap,
            .off_ = &JsInputMonitorHistogram::OffThreeFingersTap,
            .onError_ = &JsInputMonitorHistogram::OnThreeFingersTapError,
            .offError_ = &JsInputMonitorHistogram::OffThreeFingersTapError,
        }
    },
    {
        "fingerprint", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnFingerprint,
            .off_ = &JsInputMonitorHistogram::OffFingerprint,
            .onError_ = &JsInputMonitorHistogram::OnFingerprintError,
            .offError_ = &JsInputMonitorHistogram::OffFingerprintError,
        }
    },
    {
        "swipeInward", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnSwipeInward,
            .off_ = &JsInputMonitorHistogram::OffSwipeInward,
            .onError_ = &JsInputMonitorHistogram::OnSwipeInwardError,
            .offError_ = &JsInputMonitorHistogram::OffSwipeInwardError,
        }
    },
    {
        TOUCH_SWIPE_GESTURE, JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnTouchscreenSwipe,
            .off_ = &JsInputMonitorHistogram::OffTouchscreenSwipe,
            .onError_ = &JsInputMonitorHistogram::OnTouchscreenSwipeError,
            .offError_ = &JsInputMonitorHistogram::OffTouchscreenSwipeError,
        }
    },
    {
        TOUCH_PINCH_GESTURE, JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnTouchscreenPinch,
            .off_ = &JsInputMonitorHistogram::OffTouchscreenPinch,
            .onError_ = &JsInputMonitorHistogram::OnTouchscreenPinchError,
            .offError_ = &JsInputMonitorHistogram::OffTouchscreenPinchError,
        }
    },
    {
        "keyPressed", JsInputMonitorHistogram::HistogramActions {
            .on_ = &JsInputMonitorHistogram::OnKeyPressed,
            .off_ = &JsInputMonitorHistogram::OffKeyPressed,
            .onError_ = &JsInputMonitorHistogram::OnKeyPressedError,
            .offError_ = &JsInputMonitorHistogram::OffKeyPressedError,
        }
    },
};

void JsInputMonitorHistogram::HistogramOn(const std::string &type, bool sample)
{
    auto iter = histogramActions_.find(type);
    if (iter != histogramActions_.cend()) {
        iter->second.on_(sample);
    }
}

void JsInputMonitorHistogram::HistogramOff(const std::string &type, bool sample)
{
    auto iter = histogramActions_.find(type);
    if (iter != histogramActions_.cend()) {
        iter->second.off_(sample);
    }
}

void JsInputMonitorHistogram::HistogramOnError(const std::string &type, int32_t errorCode)
{
    auto iter = histogramActions_.find(type);
    if (iter != histogramActions_.cend()) {
        iter->second.onError_(errorCode);
    }
}

void JsInputMonitorHistogram::HistogramOffError(const std::string &type, int32_t errorCode)
{
    auto iter = histogramActions_.find(type);
    if (iter != histogramActions_.cend()) {
        iter->second.offError_(errorCode);
    }
}

void JsInputMonitorHistogram::OnTouch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_touch.Call", sample);
}

void JsInputMonitorHistogram::OffTouch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_touch.Call", sample);
}

void JsInputMonitorHistogram::OnTouchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touch.Error", errorCode);
}

void JsInputMonitorHistogram::OffTouchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touch.Error", errorCode);
}

void JsInputMonitorHistogram::OnMouse(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_mouse.Call", sample);
}

void JsInputMonitorHistogram::OffMouse(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_mouse.Call", sample);
}

void JsInputMonitorHistogram::OnMouseError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_mouse.Error", errorCode);
}

void JsInputMonitorHistogram::OffMouseError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_mouse.Error", errorCode);
}

void JsInputMonitorHistogram::OnPinch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_pinch.Call", sample);
}

void JsInputMonitorHistogram::OffPinch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_pinch.Call", sample);
}

void JsInputMonitorHistogram::OnPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_pinch.Error", errorCode);
}

void JsInputMonitorHistogram::OffPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_pinch.Error", errorCode);
}

void JsInputMonitorHistogram::OnThreeFingersSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_threeFingersSwipe.Call", sample);
}

void JsInputMonitorHistogram::OffThreeFingersSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_threeFingersSwipe.Call", sample);
}

void JsInputMonitorHistogram::OnThreeFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_threeFingersSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OffThreeFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_threeFingersSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OnFourFingersSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_fourFingersSwipe.Call", sample);
}

void JsInputMonitorHistogram::OffFourFingersSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_fourFingersSwipe.Call", sample);
}

void JsInputMonitorHistogram::OnFourFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_fourFingersSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OffFourFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_fourFingersSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OnRotate(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_rotate.Call", sample);
}

void JsInputMonitorHistogram::OffRotate(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_rotate.Call", sample);
}

void JsInputMonitorHistogram::OnRotateError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_rotate.Error", errorCode);
}

void JsInputMonitorHistogram::OffRotateError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_rotate.Error", errorCode);
}

void JsInputMonitorHistogram::OnThreeFingersTap(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_threeFingersTap.Call", sample);
}

void JsInputMonitorHistogram::OffThreeFingersTap(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_threeFingersTap.Call", sample);
}

void JsInputMonitorHistogram::OnThreeFingersTapError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_threeFingersTap.Error", errorCode);
}

void JsInputMonitorHistogram::OffThreeFingersTapError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_threeFingersTap.Error", errorCode);
}

void JsInputMonitorHistogram::OnFingerprint(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_fingerprint.Call", sample);
}

void JsInputMonitorHistogram::OffFingerprint(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_fingerprint.Call", sample);
}

void JsInputMonitorHistogram::OnFingerprintError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_fingerprint.Error", errorCode);
}

void JsInputMonitorHistogram::OffFingerprintError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_fingerprint.Error", errorCode);
}

void JsInputMonitorHistogram::OnSwipeInward(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_swipeInward.Call", sample);
}

void JsInputMonitorHistogram::OffSwipeInward(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_swipeInward.Call", sample);
}

void JsInputMonitorHistogram::OnSwipeInwardError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_swipeInward.Error", errorCode);
}

void JsInputMonitorHistogram::OffSwipeInwardError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_swipeInward.Error", errorCode);
}

void JsInputMonitorHistogram::OnTouchscreenSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_touchscreenSwipe.Call", sample);
}

void JsInputMonitorHistogram::OffTouchscreenSwipe(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_touchscreenSwipe.Call", sample);
}

void JsInputMonitorHistogram::OnTouchscreenSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touchscreenSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OffTouchscreenSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touchscreenSwipe.Error", errorCode);
}

void JsInputMonitorHistogram::OnTouchscreenPinch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_touchscreenPinch.Call", sample);
}

void JsInputMonitorHistogram::OffTouchscreenPinch(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_touchscreenPinch.Call", sample);
}

void JsInputMonitorHistogram::OnTouchscreenPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touchscreenPinch.Error", errorCode);
}

void JsInputMonitorHistogram::OffTouchscreenPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touchscreenPinch.Error", errorCode);
}

void JsInputMonitorHistogram::OnKeyPressed(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.on_keyPressed.Call", sample);
}

void JsInputMonitorHistogram::OffKeyPressed(bool sample)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputMonitor.off_keyPressed.Call", sample);
}

void JsInputMonitorHistogram::OnKeyPressedError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_keyPressed.Error", errorCode);
}

void JsInputMonitorHistogram::OffKeyPressedError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_keyPressed.Error", errorCode);
}
} // namespace MMI
} // namespace OHOS
