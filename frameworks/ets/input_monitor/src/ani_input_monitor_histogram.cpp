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

#include "ani_input_monitor_histogram.h"

#include "mmi_api_metrics_histograms.h"

namespace OHOS {
namespace MMI {
const AniInputMonitorHistogram::AniMonitorHistogramActionMap AniInputMonitorHistogram::histogramActions_ {
    {
        MONITORFUNTYPE::ON_TOUCH_BOOL, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnTouchError,
            .offError_ = &AniInputMonitorHistogram::OffTouchError,
        }
    },
    {
        MONITORFUNTYPE::ON_MOUSE, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnMouseError,
            .offError_ = &AniInputMonitorHistogram::OffMouseError,
        }
    },
    {
        MONITORFUNTYPE::ON_MOUSE_RECT, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnMouseError,
            .offError_ = &AniInputMonitorHistogram::OffMouseError,
        }
    },
    {
        MONITORFUNTYPE::ON_PINCH, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnPinchError,
            .offError_ = &AniInputMonitorHistogram::OffPinchError,
        }
    },
    {
        MONITORFUNTYPE::ON_PINCH_FINGERS, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnPinchError,
            .offError_ = &AniInputMonitorHistogram::OffPinchError,
        }
    },
    {
        MONITORFUNTYPE::ON_THREEFINGERSWIPE, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnThreeFingersSwipeError,
            .offError_ = &AniInputMonitorHistogram::OffThreeFingersSwipeError,
        }
    },
    {
        MONITORFUNTYPE::ON_FOURFINGERSWIPE, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnFourFingersSwipeError,
            .offError_ = &AniInputMonitorHistogram::OffFourFingersSwipeError,
        }
    },
    {
        MONITORFUNTYPE::ON_ROTATE_FINGERS, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnRotateError,
            .offError_ = &AniInputMonitorHistogram::OffRotateError,
        }
    },
    {
        MONITORFUNTYPE::ON_THREEFINGERSTAP, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnThreeFingersTapError,
            .offError_ = &AniInputMonitorHistogram::OffThreeFingersTapError,
        }
    },
    {
        MONITORFUNTYPE::ON_FINGERPRINT, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnFingerprintError,
            .offError_ = &AniInputMonitorHistogram::OffFingerprintError,
        }
    },
    {
        MONITORFUNTYPE::ON_SWIPEINWARD, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnSwipeInwardError,
            .offError_ = &AniInputMonitorHistogram::OffSwipeInwardError,
        }
    },
    {
        MONITORFUNTYPE::ON_TOUCHSCREENSWIPE_FINGERS, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnTouchscreenSwipeError,
            .offError_ = &AniInputMonitorHistogram::OffTouchscreenSwipeError,
        }
    },
    {
        MONITORFUNTYPE::ON_TOUCHSCREENPINCH_FINGERS, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnTouchscreenPinchError,
            .offError_ = &AniInputMonitorHistogram::OffTouchscreenPinchError,
        }
    },
    {
        MONITORFUNTYPE::ON_KEYPRESSED_KEYS, AniInputMonitorHistogram::HistogramActions {
            .onError_ = &AniInputMonitorHistogram::OnKeyPressedError,
            .offError_ = &AniInputMonitorHistogram::OffKeyPressedError,
        }
    },
};

void AniInputMonitorHistogram::HistogramOnError(MONITORFUNTYPE funType, int32_t errorCode)
{
    auto iter = histogramActions_.find(funType);
    if (iter != histogramActions_.cend()) {
        iter->second.onError_(errorCode);
    }
}

void AniInputMonitorHistogram::HistogramOffError(MONITORFUNTYPE funType, int32_t errorCode)
{
    auto iter = histogramActions_.find(funType);
    if (iter != histogramActions_.cend()) {
        iter->second.offError_(errorCode);
    }
}

void AniInputMonitorHistogram::OnTouchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touch.Error", errorCode);
}

void AniInputMonitorHistogram::OffTouchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touch.Error", errorCode);
}

void AniInputMonitorHistogram::OnMouseError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_mouse.Error", errorCode);
}

void AniInputMonitorHistogram::OffMouseError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_mouse.Error", errorCode);
}

void AniInputMonitorHistogram::OnPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_pinch.Error", errorCode);
}

void AniInputMonitorHistogram::OffPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_pinch.Error", errorCode);
}

void AniInputMonitorHistogram::OnThreeFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_threeFingersSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OffThreeFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_threeFingersSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OnFourFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_fourFingersSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OffFourFingersSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_fourFingersSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OnRotateError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_rotate.Error", errorCode);
}

void AniInputMonitorHistogram::OffRotateError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_rotate.Error", errorCode);
}

void AniInputMonitorHistogram::OnThreeFingersTapError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_threeFingersTap.Error", errorCode);
}

void AniInputMonitorHistogram::OffThreeFingersTapError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_threeFingersTap.Error", errorCode);
}

void AniInputMonitorHistogram::OnFingerprintError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_fingerprint.Error", errorCode);
}

void AniInputMonitorHistogram::OffFingerprintError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_fingerprint.Error", errorCode);
}

void AniInputMonitorHistogram::OnSwipeInwardError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_swipeInward.Error", errorCode);
}

void AniInputMonitorHistogram::OffSwipeInwardError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_swipeInward.Error", errorCode);
}

void AniInputMonitorHistogram::OnTouchscreenSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touchscreenSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OffTouchscreenSwipeError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touchscreenSwipe.Error", errorCode);
}

void AniInputMonitorHistogram::OnTouchscreenPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_touchscreenPinch.Error", errorCode);
}

void AniInputMonitorHistogram::OffTouchscreenPinchError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_touchscreenPinch.Error", errorCode);
}

void AniInputMonitorHistogram::OnKeyPressedError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.on_keyPressed.Error", errorCode);
}

void AniInputMonitorHistogram::OffKeyPressedError(int32_t errorCode)
{
    MMI_HISTOGRAM_ERROR("InputKit.inputMonitor.off_keyPressed.Error", errorCode);
}
} // namespace MMI
} // namespace OHOS
