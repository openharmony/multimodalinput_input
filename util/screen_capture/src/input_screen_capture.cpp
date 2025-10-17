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

#include "audio_stream_manager.h"
#include "define_multimodal.h"
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
#include "dfx_hisysevent.h"
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
#include "error_multimodal.h"
#include "input_screen_capture_monitor_listener.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputScreenCapture"

namespace OHOS {
namespace MMI {
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
namespace {
sptr<InputScreenCaptureMonitorListener> g_screenCaptureMonitorListener { nullptr };
}

extern "C" int32_t IsScreenCaptureWorking(int32_t capturePid)
{
    std::list<int32_t> pidList = Media::ScreenCaptureMonitor::GetInstance()->IsScreenCaptureWorking();
    auto iter = std::find(pidList.begin(), pidList.end(), capturePid);
    if (iter != pidList.end()) {
        return true;
    }
    return false;
}

extern "C" void RegisterListener(ScreenCaptureCallback callback)
{
    if (g_screenCaptureMonitorListener == nullptr) {
        g_screenCaptureMonitorListener = new (std::nothrow) InputScreenCaptureMonitorListener();
        CHKPV(g_screenCaptureMonitorListener);
    }
    g_screenCaptureMonitorListener->SetScreenCaptureCallback(callback);
    Media::ScreenCaptureMonitor::GetInstance()->RegisterScreenCaptureMonitorListener(g_screenCaptureMonitorListener);
}

extern "C" bool IsMusicActivate()
{
    CALL_INFO_TRACE;
    std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> rendererChangeInfo;
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    auto begin = std::chrono::high_resolution_clock::now();
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    auto ret = AudioStandard::AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(rendererChangeInfo);
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::GET_CUR_RENDERER_CHANGE_INFOS, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (ret != ERR_OK) {
        MMI_HILOGE("Check music activate failed, errnoCode is %{public}d", ret);
        return false;
    }
    if (rendererChangeInfo.empty()) {
        MMI_HILOGI("Music info empty");
        return false;
    }
    for (const auto &info : rendererChangeInfo) {
        if (info->rendererState == AudioStandard::RENDERER_RUNNING &&
            (info->rendererInfo.streamUsage != AudioStandard::STREAM_USAGE_ULTRASONIC ||
            info->rendererInfo.streamUsage != AudioStandard::STREAM_USAGE_INVALID)) {
            MMI_HILOGI("Find music activate, streamUsage:%{public}d, sessionId:%{public}d",
                info->rendererInfo.streamUsage, info->rendererInfo.sessionId);
            return true;
        }
    }
    return false;
}
#endif
}
}