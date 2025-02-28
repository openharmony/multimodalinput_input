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

#include "define_multimodal.h"
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
#endif
}
}