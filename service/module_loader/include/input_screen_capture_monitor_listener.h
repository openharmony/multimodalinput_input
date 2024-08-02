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
#ifndef INPUT_SCREEN_CAPTURE_MONITOR_LISTENER_H
#define INPUT_SCREEN_CAPTURE_MONITOR_LISTENER_H

#include "screen_capture_monitor.h"

namespace OHOS {
namespace MMI {
class InputScreenCaptureMonitorListener : public Media::ScreenCaptureMonitor::ScreenCaptureMonitorListener {
public:
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
    void OnScreenCaptureStarted(int32_t pid);
    void OnScreenCaptureFinished(int32_t pid);
#endif
};
}
}
#endif