/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "setscreenlocked_fuzzer.h"

#include "display_event_monitor.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "input_device_manager.h"
#include "libinput.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetScreenLockedFuzzTest"

namespace OHOS {
namespace MMI {
void SetScreenLocked(const uint8_t *data, size_t  size)
{
    if (data == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    bool screenStatus  = provider.ConsumeBool();
    DisplayEventMonitor displayEventMonitor;
    displayEventMonitor.SetScreenLocked(screenStatus);
    MMI_HILOGD("SetScreenLockedFuzzTest");
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::SetScreenLocked(data, size);
    return 0;
}
