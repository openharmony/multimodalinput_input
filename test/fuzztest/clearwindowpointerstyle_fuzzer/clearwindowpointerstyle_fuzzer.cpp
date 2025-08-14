/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "clearwindowpointerstyle_fuzzer.h"

#include "libinput.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ClearWindowPointerStyleFuzzTest"

namespace OHOS {
namespace MMI {
void ClearWindowPointerStyleFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    MMI_HILOGD("ClearWindowPointerStyleFuzzTest");
    InputWindowsManager manager;
    FuzzedDataProvider provider(data, size);
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    int32_t windowId = provider.ConsumeIntegral<int32_t>();
    manager.ClearWindowPointerStyle(pid, windowId);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < sizeof(int32_t)) {
        return 0;
    }
    OHOS::MMI::ClearWindowPointerStyleFuzzTest(data, size);
    return 0;
}