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

#include "handlewindowinputtype_fuzzer.h"

#include "libinput.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HandleWindowInputTypeFuzzTest"

namespace OHOS {
namespace MMI {
void HandleWindowInputTypeFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    MMI_HILOGD("HandleWindowInputTypeFuzzTest");
    FuzzedDataProvider provider(data, size);
    InputWindowsManager manager;
    WindowInfo window;
    int32_t windowName = provider.ConsumeIntegral<int32_t>();
    window.windowNameType = windowName;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int32_t pointerId = provider.ConsumeIntegral<int32_t>();
    int32_t sourceType = provider.ConsumeIntegral<int32_t>();
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetSourceType(sourceType);
    manager.HandleWindowInputType(window, pointerEvent);
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
    OHOS::MMI::HandleWindowInputTypeFuzzTest(data, size);
    return 0;
}

