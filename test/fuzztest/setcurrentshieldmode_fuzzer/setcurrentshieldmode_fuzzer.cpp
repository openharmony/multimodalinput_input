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

#include "fuzzer/FuzzedDataProvider.h"
#include "input_device_manager.h"
#include "key_event_normalize.h"
#include "libinput.h"
#include "mmi_log.h"
#include "setcurrentshieldmode_fuzzer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetCurrentShieldModeFuzzTest"

namespace OHOS {
namespace MMI {
void SetCurrentShieldModeFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    MMI_HILOGD("SetCurrentShieldModeFuzzTest");
    FuzzedDataProvider provider(data, size);
    int32_t shieldMode = provider.ConsumeIntegral<int32_t>();
    KeyEventHdr->SetCurrentShieldMode(shieldMode);
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
    OHOS::MMI::SetCurrentShieldModeFuzzTest(data, size);
    return 0;
}

