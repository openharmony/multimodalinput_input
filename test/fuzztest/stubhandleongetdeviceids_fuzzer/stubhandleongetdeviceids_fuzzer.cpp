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

#include <fuzzer/FuzzedDataProvider.h>
#include "stubhandleongetdeviceids_fuzzer.h"

#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubHandleAllocSocketFdFuzzTest"

class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

namespace OHOS {
namespace MMI {

void StubHandleOnGetDeviceIdsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::vector<int32_t> ids = {
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>()
    };

    MMIService::GetInstance()->OnGetDeviceIds(ids);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::StubHandleOnGetDeviceIdsFuzzTest(data, size);
    return 0;
}
