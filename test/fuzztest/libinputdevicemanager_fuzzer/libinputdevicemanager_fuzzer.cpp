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

#include "mmi_log.h"
#include "input_device_manager.h"
#include "libinputdevicemanager_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
void DumpFuzzTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> args = {
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5)
    };
    INPUT_DEV_MGR->Dump(fd, args);
}

void DumpDeviceListFuzzTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    std::vector<std::string> args = {
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5),
        provider.ConsumeBytesAsString(5)
    };
    INPUT_DEV_MGR->DumpDeviceList(fd, args);
}

bool LibinputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    DumpFuzzTest(provider);
    DumpDeviceListFuzzTest(provider);
    return true;
}
} // namespace MMI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::LibinputDeviceManagerFuzzTest(data, size);
    return 0;
}