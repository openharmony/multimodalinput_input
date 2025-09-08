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

#include "input_device_manager.h"
#include "inputsupportkeys_fuzzer.h"
#include "mmi_log.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
#undef MAX_VECTOR_SIZE
constexpr int32_t MAX_VECTOR_SIZE { 20 }; // test value
bool InputSupportKeysFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    size_t bytesSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_VECTOR_SIZE);
    std::vector<int32_t> keyCodes;
    for (int i = 0; i < bytesSize; i++) {
        keyCodes.push_back(provider.ConsumeIntegral<int32_t>());
    }
    bytesSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_VECTOR_SIZE);
    std::vector<bool> keystroke;
    for (int i = 0; i < bytesSize; i++) {
        keystroke.push_back(provider.ConsumeBool());
    }

    INPUT_DEV_MGR->SupportKeys(deviceId, keyCodes, keystroke);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::InputSupportKeysFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS