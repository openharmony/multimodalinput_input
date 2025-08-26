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

#include "key_option.h"
#include "keyoption_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyOptionFuzzTest"

namespace OHOS {
namespace MMI {
bool KeyOptionFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    KeyOption keyOption;

    std::set<int32_t> preKeys;
    int32_t key = provider.ConsumeIntegral<int32_t>();
    preKeys.insert(key);
    key = provider.ConsumeIntegral<int32_t>();
    preKeys.insert(key);
    keyOption.SetPreKeys(preKeys);

    int32_t finalKey = provider.ConsumeIntegral<int32_t>();
    keyOption.SetFinalKey(finalKey);

    bool isFinalKeyDown = provider.ConsumeBool();
    keyOption.SetFinalKeyDown(isFinalKeyDown);

    int32_t finalKeyDownDuration = provider.ConsumeIntegral<int32_t>();
    keyOption.SetFinalKeyDownDuration(finalKeyDownDuration);

    int32_t finalKeyUpDelay = provider.ConsumeIntegral<int32_t>();
    keyOption.SetFinalKeyUpDelay(finalKeyUpDelay);
    MMI_HILOGD("KeyOptionFuzzTest");
    return true;
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

    OHOS::MMI::KeyOptionFuzzTest(data, size);
    return 0;
}
