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
#include "key_option.h"
#include "keyoptionparcel_fuzzer.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyOptionParcelFuzzTest"

namespace OHOS {
namespace MMI {
void KeyOptionParcelFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    KeyOption keyOption;

    bool isRepeat = provider.ConsumeBool();
    keyOption.SetRepeat(isRepeat);

    int32_t priority = provider.ConsumeIntegral<int32_t>();
    keyOption.SetPriority(priority);

    Parcel parcel;
    keyOption.ReadFromParcel(parcel);
    keyOption.WriteToParcel(parcel);
    MMI_HILOGD("KeyOptionParcelFuzzTest");
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

    OHOS::MMI::KeyOptionParcelFuzzTest(data, size);
    return 0;
}
