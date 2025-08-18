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

#include "i_anco_consumer.h"
#include "ancoonehanddata_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoOneHandDataFuzzTest"

namespace OHOS {
namespace MMI {
bool AncoOneHandDataFuzzTest(const uint8_t *data, size_t size)
{
    AncoOneHandData ancoOne;
    FuzzedDataProvider provider(data, size);
    int32_t oneHandX = provider.ConsumeIntegral<int32_t>();
    ancoOne.oneHandX = oneHandX;
    int32_t oneHandY = provider.ConsumeIntegral<int32_t>();
    ancoOne.oneHandY = oneHandY;
    int32_t expandHeight = provider.ConsumeIntegral<int32_t>();
    ancoOne.expandHeight = expandHeight;
    int32_t scalePercent = provider.ConsumeIntegral<int32_t>();
    ancoOne.scalePercent = scalePercent;
    
    Parcel parcel;
    ancoOne.Marshalling(parcel);
    ancoOne.ReadFromParcel(parcel);
    ancoOne.Unmarshalling(parcel);
    MMI_HILOGD("AncoOneHandDataFuzzTest");
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

    OHOS::MMI::AncoOneHandDataFuzzTest(data, size);
    return 0;
}
