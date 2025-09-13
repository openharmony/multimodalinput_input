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
#include "getallmmisubscribedevents_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetMouseScrollRowsFuzzTest"

namespace OHOS {
namespace MMI {
void GetAllMmiSubscribedEventsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> map = {
        {{provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>(), provider.ConsumeBytesAsString(10)},
            provider.ConsumeIntegral<int32_t>()},
        {{provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>(), provider.ConsumeBytesAsString(10)},
            provider.ConsumeIntegral<int32_t>()},
        {{provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>(), provider.ConsumeBytesAsString(10)},
            provider.ConsumeIntegral<int32_t>()}
    };

    InputManager::GetInstance()->GetAllMmiSubscribedEvents(map);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < 0) {
        return 0;
    }

    /* Run your code on data */
    OHOS::MMI::GetAllMmiSubscribedEventsFuzzTest(data, size);
    return 0;
}

