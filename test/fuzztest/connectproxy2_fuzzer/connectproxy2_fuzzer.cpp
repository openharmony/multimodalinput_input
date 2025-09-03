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

#include "connectproxy2_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy2FuzzTest"

namespace OHOS {
namespace MMI {
void MarkProcessedFuzz(FuzzedDataProvider &fdp)
{
    int32_t eventType = fdp.ConsumeIntegral<int32_t>();
    int32_t eventId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->MarkProcessed(eventType, eventId);
}

void EnableCombineKeyFuzz(FuzzedDataProvider &fdp)
{
    int32_t enable = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->EnableCombineKey(enable);
}

void SetKeyboardRepeatRateFuzz(FuzzedDataProvider &fdp)
{
    int32_t rate = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetKeyboardRepeatRate(rate);
}

void GetKeyboardRepeatDelayFuzz(FuzzedDataProvider &fdp)
{
    int32_t delay = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetKeyboardRepeatDelay(delay);
}

void GetKeyboardRepeatRateFuzz(FuzzedDataProvider &fdp)
{
    int32_t rate = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetKeyboardRepeatRate(rate);
}

void ConnectProxy2FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    MarkProcessedFuzz(fdp);
    EnableCombineKeyFuzz(fdp);
    SetKeyboardRepeatRateFuzz(fdp);
    GetKeyboardRepeatDelayFuzz(fdp);
    GetKeyboardRepeatRateFuzz(fdp);
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

    OHOS::MMI::ConnectProxy2FuzzTest(data, size);
    return 0;
}
