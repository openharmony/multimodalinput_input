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

#include "connectproxy5_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy5FuzzTest"

namespace OHOS {
namespace MMI {
void SubscribeTabletProximityFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SubscribeTabletProximity(subscribeId);
}

void UnsubscribetabletProximityFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribetabletProximity(subscribeId);
}

void SubscribeLongPressEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    LongPressRequest longPressRequest;
    longPressRequest.fingerCount = fdp.ConsumeIntegral<int32_t>();
    longPressRequest.duration = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SubscribeLongPressEvent(subscribeId, longPressRequest);
}

void UnsubscribeLongPressEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeLongPressEvent(subscribeId);
}

void SetCurrentUserFuzz(FuzzedDataProvider &fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetCurrentUser(userId);
}

void ConnectProxy5FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SubscribeTabletProximityFuzz(fdp);
    UnsubscribetabletProximityFuzz(fdp);
    SubscribeLongPressEventFuzz(fdp);
    UnsubscribeLongPressEventFuzz(fdp);
    SetCurrentUserFuzz(fdp);
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

    OHOS::MMI::ConnectProxy5FuzzTest(data, size);
    return 0;
}
