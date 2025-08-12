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
#include "event_resample.h"
#include "addsample_fuzzer.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AddSampleFuzzTest"

namespace OHOS {
namespace MMI {
bool AddSampleFuzzTest(FuzzedDataProvider &provider)
{
    int64_t actionTime = provider.ConsumeIntegral<int32_t>();
    int32_t coordX = provider.ConsumeIntegral<int32_t>();
    int32_t coordY = provider.ConsumeIntegral<int32_t>();
    int32_t toolType = provider.ConsumeIntegral<int32_t>();
    uint32_t id = provider.ConsumeIntegral<uint32_t>();
    auto event = std::make_unique<EventResample::MotionEvent>();
    event->actionTime = actionTime;
    EventResample::Pointer pointer = {
        .coordX = coordX,
        .coordY = coordY,
        .toolType = toolType,
        .id = id
    };
    event->pointers.insert(std::make_pair(id, pointer));
    auto outEvent = std::make_unique<EventResample::MotionEvent>();
    EventResample eventResample;
    eventResample.AddSample(outEvent.get(), event.get());
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
    FuzzedDataProvider provider(data, size);
    OHOS::MMI::AddSampleFuzzTest(provider);
    return 0;
}
