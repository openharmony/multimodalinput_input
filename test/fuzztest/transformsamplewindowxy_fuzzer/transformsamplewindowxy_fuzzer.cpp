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
#include "transformsamplewindowxy_fuzzer.h"
#include "securec.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TransformSampleWindowXYFuzzTest"

namespace OHOS {
namespace MMI {
bool TransformSampleWindowXYFuzzTest(FuzzedDataProvider &provider)
{
    PointerEvent::PointerItem pointerItem;
    int32_t windowX = provider.ConsumeIntegral<int32_t>();
    int32_t windowY = provider.ConsumeIntegral<int32_t>();
    double logicX = provider.ConsumeFloatingPoint<double>();
    double logicY = provider.ConsumeFloatingPoint<double>();
    pointerItem.SetToolWindowX(windowX);
    pointerItem.SetToolWindowY(windowY);
    EventResample eventResample;
    eventResample.TransformSampleWindowXY(nullptr, pointerItem, logicX, logicY);
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
    OHOS::MMI::TransformSampleWindowXYFuzzTest(provider);
    return 0;
}
