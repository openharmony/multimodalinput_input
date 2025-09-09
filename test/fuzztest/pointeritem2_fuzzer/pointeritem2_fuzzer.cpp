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

#include "pointer_event.h"
#include "pointeritem2_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerItem2FuzzTest"

namespace OHOS {
namespace MMI {

void PointerItem2FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    PointerEvent::PointerItem item;

    int32_t windowX = provider.ConsumeIntegral<int32_t>();
    item.SetWindowX(windowX);

    int32_t windowY = provider.ConsumeIntegral<int32_t>();
    item.SetWindowY(windowY);

    double displayXPos = provider.ConsumeFloatingPoint<double>();
    item.SetDisplayXPos(displayXPos);

    double displayYPos = provider.ConsumeFloatingPoint<double>();
    item.SetDisplayYPos(displayYPos);

    double windowXPos = provider.ConsumeFloatingPoint<double>();
    item.SetWindowXPos(windowXPos);
    MMI_HILOGD("PointerItem2FuzzTest");
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

    OHOS::MMI::PointerItem2FuzzTest(data, size);
    return 0;
}
