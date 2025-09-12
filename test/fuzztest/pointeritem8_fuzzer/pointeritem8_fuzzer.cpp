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
#include "mmi_log.h"
#include "pointer_event.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerItem8FuzzTest"

namespace OHOS {
namespace MMI {

void PointerItem8FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    PointerEvent::PointerItem item;

    int32_t rawDx = provider.ConsumeIntegral<int32_t>();
    item.SetRawDx(rawDx);

    int32_t rawDy = provider.ConsumeIntegral<int32_t>();
    item.SetRawDy(rawDy);

    int32_t originPointerId = provider.ConsumeIntegral<int32_t>();
    item.SetOriginPointerId(originPointerId);

    int32_t rawDisplayX = provider.ConsumeIntegral<int32_t>();
    item.SetRawDisplayX(rawDisplayX);

    int32_t rawDisplayY = provider.ConsumeIntegral<int32_t>();
    item.SetRawDisplayY(rawDisplayY);
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

    OHOS::MMI::PointerItem8FuzzTest(data, size);
    return 0;
}
