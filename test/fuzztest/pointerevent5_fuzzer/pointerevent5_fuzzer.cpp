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
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEvent5FuzzTest"

namespace OHOS {
namespace MMI {
void PointerEvent5FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    PointerEvent pointEvent(eventType);

    int32_t buttonId = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetButtonId(buttonId);
    int32_t buttonId1 = provider.ConsumeIntegral<int32_t>();
    pointEvent.SetButtonPressed(buttonId1);
    int32_t buttonId2 = provider.ConsumeIntegral<int32_t>();
    pointEvent.IsButtonPressed(buttonId2);
    int32_t buttonId3 = provider.ConsumeIntegral<int32_t>();
    pointEvent.DeleteReleaseButton(buttonId3);

    MMI_HILOGD("PointerEvent5FuzzTest");
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

    OHOS::MMI::PointerEvent5FuzzTest(data, size);
    return 0;
}
