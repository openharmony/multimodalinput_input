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
#include "pointeritem_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerItemFuzzTest"

namespace OHOS {
namespace MMI {

bool PointerItemFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    PointerEvent::PointerItem item;
    int32_t pointerId = provider.ConsumeIntegral<int32_t>();
    item.SetPointerId(pointerId);

    int64_t downTime = provider.ConsumeIntegral<int64_t>();
    item.SetDownTime(downTime);

    bool pressed = provider.ConsumeBool();
    item.SetPressed(pressed);

    int32_t displayX = provider.ConsumeIntegral<int32_t>();
    item.SetDisplayX(displayX);

    int32_t displayY = provider.ConsumeIntegral<int32_t>();
    item.SetDisplayY(displayY);

    MMI_HILOGD("PointerItemFuzzTest");
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

    OHOS::MMI::PointerItemFuzzTest(data, size);
    return 0;
}
