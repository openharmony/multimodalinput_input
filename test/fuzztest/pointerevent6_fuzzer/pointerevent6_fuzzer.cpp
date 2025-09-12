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
#define MMI_LOG_TAG "PointerEvent6FuzzTest"

namespace OHOS {
namespace MMI {
void PointerEvent6FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    PointerEvent pointEvent(eventType);

    double axisValue = provider.ConsumeFloatingPoint<double>();
    PointerEvent::AxisType axisType =
        static_cast<PointerEvent::AxisType>(provider.ConsumeIntegralInRange<int32_t>(0, 14));
    pointEvent.SetAxisValue(axisType, axisValue);
    pointEvent.GetAxisValue(axisType);

    int32_t axes = provider.ConsumeIntegral<int32_t>();
    pointEvent.HasAxis(axes, axisType);
    pointEvent.ClearAxisStatus(axisType);

    MMI_HILOGD("PointerEvent6FuzzTest");
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

    OHOS::MMI::PointerEvent6FuzzTest(data, size);
    return 0;
}
