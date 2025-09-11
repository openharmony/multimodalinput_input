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

#include "axis_event.h"
#include "axisevent_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AxisEventFuzzTest"

namespace OHOS {
namespace MMI {
bool AxisEventFuzzTest(const uint8_t *data, size_t size)
{
    AxisEvent::from(nullptr);
    auto axisEvent = AxisEvent::Create();
    if (axisEvent == nullptr) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    int32_t axisAction = provider.ConsumeIntegral<int32_t>();
    axisEvent->SetAxisAction(axisAction);

    int32_t axisType = provider.ConsumeIntegral<int32_t>();
    axisEvent->SetAxisType(axisType);

    int32_t axisValue = provider.ConsumeIntegral<int32_t>();
    axisEvent->SetAxisValue(axisValue);

    int32_t action = provider.ConsumeIntegral<int32_t>();
    axisEvent->ActionToShortStr(action);
    MMI_HILOGD("AxisEventFuzzTest");
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

    OHOS::MMI::AxisEventFuzzTest(data, size);
    return 0;
}
