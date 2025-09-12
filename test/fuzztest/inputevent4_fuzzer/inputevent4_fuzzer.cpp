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
#include "input_event.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEvent4FuzzTest"

namespace OHOS {
namespace MMI {
void InputEvent4FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    InputEvent inputEvent(eventType);

    int32_t displayId = provider.ConsumeIntegral<int32_t>();
    inputEvent.SetTargetDisplayId(displayId);

    int32_t windowId = provider.ConsumeIntegral<int32_t>();
    inputEvent.SetAgentWindowId(windowId);

    windowId = provider.ConsumeIntegral<int32_t>();
    inputEvent.SetTargetWindowId(windowId);

    bool markEnabled = provider.ConsumeBool();
    inputEvent.SetMarkEnabled(markEnabled);

    int32_t action = provider.ConsumeIntegral<int32_t>();
    inputEvent.ActionToShortStr(action);
}
} // namespace MMI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::InputEvent4FuzzTest(data, size);
    return 0;
}