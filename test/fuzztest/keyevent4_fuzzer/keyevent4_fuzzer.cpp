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
#include "key_event.h"
#include "mmi_log.h"

#include "securec.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEvent4FuzzTest"

namespace OHOS {
namespace MMI {

void KeyEvent4FuzzTest(const uint8_t *data, size_t size)
{
    KeyEvent::from(nullptr);
    KeyEvent::Create();
    KeyEvent::Clone(nullptr);

    FuzzedDataProvider provider(data, size);

    funcKey = provider.ConsumeIntegral<int32_t>();
    int32_t value = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetFunctionKey(funcKey, value);

    int32_t keyIntention = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetKeyIntention(keyIntention);

    KeyEventFuzzTest_Add(provider, keyEvent);
    keyEvent.RemoveReleasedKeyItems(item);
    MMI_HILOGD("KeyEvent4FuzzTest");
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

    OHOS::MMI::KeyEvent4FuzzTest(data, size);
    return 0;
}
