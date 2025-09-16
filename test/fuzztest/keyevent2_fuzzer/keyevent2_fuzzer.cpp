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
#define MMI_LOG_TAG "KeyEvent2FuzzTest"

namespace OHOS {
namespace MMI {

void KeyEvent2FuzzTest(const uint8_t *data, size_t size)
{
    KeyEvent::from(nullptr);
    KeyEvent::Create();
    KeyEvent::Clone(nullptr);

    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    KeyEvent keyEvent(eventType);

    int32_t keyAction = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetKeyAction(keyAction);

    KeyEvent::KeyItem item;
    int32_t keyCode = provider.ConsumeIntegral<int32_t>();
    item.SetKeyCode(keyCode);
    keyEvent.AddKeyItem(item);

    std::vector<KeyEvent::KeyItem> items;
    items.push_back(item);
    keyEvent.SetKeyItem(items);

    keyEvent.AddPressedKeyItems(item);

    keyCode = provider.ConsumeIntegral<int32_t>();
    keyEvent.GetKeyItem(keyCode);
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

    OHOS::MMI::KeyEvent2FuzzTest(data, size);
    return 0;
}
