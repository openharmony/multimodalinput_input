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

#include "key_event.h"
#include "keyevent_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventFuzzTest"

namespace OHOS {
namespace MMI {
void KeyEventFuzzTest_Add(FuzzedDataProvider &provider, KeyEvent &keyEvent)
{
    bool repeat = provider.ConsumeBool();
    keyEvent.SetRepeat(repeat);

    bool repeatKey = provider.ConsumeBool();
    keyEvent.SetRepeatKey(repeatKey);

    int32_t action = provider.ConsumeIntegral<int32_t>();
    keyEvent.ActionToShortStr(action);

    Parcel parcel;
    keyEvent.WriteToParcel(parcel);
    keyEvent.Marshalling(parcel);
    keyEvent.ReadFromParcel(parcel);
    keyEvent.Unmarshalling(parcel);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    keyEvent.ReadEnhanceDataFromParcel(parcel);

    std::vector<uint8_t> enhanceData;
    uint8_t endata = provider.ConsumeIntegral<uint8_t>();
    enhanceData.push_back(endata);
    keyEvent.SetEnhanceData(enhanceData);
#endif
}

bool KeyEventFuzzTest(const uint8_t *data, size_t size)
{
    KeyEvent::from(nullptr);
    KeyEvent::Create();
    KeyEvent::Clone(nullptr);

    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    KeyEvent keyEvent(eventType);

    keyEvent.Reset();

    int32_t keyCode = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetKeyCode(keyCode);

    int32_t keyAction = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetKeyAction(keyAction);

    KeyEvent::KeyItem item;
    keyCode = provider.ConsumeIntegral<int32_t>();
    item.SetKeyCode(keyCode);
    keyEvent.AddKeyItem(item);

    std::vector<KeyEvent::KeyItem> items;
    items.push_back(item);
    keyEvent.SetKeyItem(items);

    keyEvent.AddPressedKeyItems(item);

    keyCode = provider.ConsumeIntegral<int32_t>();
    keyEvent.GetKeyItem(keyCode);

    int32_t action = provider.ConsumeIntegral<int32_t>();
    keyEvent.ActionToString(action);

    keyCode = provider.ConsumeIntegral<int32_t>();
    keyEvent.KeyCodeToString(keyCode);

    bool fourceMonitorFlag = provider.ConsumeBool();
    keyEvent.SetFourceMonitorFlag(fourceMonitorFlag);

    keyCode = provider.ConsumeIntegral<int32_t>();
    keyEvent.TransitionFunctionKey(keyCode);

    int32_t funcKey = provider.ConsumeIntegral<int32_t>();
    keyEvent.GetFunctionKey(funcKey);

    funcKey = provider.ConsumeIntegral<int32_t>();
    int32_t value = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetFunctionKey(funcKey, value);

    int32_t keyIntention = provider.ConsumeIntegral<int32_t>();
    keyEvent.SetKeyIntention(keyIntention);

    KeyEventFuzzTest_Add(provider, keyEvent);
    keyEvent.RemoveReleasedKeyItems(item);
    MMI_HILOGD("KeyEventFuzzTest");
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

    OHOS::MMI::KeyEventFuzzTest(data, size);
    return 0;
}
