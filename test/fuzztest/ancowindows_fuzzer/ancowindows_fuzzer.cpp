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

#include "i_anco_consumer.h"
#include "ancowindows_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoWindowsFuzzTest"

namespace OHOS {
namespace MMI {
bool AncoWindowsFuzzTest(const uint8_t *data, size_t size)
{
    AncoWindows ancoWindows;
    FuzzedDataProvider provider(data, size);
    bool update = provider.ConsumeBool();
    ancoWindows.updateType = update ? ANCO_WINDOW_UPDATE_TYPE::ALL : ANCO_WINDOW_UPDATE_TYPE::INCREMENT;

    int32_t focusWindowId = provider.ConsumeIntegral<int32_t>();
    ancoWindows.focusWindowId = focusWindowId;

    AncoWindowInfo windowInfo;
    int32_t id = provider.ConsumeIntegral<int32_t>();
    windowInfo.id = id;
    ancoWindows.windows.push_back(windowInfo);

    id = provider.ConsumeIntegral<int32_t>();
    AncoWindowInfo windowInfo2;
    windowInfo2.id = id;
    ancoWindows.windows.push_back(windowInfo2);

    Parcel parcel;
    ancoWindows.Marshalling(parcel);
    ancoWindows.ReadFromParcel(parcel);
    ancoWindows.Unmarshalling(parcel);
    MMI_HILOGD("AncoWindowsFuzzTest");
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

    OHOS::MMI::AncoWindowsFuzzTest(data, size);
    return 0;
}
