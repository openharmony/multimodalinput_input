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

#include <fuzzer/FuzzedDataProvider.h>
#include "mmi_log.h"
#include "input_device_manager.h"
#include "inputpointerdevice_fuzzer.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManagerFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {

bool InputPointerDeviceFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    bool hasPointerDevice = provider.ConsumeBool();
    bool isVisible = provider.ConsumeBool();
    bool isHotPlug = provider.ConsumeBool();

    INPUT_DEV_MGR->NotifyPointerDevice(hasPointerDevice, isVisible, isHotPlug);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::InputPointerDeviceFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS