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

#include "mmi_log.h"
#include "input_device_manager.h"
#include "ismatchkeys_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputDeviceManagerFuzzTest"

struct udev_device {
    int32_t tags;
};

struct libinput_device {
    struct udev_device udevDev;
    int32_t busType;
    int32_t version;
    int32_t product;
    int32_t vendor;
    std::string name;
};

namespace OHOS {
namespace MMI {
void IsMatchKeysFuzzTest(FuzzedDataProvider &provider)
{
    int32_t tags = provider.ConsumeIntegral<int32_t>();
    struct libinput_device libDev {
        .udevDev { tags },
        .busType = provider.ConsumeIntegral<int32_t>(),
        .version = provider.ConsumeIntegral<int32_t>(),
        .product = provider.ConsumeIntegral<int32_t>(),
        .vendor = provider.ConsumeIntegral<int32_t>(),
        .name = provider.ConsumeBytesAsString(5),
    };
    std::vector<int32_t> keyCodes = {
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>(),
        provider.ConsumeIntegral<int32_t>()
    };
    INPUT_DEV_MGR->IsMatchKeys(&libDev, keyCodes);
}

void ParseDeviceIdFuzzTest(FuzzedDataProvider &provider)
{
    int32_t tags = provider.ConsumeIntegral<int32_t>();
    struct libinput_device libDev {
        .udevDev { tags },
        .busType = provider.ConsumeIntegral<int32_t>(),
        .version = provider.ConsumeIntegral<int32_t>(),
        .product = provider.ConsumeIntegral<int32_t>(),
        .vendor = provider.ConsumeIntegral<int32_t>(),
        .name = provider.ConsumeBytesAsString(5),
    };
    INPUT_DEV_MGR->ParseDeviceId(&libDev);
}

void OnInputDeviceAddedFuzzTest(FuzzedDataProvider &provider)
{
    int32_t tags = provider.ConsumeIntegral<int32_t>();
    struct libinput_device libDev {
        .udevDev { tags },
        .busType = provider.ConsumeIntegral<int32_t>(),
        .version = provider.ConsumeIntegral<int32_t>(),
        .product = provider.ConsumeIntegral<int32_t>(),
        .vendor = provider.ConsumeIntegral<int32_t>(),
        .name = provider.ConsumeBytesAsString(5),
    };
    INPUT_DEV_MGR->OnInputDeviceAdded(&libDev);
}

void IsTouchDeviceFuzzTest(FuzzedDataProvider &provider)
{
    int32_t tags = provider.ConsumeIntegral<int32_t>();
    struct libinput_device libDev {
        .udevDev { tags },
        .busType = provider.ConsumeIntegral<int32_t>(),
        .version = provider.ConsumeIntegral<int32_t>(),
        .product = provider.ConsumeIntegral<int32_t>(),
        .vendor = provider.ConsumeIntegral<int32_t>(),
        .name = provider.ConsumeBytesAsString(5),
    };
    INPUT_DEV_MGR->IsTouchDevice(&libDev);
}

void FindInputDeviceIdFuzzTest(FuzzedDataProvider &provider)
{
    int32_t tags = provider.ConsumeIntegral<int32_t>();
    struct libinput_device libDev {
        .udevDev { tags },
        .busType = provider.ConsumeIntegral<int32_t>(),
        .version = provider.ConsumeIntegral<int32_t>(),
        .product = provider.ConsumeIntegral<int32_t>(),
        .vendor = provider.ConsumeIntegral<int32_t>(),
        .name = provider.ConsumeBytesAsString(5),
    };
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    InputDeviceManager::InputDeviceInfo deviceInfo;
    deviceInfo.inputDeviceOrigin = &libDev;
    deviceInfo.isRemote = provider.ConsumeBool();
    deviceInfo.enable = provider.ConsumeBool();
    INPUT_DEV_MGR->inputDevice_.insert(std::make_pair(deviceId, deviceInfo));
    INPUT_DEV_MGR->FindInputDeviceId(&libDev);
}

bool LibinputDeviceManagerFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    IsMatchKeysFuzzTest(provider);
    ParseDeviceIdFuzzTest(provider);
    OnInputDeviceAddedFuzzTest(provider);
    IsTouchDeviceFuzzTest(provider);
    FindInputDeviceIdFuzzTest(provider);
    return true;
}
} // namespace MMI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::LibinputDeviceManagerFuzzTest(data, size);
    return 0;
}