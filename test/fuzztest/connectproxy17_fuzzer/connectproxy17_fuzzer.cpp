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
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy17FuzzTest"

namespace OHOS {
namespace MMI {
constexpr size_t MAX_NAME_COUNT = 8;
constexpr size_t MAX_BUNDLE_NAME_LEN = 128;
void QuerySwitchStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t switchType = fdp.ConsumeIntegral<int32_t>();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->QuerySwitchStatus(switchType, status);
}

void SetKnuckleSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool isKnuckleSwitch = fdp.ConsumeIntegral<bool>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetKnuckleSwitch(isKnuckleSwitch);
}

void SetInputDeviceConsumerFuzz(FuzzedDataProvider &fdp)
{
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_NAME_COUNT);
    std::vector<std::string> deviceNames;
    for (size_t i = 0; i < n; ++i) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
        deviceNames.emplace_back(fdp.ConsumeRandomLengthString(len));
    }
    MULTIMODAL_INPUT_CONNECT_MGR->SetInputDeviceConsumer(deviceNames);
}

void ClearInputDeviceConsumerFuzz(FuzzedDataProvider &fdp)
{
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_NAME_COUNT);
    std::vector<std::string> deviceNames;
    for (size_t i = 0; i < n; ++i) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
        deviceNames.emplace_back(fdp.ConsumeRandomLengthString(len));
    }
    MULTIMODAL_INPUT_CONNECT_MGR->ClearInputDeviceConsumer(deviceNames);
}

void AddKeyEventHookFuzz(FuzzedDataProvider &fdp)
{
    int32_t hookId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->AddKeyEventHook(hookId);
}

void ConnectProxy17FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    QuerySwitchStatusFuzz(fdp);
    SetKnuckleSwitchFuzz(fdp);
    SetInputDeviceConsumerFuzz(fdp);
    ClearInputDeviceConsumerFuzz(fdp);
    AddKeyEventHookFuzz(fdp);
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

    OHOS::MMI::ConnectProxy17FuzzTest(data, size);
    return 0;
}
