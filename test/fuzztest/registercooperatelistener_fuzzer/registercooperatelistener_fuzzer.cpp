/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "registercooperatelistener_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"
#include "i_input_device_cooperate_listener.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "RegisterCooperateListenerFuzzTest" };
} // namespace

class InputDeviceCooperateListenerTest : public IInputDeviceCooperateListener {
public:
    InputDeviceCooperateListenerTest() : IInputDeviceCooperateListener() {}
    void OnCooperateMessage(const std::string &deviceId, CooperationMessage msg) override
    {
        MMI_HILOGD("RegisterCooperateListenerFuzzTest");
    };
};

void RegisterCooperateListenerFuzzTest(const uint8_t* data, size_t size)
{
    std::shared_ptr<InputDeviceCooperateListenerTest> consumer = std::make_shared<InputDeviceCooperateListenerTest>();
    InputManager::GetInstance()->RegisterCooperateListener(consumer);
    InputManager::GetInstance()->UnregisterCooperateListener(consumer);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::RegisterCooperateListenerFuzzTest(data, size);
    return 0;
}
