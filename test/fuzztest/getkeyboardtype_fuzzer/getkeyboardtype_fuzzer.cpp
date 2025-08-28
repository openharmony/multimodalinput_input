/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "getkeyboardtype_fuzzer.h"

#include "input_manager.h"

namespace OHOS {
namespace MMI {
void GetKeyboardTypeFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    auto callback = [](int32_t) {};
    InputManager::GetInstance()->GetKeyboardType(deviceId, callback);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    GetKeyboardTypeFuzzTest(fdp);
    return true;
}

} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::MmiServiceFuzzTest(fdp);
    return 0;
}