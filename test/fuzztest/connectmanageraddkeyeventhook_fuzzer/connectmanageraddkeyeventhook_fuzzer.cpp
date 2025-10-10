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
#include "connectmanageraddkeyeventhook_fuzzer.h"

#include "imultimodal_input_connect.h"
#include "multimodal_input_connect_manager.h"

namespace OHOS {
namespace MMI {
void ConnectManagerAddKeyEventHookFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t hookId = fdp.ConsumeIntegral<int32_t>();
    MultimodalInputConnectManager::GetInstance()->AddKeyEventHook(hookId);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    ConnectManagerAddKeyEventHookFuzzTest(fdp);
    return true;
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::MmiServiceFuzzTest(fdp);
    return 0;
}