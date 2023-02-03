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

#include "getfunctionkeystate_fuzzer.h"

#include "securec.h"

#include "common_method.h"
#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

void GetFunctionkeyStateFuzzTest(const uint8_t* data, size_t  size)
{
    int32_t funcKey;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(funcKey, data + startPos, size - startPos);
    InputManager::GetInstance()->GetFunctionKeyState(funcKey);

    int32_t random = 0;
    startPos += GetObject<int32_t>(funcKey, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(random, data + startPos, size - startPos);
    bool enable = (random % 2) ? false : true;
    InputManager::GetInstance()->SetFunctionKeyState(funcKey, enable);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::GetFunctionkeyStateFuzzTest(data, size);
    return 0;
}

