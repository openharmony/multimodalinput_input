/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "appendextradata_fuzzer.h"

#include "input_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_BUFFER_SIZE = 512;
}
void AppendExtraDataFuzzTest(FuzzedDataProvider &fdp)
{
    ExtraData extraData;
    extraData.appended = fdp.ConsumeBool();
    extraData.sourceType = fdp.ConsumeIntegral<int32_t>();
    extraData.pointerId = fdp.ConsumeIntegral<int32_t>();

    size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    extraData.buffer = fdp.ConsumeBytes<uint8_t>(len);

    InputManager::GetInstance()->AppendExtraData(extraData);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    AppendExtraDataFuzzTest(fdp);
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