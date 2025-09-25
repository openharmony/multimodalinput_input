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
#include <vector>
#include "eventtransmitinfrared_fuzzer.h"
#include "input_manager.h"

static constexpr int32_t MAX_SIZE = 64;

namespace OHOS {
namespace MMI {
void EventTransmitInfraredFuzzTest(FuzzedDataProvider &fdp)
{
    int64_t number = fdp.ConsumeIntegral<int64_t>();
    int32_t vectorSize = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_SIZE);
    std::vector<int64_t>  pattern;
    for (int i = 0; i < vectorSize; ++i) {
        pattern.push_back(fdp.ConsumeIntegral<int64_t>());
    }
    InputManager::GetInstance()->TransmitInfrared(number, pattern);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    EventTransmitInfraredFuzzTest(fdp);
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