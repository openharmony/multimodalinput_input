/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or enforced by applicable law, software
 * distributed under the License is distributed on an "AS IS",
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "moduleloader_consumer_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_NAME_COUNT = 8;
constexpr size_t MAX_BUNDLE_NAME_LEN = 128;
}

void ConsumerFuzzTest(FuzzedDataProvider &fdp)
{
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_NAME_COUNT);
    std::vector<std::string> names;
    for (size_t i = 0; i < n; ++i) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
        names.emplace_back(fdp.ConsumeRandomLengthString(len));
    }

    int32_t subId = fdp.ConsumeIntegral<int32_t>();
    int64_t interval = fdp.ConsumeIntegral<int64_t>();
    MMIService::GetInstance()->SubscribeInputActive(subId, interval);
    MMIService::GetInstance()->UnsubscribeInputActive(subId);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    ConsumerFuzzTest(fdp);
    return true;
}
} // namespace MMI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    
    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::MmiServiceFuzzTest(fdp);
    return 0;
}