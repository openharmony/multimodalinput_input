/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or enforced by applicable law, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "mmiservice_handler_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_PREINPUT_KEYS = 8;
} // namespace

void HandlerFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t raw = fdp.ConsumeIntegralInRange<int32_t>(
        static_cast<int32_t>(InputHandlerType::INTERCEPTOR),
        static_cast<int32_t>(InputHandlerType::MONITOR)
    );
    InputHandlerType ht = static_cast<InputHandlerType>(raw);
    MMIService::GetInstance()->CheckInputHandlerVaild(ht);

    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    uint32_t deviceTags = fdp.ConsumeIntegral<uint32_t>();
    MMIService::GetInstance()->AddInputHandler(handlerType, eventType, priority, deviceTags);

    int32_t handlerId = fdp.ConsumeIntegral<int32_t>();
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_PREINPUT_KEYS);
    std::vector<int32_t> keys;
    for (size_t i = 0; i < n; i++) {
        keys.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    MMIService::GetInstance()->AddPreInputHandler(handlerId, eventType, keys);
    MMIService::GetInstance()->RemovePreInputHandler(handlerId);

    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->ObserverAddInputHandler(pid);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    HandlerFuzzTest(fdp);
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