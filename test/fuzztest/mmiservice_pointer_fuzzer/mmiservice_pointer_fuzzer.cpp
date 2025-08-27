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
#include "mmiservice_pointer_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
}

void PointerFuzzTest(FuzzedDataProvider &fdp)
{
    bool visible = fdp.ConsumeBool();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerVisible(visible, priority);

    int32_t color = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerColor(color);

    int32_t sizeArg = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerSize(sizeArg);

    int32_t speed1 = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerSpeed(speed1);

    int32_t speed2 = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetPointerSpeed(speed2);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    PointerFuzzTest(fdp);
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