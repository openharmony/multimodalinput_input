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
#include "mmiservice_keyboard_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t OUT_INIT = -1;
} // namespace

void KeyboardFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t keyboardType = OUT_INIT;
    MMIService::GetInstance()->GetKeyboardType(deviceId, keyboardType);

    int32_t rate1 = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetKeyboardRepeatRate(rate1);

    int32_t rate2 = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetKeyboardRepeatRate(rate2);

    int32_t delay = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetKeyboardRepeatDelay(delay);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    KeyboardFuzzTest(fdp);
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