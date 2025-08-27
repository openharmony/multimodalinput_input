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
#include "mmiservice_hotkey_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
void HotkeyFuzzTest(FuzzedDataProvider &fdp)
{
    KeyOption keyOption;
    keyOption.finalKey_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isFinalKeyDown_ = fdp.ConsumeBool();
    keyOption.finalKeyDownDuration_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.finalKeyUpDelay_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isRepeat_ = fdp.ConsumeBool();
    keyOption.priority_ = SubscribePriority::PRIORITY_0;

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SubscribeHotkey(subscribeId, keyOption);
    MMIService::GetInstance()->UnsubscribeHotkey(subscribeId);

    MmiEventMap eventMap;
    MMIService::GetInstance()->GetAllMmiSubscribedEvents(eventMap);

    int32_t funcKey = fdp.ConsumeIntegral<int32_t>();
    bool state = fdp.ConsumeBool();
    MMIService::GetInstance()->GetFunctionKeyState(funcKey, state);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    HotkeyFuzzTest(fdp);
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