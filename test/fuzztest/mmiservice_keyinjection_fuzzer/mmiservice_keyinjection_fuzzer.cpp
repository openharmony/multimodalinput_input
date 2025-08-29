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
#include "mmiservice_keyinjection_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
void KeyInjectionFuzzTest(FuzzedDataProvider &fdp)
{
    auto keyEvent = KeyEvent::Create();
    if (keyEvent) {
        keyEvent->SetKeyCode(fdp.ConsumeIntegral<int32_t>());
        keyEvent->SetKeyAction(fdp.ConsumeIntegral<int32_t>());
        bool isNativeInject = fdp.ConsumeBool();
        MMIService::GetInstance()->InjectKeyEvent(*keyEvent, isNativeInject);

        int32_t pid = fdp.ConsumeIntegral<int32_t>();
        MMIService::GetInstance()->CheckInjectKeyEvent(keyEvent, pid, isNativeInject);
    }
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    KeyInjectionFuzzTest(fdp);
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