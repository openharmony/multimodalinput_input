/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or enforced by applicable law, software
 * distributed on an "AS IS",
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>
#include "moduleloader_permission_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
void PermissionFuzzTest(FuzzedDataProvider &fdp)
{
    bool skip = fdp.ConsumeBool();
    MMIService::GetInstance()->SkipPointerLayer(skip);

    uint32_t type = fdp.ConsumeIntegral<uint32_t>();
    bool enable = fdp.ConsumeBool();
    MMIService::GetInstance()->SwitchScreenCapturePermission(type, enable);

    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    uint64_t tid = fdp.ConsumeIntegral<uint64_t>();
    MMIService::GetInstance()->SetClientInfo(pid, tid);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    PermissionFuzzTest(fdp);
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