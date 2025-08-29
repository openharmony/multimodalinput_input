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
#include "mmiservice_gesture_fuzzer.h"

#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_GESTURE_FINGERS = 10;
} // namespace

void GestureFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    uint32_t gestureType = fdp.ConsumeIntegral<uint32_t>();
    int32_t fingers = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_GESTURE_FINGERS);

    MMIService::GetInstance()->AddGestureMonitor(handlerType, eventType, gestureType, fingers);
    MMIService::GetInstance()->RemoveGestureMonitor(handlerType, eventType, gestureType, fingers);

    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->ObserverAddInputHandler(pid);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    GestureFuzzTest(fdp);
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