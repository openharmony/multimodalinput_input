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

#include "connectproxy3_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy3FuzzTest"

namespace OHOS {
namespace MMI {
void AddPreInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerId = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    std::vector<int32_t> keys = {
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()
    };
    MULTIMODAL_INPUT_CONNECT_MGR->AddPreInputHandler(handlerId, eventType, keys);
}

void RemovePreInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->RemovePreInputHandler(handlerId);
}

void AddGestureMonitorFuzz(FuzzedDataProvider &fdp)
{
    int32_t type = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    InputHandlerType handlerType = static_cast<InputHandlerType>(type);
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    uint32_t gestureType = fdp.ConsumeIntegral<uint32_t>();
    int32_t fingers = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->AddGestureMonitor(handlerType, eventType, gestureType, fingers);
}

void RemoveGestureMonitorFuzz(FuzzedDataProvider &fdp)
{
    int32_t type = fdp.ConsumeIntegralInRange<int32_t>(0, 2);
    InputHandlerType handlerType = static_cast<InputHandlerType>(type);
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    uint32_t gestureType = fdp.ConsumeIntegral<uint32_t>();
    int32_t fingers = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->RemoveGestureMonitor(handlerType, eventType, gestureType, fingers);
}

void UnsubscribeKeyEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeKeyEvent(subscribeId);
}

void ConnectProxy3FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    AddPreInputHandlerFuzz(fdp);
    RemovePreInputHandlerFuzz(fdp);
    AddGestureMonitorFuzz(fdp);
    RemoveGestureMonitorFuzz(fdp);
    UnsubscribeKeyEventFuzz(fdp);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::ConnectProxy3FuzzTest(data, size);
    return 0;
}
