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

#include "connectproxy4_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy4FuzzTest"

namespace OHOS {
namespace MMI {
void SubscribeHotkeyFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    keyOption->finalKey_ = fdp.ConsumeIntegral<int32_t>();
    keyOption->isFinalKeyDown_ = fdp.ConsumeBool();
    keyOption->finalKeyDownDuration_ = fdp.ConsumeIntegral<int32_t>();
    keyOption->finalKeyUpDelay_ = fdp.ConsumeIntegral<int32_t>();
    keyOption->isRepeat_ = fdp.ConsumeBool();
    keyOption->priority_ = SubscribePriority::PRIORITY_0;

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SubscribeHotkey(subscribeId, keyOption);
}

void UnsubscribeHotkeyFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeHotkey(subscribeId);
}

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
void SubscribeKeyMonitorFuzz(FuzzedDataProvider &fdp)
{
    KeyMonitorOption keyOption;
    MULTIMODAL_INPUT_CONNECT_MGR->SubscribeKeyMonitor(keyOption);
}

void UnsubscribeKeyMonitorFuzz(FuzzedDataProvider &fdp)
{
    KeyMonitorOption keyOption;
    MULTIMODAL_INPUT_CONNECT_MGR->UnsubscribeKeyMonitor(keyOption);
}
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER

void GetTouchpadScrollDirectionFuzz(FuzzedDataProvider &fdp)
{
    bool state = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadScrollDirection(state);
}

void ConnectProxy4FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    SubscribeHotkeyFuzz(fdp);
    UnsubscribeHotkeyFuzz(fdp);
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    SubscribeKeyMonitorFuzz(fdp);
    UnsubscribeKeyMonitorFuzz(fdp);
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    GetTouchpadScrollDirectionFuzz(fdp);
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

    OHOS::MMI::ConnectProxy4FuzzTest(data, size);
    return 0;
}
