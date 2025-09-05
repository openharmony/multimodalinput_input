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

#include "connectproxy9_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "multimodal_input_connect_manager.h"
#include "multimodal_input_connect_proxy.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ConnectProxy9FuzzTest"

namespace OHOS {
namespace MMI {

void GetTouchpadPinchSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadPinchSwitch(switchFlag);
}

void SetTouchpadSwipeSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadSwipeSwitch(switchFlag);
}

void GetTouchpadSwipeSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadSwipeSwitch(switchFlag);
}

void SetTouchpadRightClickTypeFuzz(FuzzedDataProvider &fdp)
{
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->SetTouchpadRightClickType(type);
}

void GetTouchpadRightClickTypeFuzz(FuzzedDataProvider &fdp)
{
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    MULTIMODAL_INPUT_CONNECT_MGR->GetTouchpadRightClickType(type);
}


void ConnectProxy9FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    GetTouchpadPinchSwitchFuzz(fdp);
    SetTouchpadSwipeSwitchFuzz(fdp);
    GetTouchpadSwipeSwitchFuzz(fdp);
    SetTouchpadRightClickTypeFuzz(fdp);
    GetTouchpadRightClickTypeFuzz(fdp);
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

    OHOS::MMI::ConnectProxy9FuzzTest(data, size);
    return 0;
}
