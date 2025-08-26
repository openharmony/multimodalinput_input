/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "setmousescrollrows_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetMouseScrollRowsFuzzTest"

namespace OHOS {
namespace MMI {
void SetMouseScrollRowsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t rowsBefore = fdp.ConsumeIntegral<int32_t>();
    int32_t rowsAfter;
    MMI_HILOGD("SetMouseScrollRows start");
    InputManager::GetInstance()->SetMouseScrollRows(rowsBefore);
    InputManager::GetInstance()->GetMouseScrollRows(rowsAfter);
}

void SetPointerSizeFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t pointerSizeBefore = fdp.ConsumeIntegral<int32_t>();
    int32_t pointerSizeAfter;
    InputManager::GetInstance()->SetPointerSize(pointerSizeBefore);
    InputManager::GetInstance()->GetPointerSize(pointerSizeAfter);
}

void GetAllMmiSubscribedEventsFuzzTest(const uint8_t* data, size_t size)
{
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> map;
    MMI_HILOGD("GetAllMmiSubscribedEventsFuzzTest start");
    InputManager::GetInstance()->GetAllMmiSubscribedEvents(map);
}

void SetNapStatusFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    InputManager::GetInstance()->SetNapStatus(pid, uid, bundleName, state);
}

void SetHoverScrollStateFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    bool state = fdp.ConsumeBool();
    InputManager::GetInstance()->SetHoverScrollState(state);
    InputManager::GetInstance()->GetHoverScrollState(state);
}

void PointerColorFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t color = fdp.ConsumeIntegralInRange(0, 0x00FFFFFF);
    InputManager::GetInstance()->SetPointerColor(color);
    InputManager::GetInstance()->GetPointerColor(color);
}

void ClearWindowPointerStyleFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    InputManager::GetInstance()->ClearWindowPointerStyle(pid, uid);
}

void SetKeyboardRepeatDelayFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t delayTime = fdp.ConsumeIntegral<int32_t>();
    InputManager::GetInstance()->SetKeyboardRepeatDelay(delayTime);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SetMouseScrollRowsFuzzTest(data, size);
    OHOS::MMI::SetPointerSizeFuzzTest(data, size);
    OHOS::MMI::GetAllMmiSubscribedEventsFuzzTest(data, size);
    OHOS::MMI::SetNapStatusFuzzTest(data, size);
    OHOS::MMI::SetHoverScrollStateFuzzTest(data, size);
    OHOS::MMI::PointerColorFuzzTest(data, size);
    OHOS::MMI::ClearWindowPointerStyleFuzzTest(data, size);
    OHOS::MMI::SetKeyboardRepeatDelayFuzzTest(data, size);
    return 0;
}

