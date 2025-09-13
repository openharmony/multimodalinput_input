/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "injecteventsetdowntime_fuzzer.h"
#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_service.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

bool InjecteventSetDownTimeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int64_t downTime = provider.ConsumeIntegral<int64_t>();

    KeyEvent::KeyItem kitDown;
    kitDown.SetDownTime(downTime);

    return true;
}

} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < 0) {
        return 0;
    }
    /* Run your code on data */

    OHOS::MMI::InjecteventSetDownTimeFuzzTest(data, size);

    return 0;
}