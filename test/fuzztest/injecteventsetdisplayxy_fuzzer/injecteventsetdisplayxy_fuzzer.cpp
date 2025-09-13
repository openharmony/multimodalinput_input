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
#include "injecteventsetdisplayxy_fuzzer.h"
#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_service.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

bool InjecteventSetDisplayXYFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t pointerIdX = provider.ConsumeIntegral<int32_t>();
    int32_t pointerIdY = provider.ConsumeIntegral<int32_t>();

    PointerEvent::PointerItem downitem;
    downitem.SetDisplayX(pointerIdX);
    downitem.SetDisplayY(pointerIdY);

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

    OHOS::MMI::InjecteventSetDisplayXYFuzzTest(data, size);

    return 0;
}