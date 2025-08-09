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
#include "event_resample.h"
#include "updatetouchstate_fuzzer.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UpdateTouchStateFuzzTest"

namespace OHOS {
namespace MMI {
bool UpdateTouchStateFuzzTest(FuzzedDataProvider &provider)
{
    EventResample::MotionEvent event;
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    int32_t sourceType = provider.ConsumeIntegral<int32_t>();
    int32_t pointerAction = provider.ConsumeIntegral<int32_t>();
    event.deviceId = deviceId;
    event.sourceType = sourceType;
    event.pointerAction = pointerAction;
    EventResample eventResample;
    eventResample.UpdateTouchState(event);
    return true;
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
    FuzzedDataProvider provider(data, size);
    OHOS::MMI::UpdateTouchStateFuzzTest(provider);
    return 0;
}
