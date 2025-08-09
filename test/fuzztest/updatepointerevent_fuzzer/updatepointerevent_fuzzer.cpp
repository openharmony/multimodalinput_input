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
#include "updatepointerevent_fuzzer.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UpdatePointerEventFuzzTest"

namespace OHOS {
namespace MMI {
bool UpdatePointerEventFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    int64_t actionTime = provider.ConsumeIntegral<int64_t>();
    int32_t deviceId = provider.ConsumeIntegral<int32_t>();
    int32_t sourceType = provider.ConsumeIntegral<int32_t>();
    int32_t pointerAction = provider.ConsumeIntegral<int32_t>();
    int32_t id = provider.ConsumeIntegral<int32_t>();
    uint32_t flag = provider.ConsumeIntegral<uint32_t>();
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetId(id);
    pointerEvent->AddFlag(flag);
    PointerEvent::PointerItem pointerItem;
    uint32_t pointerId = provider.ConsumeIntegral<uint32_t>();
    int32_t windowX = provider.ConsumeIntegral<int32_t>();
    int32_t windowY = provider.ConsumeIntegral<int32_t>();
    pointerItem.SetToolWindowX(windowX);
    pointerItem.SetToolWindowY(windowY);
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);

    int32_t coordX = provider.ConsumeIntegral<int32_t>();
    int32_t coordY = provider.ConsumeIntegral<int32_t>();
    int32_t toolType = provider.ConsumeIntegral<int32_t>();
    EventResample::Pointer pointer = {
        .coordX = coordX,
        .coordY = coordY,
        .toolType = toolType,
        .id = pointerId
    };
    auto outEvent = std::make_unique<EventResample::MotionEvent>();
    outEvent->InitializeFrom(pointerEvent);
    outEvent->pointers.insert(std::make_pair(pointerId, pointer));
    EventResample eventResample;
    eventResample.pointerEvent_ = PointerEvent::Create();
    eventResample.UpdatePointerEvent(outEvent.get());
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
    OHOS::MMI::UpdatePointerEventFuzzTest(provider);
    return 0;
}
