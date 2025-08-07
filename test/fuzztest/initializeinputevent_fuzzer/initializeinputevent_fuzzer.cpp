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

#include "event_resample.h"
#include "initializeinputevent_fuzzer.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InitializeInputEventFuzzTest"

namespace OHOS {
namespace MMI {
template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

bool InitializeInputEventFuzzTest(const uint8_t *data, size_t size)
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    size_t startPos = 0;
    int64_t actionTime;
    int32_t deviceId;
    int32_t sourceType;
    int32_t pointerAction;
    int32_t id;
    startPos += GetObject<int64_t>(actionTime, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(deviceId, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(sourceType, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(pointerAction, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(id, data + startPos, size - startPos);
    pointerEvent->SetActionTime(actionTime);
    pointerEvent->SetDeviceId(deviceId);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetPointerAction(pointerAction);
    pointerEvent->SetId(id);

    PointerEvent::PointerItem pointerItem;
    int32_t displayX;
    int32_t displayY;
    int32_t toolType;
    int32_t pointerId;
    startPos += GetObject<int32_t>(displayX, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(displayY, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(toolType, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(pointerId, data + startPos, size - startPos);
    pointerItem.SetDisplayX(displayX);
    pointerItem.SetDisplayY(displayY);
    pointerItem.SetToolType(toolType);
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    
    int64_t frameTime;
    startPos += GetObject<int64_t>(frameTime, data + startPos, size - startPos);
    EventResample eventResample;
    eventResample.InitializeInputEvent(pointerEvent, frameTime);
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
    OHOS::MMI::InitializeInputEventFuzzTest(data, size);
    return 0;
}
