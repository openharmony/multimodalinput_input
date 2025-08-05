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

#include "mmi_log.h"
#include "input_event.h"
#include "inputevent_fuzzer.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
#define ODDEVENFLAG 2
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

void InputEventGetFuncFuzzTest(InputEvent &inputEvent)
{
    Parcel parcel;
    inputEvent.Marshalling(parcel);
    inputEvent.ReadFromParcel(parcel);
    inputEvent.Unmarshalling(parcel);

    inputEvent.GetId();
    inputEvent.UpdateId();
    inputEvent.GetActionTime();
    inputEvent.GetSensorInputTime();
    inputEvent.GetAction();
    inputEvent.GetActionStartTime();
    inputEvent.GetDeviceId();
    inputEvent.GetSourceType();
    inputEvent.GetTargetDisplayId();
    inputEvent.GetAgentWindowId();
    inputEvent.GetTargetWindowId();
    inputEvent.GetEventType();
    inputEvent.GetFlag();
    inputEvent.IsMarkEnabled();
    inputEvent.MarkProcessed();
    inputEvent.ToString();

    InputEvent::Create();
    InputEvent inputEvent2 = InputEvent(inputEvent);
    inputEvent2.ToString();
}

bool InputEventFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    int32_t rowsBefore;
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);

    InputEvent inputEvent(rowsBefore);
    inputEvent.Reset();

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.EventTypeToString(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetActionTime(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetSensorInputTime(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetAction(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetActionStartTime(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetDeviceId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetSourceType(rowsBefore);

    inputEvent.DumpSourceType();

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetTargetDisplayId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetAgentWindowId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetTargetWindowId(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.HasFlag(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.IsFlag(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.AddFlag(rowsBefore);
    inputEvent.ClearFlag();

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.ClearFlag(rowsBefore);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.SetMarkEnabled(rowsBefore);

    std::function<void(int32_t, int64_t)> callback = [](int32_t, int64_t) {};
    inputEvent.SetProcessedCallback(callback);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);

    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    inputEvent.ActionToShortStr(rowsBefore);
    InputEventGetFuncFuzzTest(inputEvent);
    
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::InputEventFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS