/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "shiftapppointerevent_fuzzer.h"

#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_service.h"
#include "mmi_log.h"


namespace OHOS {
constexpr uint32_t MAX_ENUM_VALUE = 10;
namespace MMI {
template<class T>
size_t GetObject(T& object, const uint8_t* data, size_t size)
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

bool ShiftAppPointerEvent(const uint8_t* data, const size_t size, size_t& startPos)
{
    ShiftWindowParam param;
    bool autoGenDown;
    startPos += GetObject<ShiftWindowParam>(param, data + startPos, size - startPos);
    startPos += GetObject<bool>(autoGenDown, data + startPos, size - startPos);
    InputManager::GetInstance()->ShiftAppPointerEvent(param, autoGenDown);
    return true;
}
		
bool ShiftAppPointerEventNoHapTokenVerify(const uint8_t* data, const size_t size, size_t& startPos)
{
    ShiftWindowParam param;
    bool autoGenDown;
    startPos += GetObject<ShiftWindowParam>(param, data + startPos, size - startPos);
    startPos += GetObject<bool>(autoGenDown, data + startPos, size - startPos);
    WIN_MGR->ShiftAppPointerEvent(param, autoGenDown);
    return true;
}
		
bool ShiftAppPointerEventFuzzTest(const uint8_t* data, const size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t sourceWindowId = fdp.ConsumeIntegral<int32_t>();
    int32_t targetWindowId = fdp.ConsumeIntegral<int32_t>();
    int32_t x = fdp.ConsumeIntegral<int32_t>();
    int32_t y = fdp.ConsumeIntegral<int32_t>();
    int32_t fingerId = fdp.ConsumeIntegral<int32_t>();
    int32_t sourceType = fdp.ConsumeIntegral<int32_t>() % MAX_ENUM_VALUE;
    bool autoGenDown = fdp.ConsumeBool();
    OHOS::MMI::ShiftWindowParam param;
    param.sourceWindowId = sourceWindowId;
    param.targetWindowId = targetWindowId;
    param.x = x;
    param.y = y;
    param.fingerId = fingerId;
    param.sourceType = sourceType;
    bool winRes = WIN_MGR->ShiftAppPointerEvent(param, autoGenDown);
    bool mgrRes = InputManager::GetInstance()->ShiftAppPointerEvent(param, autoGenDown);
    if (winRes && mgrRes) {
        return true;
    }
    return false;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::ShiftAppPointerEventFuzzTest(data, size);
    return 0;
}