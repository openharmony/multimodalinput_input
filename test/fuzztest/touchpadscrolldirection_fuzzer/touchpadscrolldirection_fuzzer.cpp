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

#include "touchpadscrolldirection_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

template <class T>
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

void TouchpadScrollDirectionFuzzTest(const uint8_t *data, size_t size)
{
    int32_t random = 0;
    GetObject<int32_t>(random, data, size);
    bool direction = (random % 2 == 0);
    InputManager::GetInstance()->SetTouchpadScrollDirection(direction);
    bool currentDirection = false;
    InputManager::GetInstance()->GetTouchpadScrollDirection(currentDirection);
}

} // namespace MMI
} // namespace OHOS

// fuzz entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::TouchpadScrollDirectionFuzzTest(data, size);
    return 0;
}