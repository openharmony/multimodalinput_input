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

#include "pointerlocation_fuzzer.h"

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

void PointerLocationFuzzTest(const uint8_t *data, size_t size)
{
    int32_t x = 0;
    int32_t y = 0;
    int32_t displayId = 0;
    size_t startPos = 0;

    startPos += GetObject<int32_t>(x, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(y, data + startPos, size - startPos);
    GetObject<int32_t>(displayId, data + startPos, size - startPos);

    InputManager::GetInstance()->SetPointerLocation(x, y, displayId);

    int32_t gotDisplayId = -1;
    double displayX = 0.0;
    double displayY = 0.0;
    InputManager::GetInstance()->GetPointerLocation(gotDisplayId, displayX, displayY);
}

} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::PointerLocationFuzzTest(data, size);
    return 0;
}
