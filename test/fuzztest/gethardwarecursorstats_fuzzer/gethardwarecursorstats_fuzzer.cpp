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

#include "gethardwarecursorstats_fuzzer.h"

#include "ipc_skeleton.h"
#include "securec.h"

#include "input_manager.h"

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

void GetHardwareCursorStatsFuzzTest(const uint8_t *data, size_t size)
{
    int32_t mouseX;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(mouseX, data + startPos, size - startPos);
    int32_t mouseY;
    startPos += GetObject<int32_t>(mouseY, data + startPos, size - startPos);
    InputManager::GetInstance()->EnableHardwareCursorStats(true);
    InputManager::GetInstance()->MoveMouse(mouseX, mouseY);
    InputManager::GetInstance()->EnableHardwareCursorStats(false);
    uint32_t frameCount = 2;
    uint32_t vsyncCount = 2;
    InputManager::GetInstance()->GetHardwareCursorStats(frameCount, vsyncCount);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::GetHardwareCursorStatsFuzzTest(data, size);
    return 0;
}