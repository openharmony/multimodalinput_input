/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "pointervisible_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerVisibleFuzzTest" };
} // namespace
inline bool IntToBool(int32_t visible)
{
    return !(visible % 2) ? true : false;
}

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

void PointerVisibleFuzzTest(const uint8_t* data, size_t size)
{
    int32_t visible = 0;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(visible, data + startPos, size - startPos);
    if (InputManager::GetInstance()->SetPointerVisible(IntToBool(visible)) == RET_OK) {
        MMI_HILOGD("set pointer visible succeeded");
    }
    if (InputManager::GetInstance()->IsPointerVisible()) {
        MMI_HILOGD("the pointer is visible");
    }
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::PointerVisibleFuzzTest(data, size);
    return 0;
}
