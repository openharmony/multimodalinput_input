/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "setkeydownduration_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SetKeyDownDurationFuzzTest"

namespace OHOS {
namespace MMI {
template <class T> size_t GetObject(T &object, const uint8_t *data, size_t size)
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

size_t GetString(const uint8_t *data, size_t size, char *object, size_t objectSize)
{
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

void SetKeyDownDurationFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    size_t stringSize = 4;
    char businessId[] = "businessId";
    startPos += GetString(data + startPos, size - startPos, businessId, stringSize);
    int32_t delay;
    MMI_HILOGD("SetKeyDownDurationFuzzTest start");
    startPos += GetObject<int32_t>(delay, data + startPos, size - startPos);
    InputManager::GetInstance()->SetKeyDownDuration(businessId, delay);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SetKeyDownDurationFuzzTest(data, size);
    return 0;
}