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

#include "getkeyboardtype_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "GetKeyboardTypeFuzzTest" };
} // namespace

template<class T>
size_t GetObject(const uint8_t *data, size_t size, T &object)
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

void GetKeyboardTypeFuzzTest(const uint8_t* data, size_t size)
{
    int32_t deviceId;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(data + startPos, size - startPos, deviceId);
    auto fun = [](int32_t keyboardType) {
        MMI_HILOGD("Get keyboard type success");
    };
    InputManager::GetInstance()->GetKeyboardType(deviceId, fun);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::GetKeyboardTypeFuzzTest(data, size);
    return 0;
}