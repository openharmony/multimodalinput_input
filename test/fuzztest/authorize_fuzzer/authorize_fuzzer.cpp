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

#include "authorize_fuzzer.h"

#include "securec.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AuthorizeFuzzTest"

namespace OHOS {
namespace MMI {

template <class T>
size_t GetObject(const uint8_t *data, size_t size, T &object)
{
    size_t objectSize = sizeof(T);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    return (ret == EOK) ? objectSize : 0;
}

void AuthorizeFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    size_t startPos = 0;
    int32_t random = 0;
    startPos += GetObject(data + startPos, size - startPos, random);
    bool isAuthorize = (random % 2 == 0);
    InputManager::GetInstance()->Authorize(isAuthorize);
    MMI_HILOGD("Authorize called with isAuthorize = %{public}d", isAuthorize);

    int32_t status = -1;
    int32_t retQuery = InputManager::GetInstance()->QueryAuthorizedStatus(status);
    if (retQuery == 0) {
        MMI_HILOGD("QueryAuthorizedStatus success, status = %{public}d", status);
    } else {
        MMI_HILOGW("QueryAuthorizedStatus failed, ret = %{public}d", retQuery);
    }
}

} // namespace MMI
} // namespace OHOS

// Fuzz entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::AuthorizeFuzzTest(data, size);
    return 0;
}