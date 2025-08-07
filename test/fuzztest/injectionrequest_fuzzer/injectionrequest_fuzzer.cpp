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

#include "injectionrequest_fuzzer.h"

#include "mmi_service.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InjectionRequestFuzzTest"

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

void InjectionRequestFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t startPos = 0;
    int32_t random = 0;
    startPos += GetObject(data + startPos, size - startPos, random);
    bool doRequestFirst = (random % 2 == 0);

    if (doRequestFirst) {
        int32_t status = -1;
        int32_t reqId = -1;
        int32_t ret = MMIService::GetInstance()->RequestInjection(status, reqId);
        MMI_HILOGD("RequestInjection: ret=%{public}d, status=%{public}d, reqId=%{public}d", ret, status, reqId);
    }

    int32_t cancelRet = MMIService::GetInstance()->CancelInjection();
    MMI_HILOGD("CancelInjection: ret=%{public}d", cancelRet);
    if (!doRequestFirst) {
        int32_t status = -1;
        int32_t reqId = -1;
        int32_t ret = MMIService::GetInstance()->RequestInjection(status, reqId);
        MMI_HILOGD("RequestInjection: ret=%{public}d, status=%{public}d, reqId=%{public}d", ret, status, reqId);
    }
}

} // namespace MMI
} // namespace OHOS

// fuzz entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::InjectionRequestFuzzTest(data, size);
    return 0;
}