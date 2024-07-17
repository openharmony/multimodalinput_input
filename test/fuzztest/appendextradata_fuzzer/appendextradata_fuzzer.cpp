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

#include "appendextradata_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

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

void AppendExtraDataFuzzTest(const uint8_t *data, size_t size)
{
    ExtraData extraData;
    size_t startPos = 0;
    int32_t random;
    GetObject<int32_t>(random, data + startPos, size - startPos);
    bool appended = (random % 2) ? false : true;
    extraData.appended = appended;
    int32_t sourceType;
    GetObject<int32_t>(sourceType, data + startPos, size - startPos);
    extraData.sourceType = sourceType;
    int32_t pointerId;
    GetObject<int32_t>(pointerId, data + startPos, size - startPos);
    extraData.pointerId = pointerId;
    std::vector<uint8_t> dataBuffer(512, 1);
    extraData.buffer = dataBuffer;
    InputManager::GetInstance()->AppendExtraData(extraData);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::AppendExtraDataFuzzTest(data, size);
    return 0;
}