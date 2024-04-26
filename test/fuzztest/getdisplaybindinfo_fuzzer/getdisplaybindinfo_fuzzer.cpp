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

#include "getdisplaybindinfo_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "GetDisplayBindInfoFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_PREKEY_COUNT = 5;
} // namespace

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

void GetDisplayBindInfoFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<DisplayBindInfo> displayBindInfos;
    size_t startPos = 0;
    size_t stringSize = 4;
    for (int32_t i = 0; i < DEFAULT_PREKEY_COUNT; i++) {
        DisplayBindInfo displayBindInfo;
        int32_t inputDeviceId;
        startPos += GetObject<int32_t>(inputDeviceId, data + startPos, size - startPos);
        displayBindInfo.inputDeviceId = inputDeviceId;
        int32_t displayId;
        startPos += GetObject<int32_t>(displayId, data + startPos, size - startPos);
        displayBindInfo.displayId = displayId;
        char inputDeviceName[] = "inputDeviceName";
        startPos += GetString(data + startPos, size - startPos, inputDeviceName, stringSize);
        displayBindInfo.inputDeviceName = inputDeviceName;
        char displayName[] = "displayName";
        startPos += GetString(data + startPos, size - startPos, displayName, stringSize);
        displayBindInfo.displayName = displayName;
        displayBindInfos.push_back(displayBindInfo);
    }
    MMI_HILOGD("GetDisplayBindInfo start");
    InputManager::GetInstance()->GetDisplayBindInfo(displayBindInfos);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::GetDisplayBindInfoFuzzTest(data, size);
    return 0;
}

