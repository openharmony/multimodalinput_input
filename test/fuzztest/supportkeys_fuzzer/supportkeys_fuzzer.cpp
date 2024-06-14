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

#include "supportkeys_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SupportKeysFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FUZZ_FST_DATA = 0;
constexpr int32_t MAX_SUPPORT_KEY = 5;
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

void SupportKeysFuzzTest(const uint8_t* data, size_t size)
{
    int32_t id = data[FUZZ_FST_DATA];
    size_t startPos = 0;
    std::vector<int32_t> keycodes;
    for (int32_t i = 0; i < MAX_SUPPORT_KEY; i++) {
        int32_t preKey;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, preKey);
        keycodes.push_back(preKey);
    }
    auto fun = [](std::vector<bool> isSupport) {
        MMI_HILOGD("Support key success");
    };
    InputManager::GetInstance()->SupportKeys(id, keycodes, fun);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SupportKeysFuzzTest(data, size);
    return 0;
}