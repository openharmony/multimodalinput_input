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

#include "shieldstatus_fuzzer.h"

#include "securec.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ShieldStatusFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
int32_t BYTES_PER_COMBINATION = 2;
constexpr size_t MAX_SHIELD_COMBINATIONS = 3;
} // namespace

template <class T>
size_t GetObject(const uint8_t *data, size_t size, T &object)
{
    size_t objectSize = sizeof(T);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

void ShieldStatusFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    for (size_t i = 0; i < MAX_SHIELD_COMBINATIONS && startPos + sizeof(int32_t) * BYTES_PER_COMBINATION <= size; ++i) {
        int32_t shieldMode = 0;
        size_t readSize = GetObject(data + startPos, size - startPos, shieldMode);
        if (readSize == 0) {
            MMI_HILOGW("Failed to read shieldMode");
            break;
        }
        startPos += readSize;
        int32_t random = 0;
        readSize = GetObject(data + startPos, size - startPos, random);
        if (readSize == 0) {
            MMI_HILOGW("Failed to read random for isShield");
            break;
        }
        startPos += readSize;
        bool isShield = ((random % 2) == 0);
        int32_t retSet = InputManager::GetInstance()->SetShieldStatus(shieldMode, isShield);
        if (retSet != 0) {
            MMI_HILOGW("SetShieldStatus failed. mode=%{public}d", shieldMode);
            continue;
        }
        bool readBackShield = !isShield;
        int32_t retGet = InputManager::GetInstance()->GetShieldStatus(shieldMode, readBackShield);
        if (retGet != 0) {
            MMI_HILOGW("GetShieldStatus failed. mode=%{public}d", shieldMode);
            continue;
        }

        if (readBackShield != isShield) {
            MMI_HILOGE("Mismatch: Set=%{public}d, Got=%{public}d, mode=%{public}d",
                       isShield, readBackShield, shieldMode);
        } else {
            MMI_HILOGD("Match: mode=%{public}d, state=%{public}d", shieldMode, isShield);
        }
    }
}

} // namespace MMI
} // namespace OHOS

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::ShieldStatusFuzzTest(data, size);
    return 0;
}