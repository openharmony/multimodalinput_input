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

#include "pointerspeed_fuzzer.h"

#include "securec.h"

#include "common_method.h"
#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "PointerSpeedFuzzTest" };
} // namespace

void PointerSpeedFuzzTest(const uint8_t* data, size_t size)
{
    int32_t speed;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(speed, data + startPos, size - startPos);
    InputManager::GetInstance()->SetPointerSpeed(speed);
    if (InputManager::GetInstance()->SetPointerSpeed(speed) == RET_OK) {
        MMI_HILOGD("Set pointer speed success");
    }

    startPos += GetObject<int32_t>(speed, data + startPos, size - startPos);
    if (InputManager::GetInstance()->GetPointerSpeed(speed) == RET_OK) {
        MMI_HILOGD("Get pointer speed success");
    }
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::PointerSpeedFuzzTest(data, size);
    return 0;
}