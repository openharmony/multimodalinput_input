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

#include "touchpadthreefingerstapswitch_fuzzer.h"

#include "mmi_service.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadThreeFingersTapSwitchFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_ITERATION_COUNT = 2;
} // namespace

template <typename T>
size_t GetObject(const uint8_t *data, size_t size, T &object)
{
    size_t objSize = sizeof(T);
    if (objSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objSize, data, objSize);
    return (ret == EOK) ? objSize : 0;
}

void TouchPadThreeFingersTapSwitchFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    size_t startPos = 0;
    for (size_t i = 0; i < MAX_ITERATION_COUNT && (startPos + sizeof(int32_t) <= size); ++i) {
        int32_t rnd = 0;
        startPos += GetObject(data + startPos, size - startPos, rnd);
        bool enable = (rnd % 2 == 0);

        MMIService::GetInstance()->SetTouchpadThreeFingersTapSwitch(enable);
        MMI_HILOGD("SetTouchpadThreeFingersTapSwitch: %d", enable);

        bool status = !enable;
        int32_t ret = MMIService::GetInstance()->GetTouchpadThreeFingersTapSwitch(status);
        if (ret == 0) {
            MMI_HILOGD("GetTouchpadThreeFingersTapSwitch: status=%{public}d", status);
        } else {
            MMI_HILOGD("GetTouchpadThreeFingersTapSwitch failed");
        }
    }
}

} // namespace MMI
} // namespace OHOS

// fuzz entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::TouchPadThreeFingersTapSwitchFuzzTest(data, size);
    return 0;
}