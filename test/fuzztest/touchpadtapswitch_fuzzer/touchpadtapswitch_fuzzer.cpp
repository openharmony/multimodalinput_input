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

#include "touchpadtapswitch_fuzzer.h"

#include "securec.h"
#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

template <class T>
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

void TouchpadTapSwitchFuzzTest(const uint8_t *data, size_t size)
{
    int32_t rnd1 = 0;
    (void)GetObject<int32_t>(rnd1, data, size);
    bool enable1 = (rnd1 & 1) == 0;
    (void)InputManager::GetInstance()->SetTouchpadTapSwitch(enable1);
    bool state1 = false;
    (void)InputManager::GetInstance()->GetTouchpadTapSwitch(state1);
    int32_t rnd2 = 0;
    if (size > sizeof(int32_t)) {
        (void)GetObject<int32_t>(rnd2, data + sizeof(int32_t), size - sizeof(int32_t));
        bool enable2 = (rnd2 & 1) != 0;
        (void)InputManager::GetInstance()->SetTouchpadTapSwitch(enable2);
        bool state2 = false;
        (void)InputManager::GetInstance()->GetTouchpadTapSwitch(state2);
    }
}

} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::TouchpadTapSwitchFuzzTest(data, size);
    return 0;
}