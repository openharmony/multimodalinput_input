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

#include "touchpaddoubletapanddragstate_fuzzer.h"

#include "securec.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadDoubleTapAndDragStateFuzzTest"

namespace OHOS {
namespace MMI {

template <class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(T)) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, sizeof(T), data, sizeof(T));
    if (ret != EOK) {
        return 0;
    }
    return sizeof(T);
}

void TouchpadDoubleTapAndDragStateFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }

    bool switchFlag = false;
    size_t offset = GetObject<bool>(switchFlag, data, size);
    if (offset == 0) {
        return;
    }

    int32_t ret = InputManager::GetInstance()->SetTouchpadDoubleTapAndDragState(switchFlag);
    MMI_HILOGD("SetTouchpadDoubleTapAndDragState return:%{public}d", ret);

    bool outFlag = false;
    ret = InputManager::GetInstance()->GetTouchpadDoubleTapAndDragState(outFlag);
    MMI_HILOGD("GetTouchpadDoubleTapAndDragState return:%{public}d, outFlag:%{public}d", ret, outFlag);
}

} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::MMI::TouchpadDoubleTapAndDragStateFuzzTest(data, size);
    return 0;
}