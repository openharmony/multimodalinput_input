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

#include "addinputeventfilter_fuzzer.h"

#include "input_manager.h"
#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AddInputEventFilterFuzzTest"

namespace OHOS {
namespace MMI {
void AddInputEventFilterFuzzTest(const uint8_t *data, size_t size)
{
    struct TestFilter : public IInputEventFilter {
        bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
        {
            CHKPR(keyEvent, false);
            MMI_HILOGI("Fuzz test in TestFilter::OnInputEvent,key code:%{public}d", keyEvent->GetKeyCode());
            return false;
        }
        bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
        {
            CHKPR(pointerEvent, false);
            MMI_HILOGI("Fuzz test in TestFilter::OnInputEvent,pointer id:%{public}d", pointerEvent->GetPointerId());
            return false;
        }
    };
    auto filter = std::make_shared<TestFilter>();
    const auto priority = 200 + (size % 100);
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    const auto filterId = InputManager::GetInstance()->AddInputEventFilter(filter, priority, touchTags);
    if (filterId == -1) {
        MMI_HILOGE("Add filter,ret:%{public}d", filterId);
        return;
    } else {
        MMI_HILOGE("Add filter success,filterId:%{public}d", filterId);
    }
    auto ret = InputManager::GetInstance()->RemoveInputEventFilter(filterId);
    if (ret != RET_OK) {
        MMI_HILOGE("Remove filter,ret:%{public}d", ret);
        return;
    } else {
        MMI_HILOGE("Remove filter,success,filterId:%{public}d", filterId);
    }
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::AddInputEventFilterFuzzTest(data, size);
    return 0;
}
