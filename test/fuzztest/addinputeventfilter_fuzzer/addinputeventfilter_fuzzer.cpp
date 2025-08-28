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

#include <fuzzer/FuzzedDataProvider.h>
#include "addinputeventfilter_fuzzer.h"

#include "input_manager.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
void AddInputEventFilterFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t priority = fdp.ConsumeIntegralInRange<int32_t>(0, 500);
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);

    struct TestFilter : public IInputEventFilter {
        bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
        {
            return false;
        }
        bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
        {
            return false;
        }
    };

    auto filter = std::make_shared<TestFilter>();
    int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, priority, touchTags);
    if (filterId != -1) {
        InputManager::GetInstance()->RemoveInputEventFilter(filterId);
    }
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    AddInputEventFilterFuzzTest(fdp);
    return true;
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::MmiServiceFuzzTest(fdp);
    return 0;
}