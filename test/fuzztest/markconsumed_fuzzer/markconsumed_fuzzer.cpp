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

#include "markconsumed_fuzzer.h"

#include "securec.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MarkConsumedFuzzTest"

namespace OHOS {
namespace MMI {
class InputEventConsumerTest : public IInputEventConsumer {
public:
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override{};
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGD("Report pointer event success");
    };
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override{};
};

template <class T> size_t GetObject(const uint8_t *data, size_t size, T &object)
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

void MarkConsumedFuzzTest(const uint8_t *data, size_t size)
{
    CALL_DEBUG_ENTER;
    int32_t eventId;
    GetObject<int32_t>(data, size, eventId);
    auto consumer = std::make_shared<InputEventConsumerTest>();
    int32_t monitorId = InputManager::GetInstance()->AddMonitor(consumer);
    InputManager::GetInstance()->MarkConsumed(monitorId, eventId);
    InputManager::GetInstance()->RemoveMonitor(monitorId);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::MarkConsumedFuzzTest(data, size);
    return 0;
}
