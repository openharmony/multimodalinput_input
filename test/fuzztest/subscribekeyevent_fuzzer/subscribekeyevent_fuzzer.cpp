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

#include "subscribekeyevent_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SubscribeKeyEventFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_PREKEY_COUNT = 3;
} // namespace

class InputEventConsumerTest : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGD("Report pointer event success");
    };
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override {};
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {};
};

template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t bodySize = sizeof(object);
    if (bodySize > size) {
        return 0;
    }
    errno_t retNum = memcpy_s(&object, bodySize, data, bodySize);
    if (retNum != EOK) {
        return 0;
    }
    return bodySize;
}

void SubscribeKeyEventFuzzTest(const uint8_t* data, size_t size)
{
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> prekeys;
    size_t startPos = 0;
    for (int32_t i = 0; i < DEFAULT_PREKEY_COUNT; i++) {
        int32_t preKey;
        startPos += GetObject<int32_t>(preKey, data + startPos, size - startPos);
        prekeys.insert(preKey);
    }
    keyOption->SetPreKeys(prekeys);
    int32_t keyDown;
    startPos += GetObject<int32_t>(keyDown, data + startPos, size - startPos);
    keyOption->SetFinalKeyDown(keyDown != 0);
    int32_t keyDownDuration;
    startPos += GetObject<int32_t>(keyDownDuration, data + startPos, size - startPos);
    keyOption->SetFinalKeyDownDuration(keyDownDuration);
    int32_t finalKey;
    startPos += GetObject<int32_t>(finalKey, data + startPos, size - startPos);
    keyOption->SetFinalKey(finalKey);
    auto fun = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("Subscribe keyevent success");
    };
    int32_t subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, fun);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SubscribeKeyEventFuzzTest(data, size);
    return 0;
}

