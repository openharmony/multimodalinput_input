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

#include "subscribekeyevent_fuzzer.h"

#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SubscribeKeyEventFuzzTest" };
} // namespace

class InputEventConsumerTest: public OHOS::MMI::IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override {};
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override {
        MMI_HILOGD("report pointerevent success");
    };
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {};
};

bool SubscribeKeyEventFuzzTest(const uint8_t* data, size_t /* size */)
{
    std::shared_ptr<KeyOption> keyOption = std::make_shared<KeyOption>();
    std::set<int32_t> prekeys;
    prekeys.insert(KeyEvent::KEYCODE_CTRL_LEFT);
    prekeys.insert(KeyEvent::KEYCODE_ALT_LEFT);
    keyOption->SetPreKeys(prekeys);
    keyOption->SetFinalKeyDown(true);
    keyOption->SetFinalKeyDownDuration(0);
    keyOption->SetFinalKey(KeyEvent::KEYCODE_DEL);
    auto fun = [](std::shared_ptr<KeyEvent> event) {
        MMI_HILOGD("subscribe keyevent success");
    };
    int32_t subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, fun);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SubscribeKeyEventFuzzTest(data, size);
    return 0;
}

