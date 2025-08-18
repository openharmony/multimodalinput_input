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

#include "injectkeyevent_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include "key_event.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "InjectKeyEventFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken { u"ohos.multimodalinput.IConnectManager" };
constexpr int32_t kMinKeyCode = 0;
constexpr int32_t kMaxKeyCode = 300;
constexpr int32_t kMinAction  = 0;
constexpr int32_t kMaxAction  = 2;
} // namespace

bool InjectKeyEventFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<KeyEvent> ke = KeyEvent::Create();
    if (!ke) {
        return false;
    }

    const int32_t keyCode = provider.ConsumeIntegralInRange<int32_t>(kMinKeyCode, kMaxKeyCode);
    const int32_t action  = provider.ConsumeIntegralInRange<int32_t>(kMinAction, kMaxAction);
    const bool isNativeInject = provider.ConsumeBool();
    const int64_t downTime = provider.ConsumeIntegral<int64_t>();
    const int64_t actionTime = provider.ConsumeIntegral<int64_t>();

    ke->SetKeyCode(keyCode);
    ke->SetKeyAction(action);
    ke->SetActionTime(actionTime);

    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetDownTime(downTime);
    item.SetDeviceId(provider.ConsumeIntegral<int32_t>());
    ke->AddKeyItem(item);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }
    if (!datas.WriteParcelable(ke.get())) {
        return false;
    }
    if (!datas.WriteBool(isNativeInject)) {
        return false;
    }
    if (!datas.RewindRead(0)) {
        return false;
    }
    (void)provider.ConsumeRemainingBytes<uint8_t>();

    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    (void)MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_INJECT_KEY_EVENT),
        datas, reply, option);

    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    (void)OHOS::MMI::InjectKeyEventFuzzTest(provider);
    return 0;
}

} // namespace MMI
} // namespace OHOS