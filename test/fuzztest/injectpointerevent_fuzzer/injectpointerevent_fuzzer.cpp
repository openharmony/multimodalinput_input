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

#include "injectpointerevent_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "InjectPointerEventFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken = IMultimodalInputConnect::GetDescriptor();
constexpr int32_t kMinCoord = -100000;
constexpr int32_t kMaxCoord =  100000;
constexpr int32_t kMinId    = -1;
constexpr int32_t kMaxId    =  65535;
constexpr int32_t kMinAction = 0;
constexpr int32_t kMaxAction = 10;
constexpr int32_t kMinUseCoord = 0;
constexpr int32_t kMaxUseCoord = 2;
}

bool InjectPointerEventFuzzTest(FuzzedDataProvider &provider)
{
    std::shared_ptr<PointerEvent> pe = PointerEvent::Create();
    if (!pe) {
        return false;
    }

    const int32_t pointerId = provider.ConsumeIntegralInRange<int32_t>(kMinId, kMaxId);
    const int32_t action    = provider.ConsumeIntegralInRange<int32_t>(kMinAction, kMaxAction);
    const int32_t gx        = provider.ConsumeIntegralInRange<int32_t>(kMinCoord, kMaxCoord);
    const int32_t gy        = provider.ConsumeIntegralInRange<int32_t>(kMinCoord, kMaxCoord);
    const int32_t wx        = provider.ConsumeIntegralInRange<int32_t>(kMinCoord, kMaxCoord);
    const int32_t wy        = provider.ConsumeIntegralInRange<int32_t>(kMinCoord, kMaxCoord);
    const int32_t deviceId  = provider.ConsumeIntegral<int32_t>();
    const bool isNativeInject = provider.ConsumeBool();
    const int32_t useCoordinate = provider.ConsumeIntegralInRange<int32_t>(kMinUseCoord, kMaxUseCoord);

    pe->SetPointerAction(action);
    pe->SetPointerId(pointerId);
    pe->SetDeviceId(deviceId);

    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetGlobalX(gx);
    item.SetGlobalY(gy);
    item.SetWindowX(wx);
    item.SetWindowY(wy);
    pe->AddPointerItem(item);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }
    if (!datas.WriteParcelable(pe.get())) {
        return false;
    }
    if (!datas.WriteBool(isNativeInject)) {
        return false;
    }
    if (!datas.WriteInt32(useCoordinate)) {
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
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_INJECT_POINTER_EVENT),
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
    (void)OHOS::MMI::InjectPointerEventFuzzTest(provider);
    return 0;
}

} // namespace MMI
} // namespace OHOS