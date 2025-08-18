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

#include "switchscreencapturepermission_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "SwitchScreenCapturePermissionFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken{ u"ohos.multimodalinput.IConnectManager" };
} // namespace

bool SwitchScreenCapturePermissionFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }

    const uint32_t permissionType = provider.ConsumeIntegral<uint32_t>();
    const bool enable = provider.ConsumeBool();

    if (!datas.WriteUint32(permissionType)) {
        return false;
    }
    if (!datas.WriteBool(enable)) {
        return false;
    }
    if (!datas.RewindRead(0)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;

    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    (void)MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SWITCH_SCREEN_CAPTURE_PERMISSION),
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
    (void)OHOS::MMI::SwitchScreenCapturePermissionFuzzTest(provider);
    return 0;
}

} // namespace MMI
} // namespace OHOS