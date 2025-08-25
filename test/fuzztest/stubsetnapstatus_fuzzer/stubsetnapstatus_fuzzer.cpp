/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or enforced by applicable law, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "stubsetnapstatus_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "StubSetNapStatusFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken{u"ohos.multimodalinput.IConnectManager"};
} // namespace

static bool StubSetNapStatusFuzz(FuzzedDataProvider &provider)
{
    const int32_t pid  = provider.ConsumeIntegral<int32_t>();
    const int32_t uid  = provider.ConsumeIntegral<int32_t>();
    const std::string bundleName = provider.ConsumeRandomLengthString(
        provider.ConsumeIntegralInRange<size_t>(0, 128));
    const int32_t napStatus = provider.ConsumeIntegral<int32_t>();

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }
    if (!datas.WriteInt32(pid) ||
        !datas.WriteInt32(uid) ||
        !datas.WriteString(bundleName) ||
        !datas.WriteInt32(napStatus) ||
        !datas.RewindRead(0)) {
        return false;
    }

    (void)provider.ConsumeRemainingBytes<uint8_t>();

    MessageParcel reply;
    MessageOption option;

    auto *svc = MMIService::GetInstance();
    if (svc == nullptr) {
        return false;
    }
    svc->state_ = ServiceRunningState::STATE_RUNNING;

    const uint32_t code = static_cast<uint32_t>(
        IMultimodalInputConnectIpcCode::COMMAND_SET_NAP_STATUS);

    (void)svc->OnRemoteRequest(code, datas, reply, option);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    (void)OHOS::MMI::StubSetNapStatusFuzz(provider);
    return 0;
}

} // namespace MMI
} // namespace OHOS