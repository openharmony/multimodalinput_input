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

#include "stubsetcustomcursorpixelmap_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "StubSetCustomCursorPixelMapFuzzTest"

namespace OHOS {
namespace MMI {

namespace {
const std::u16string kInterfaceToken{u"ohos.multimodalinput.IConnectManager"};
} // namespace

static bool StubSetCustomCursorPixelMapFuzzTest(FuzzedDataProvider &provider)
{
    const int32_t windowId = provider.ConsumeIntegral<int32_t>();
    const int32_t focusX   = provider.ConsumeIntegral<int32_t>();
    const int32_t focusY   = provider.ConsumeIntegral<int32_t>();

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(kInterfaceToken)) {
        return false;
    }
    if (!datas.WriteInt32(windowId) ||
        !datas.WriteInt32(focusX)   ||
        !datas.WriteInt32(focusY)) {
        return false;
    }

    if (provider.ConsumeBool()) {
        auto garbage = provider.ConsumeBytes<uint8_t>(provider.ConsumeIntegralInRange<size_t>(0, 16));
        if (!garbage.empty()) {
            (void)datas.WriteBuffer(garbage.data(), garbage.size());
        }
    }

    if (!datas.RewindRead(0)) {
        return false;
    }
    (void)provider.ConsumeRemainingBytes<uint8_t>();

    MessageParcel reply;
    MessageOption option;

    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;

    (void)MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_CUSTOM_CURSOR_PIXEL_MAP),
        datas, reply, option);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    (void)OHOS::MMI::StubSetCustomCursorPixelMapFuzzTest(provider);
    return 0;
}
} // namespace MMI
} // namespace OHOS