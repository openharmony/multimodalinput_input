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

#include "touchpadscrollrows_fuzzer.h"

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"
#include "mmi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#undef LOG_TAG
#define LOG_TAG "TouchpadScrollRowsFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {

const std::u16string FORMMGR_INTERFACE_TOKEN{ u"ohos.multimodalinput.IConnectManager" };

namespace {
constexpr int32_t ROWS_MIN = -1000;
constexpr int32_t ROWS_MAX =  1000;
} // namespace

bool SetTouchpadScrollRowsFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return false;
    }
    int32_t rows = provider.ConsumeIntegralInRange<int32_t>(ROWS_MIN, ROWS_MAX);
    if (!datas.WriteInt32(rows)) {
        return false;
    }
    if (!datas.RewindRead(0)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_TOUCHPAD_SCROLL_ROWS),
        datas, reply, option);
    return true;
}

bool GetTouchpadScrollRowsFuzzTest(FuzzedDataProvider &provider)
{
    (void)provider;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return false;
    }
    if (!datas.RewindRead(0)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_TOUCHPAD_SCROLL_ROWS),
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
    OHOS::SetTouchpadScrollRowsFuzzTest(provider);
    OHOS::GetTouchpadScrollRowsFuzzTest(provider);
    return 0;
}

} // namespace OHOS
} // namespace MMI
} // namespace OHOS