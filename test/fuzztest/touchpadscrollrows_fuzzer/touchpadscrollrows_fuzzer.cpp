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
#include "securec.h"

#undef LOG_TAG
#define LOG_TAG "TouchpadScrollRowsFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {

const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };

namespace {
constexpr size_t MIN_SIZE_FOR_INT32 = sizeof(int32_t);
} // namespace

template <class T>
size_t GetObjectSafe(const uint8_t *data, size_t size, T &object)
{
    if (data == nullptr || size < sizeof(T)) {
        return 0;
    }
    size_t objectSize = sizeof(T);
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

bool SetTouchpadScrollRowsFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_SIZE_FOR_INT32) {
        return false;
    }

    size_t startPos = 0;
    int32_t rows = 0;
    size_t read = GetObjectSafe(data + startPos, size - startPos, rows);
    if (read == 0) {
        return false;
    }
    startPos += read;

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return false;
    }

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

bool GetTouchpadScrollRowsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return false;
    }

    int32_t placeholder = -1;
    if (!datas.WriteInt32(placeholder)) {
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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    OHOS::SetTouchpadScrollRowsFuzzTest(data, size);
    OHOS::GetTouchpadScrollRowsFuzzTest(data, size);
    return 0;
}

} // namespace OHOS
} // namespace MMI
} // namespace OHOS