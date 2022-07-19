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

#include "call_dinput_stub.h"

#include <sys/socket.h>
#include <sys/types.h>

#include "ipc_skeleton.h"
#include "mmi_log.h"
#include "string_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "CallDinputStub" };
}  // namespace

int32_t CallDinputStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MMI_HILOGI("enter, code:%{public}d", code);

    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ICallDinput::GetDescriptor()) {
        MMI_HILOGW("get unexpect descriptor:%{public}s", Str16ToStr8(descriptor).c_str());
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case HANDLE_PREPARE_DINPUT: {
            return StubHandlePrepareDinput(data, reply);
        }
        case HANDLE_UNPREPARE_DINPUT: {
            return StubHandleUnprepareDinput(data, reply);
        }
        case HANDLE_START_DINPUT: {
            return StubHandleStartDinput(data, reply);
        }
        case HANDLE_STOP_DINPUT: {
            return StubHandleStopDinput(data, reply);
        }
        case HANDLE_REMOTE_INPUT_ABILITY: {
            return StubHandleRemoteInputAbility(data, reply);
        }
        default: {
            MMI_HILOGW("unknown code:%{public}u, go switch defaut", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t CallDinputStub::StubHandlePrepareDinput(MessageParcel& data, MessageParcel& reply)
{
    CALL_INFO_TRACE;
    std::string deviceId;
    READSTRING(data, deviceId, RET_ERR);
    int32_t status;
    READINT32(data, status, RET_ERR);
    return HandlePrepareDinput(deviceId, status);
}

int32_t CallDinputStub::StubHandleUnprepareDinput(MessageParcel& data, MessageParcel& reply)
{
    CALL_INFO_TRACE;
    std::string deviceId;
    READSTRING(data, deviceId, RET_ERR);
    int32_t status;
    READINT32(data, status, RET_ERR);
    return HandleUnprepareDinput(deviceId, status);
}

int32_t CallDinputStub::StubHandleStartDinput(MessageParcel& data, MessageParcel& reply)
{
    CALL_INFO_TRACE;
    std::string deviceId;
    READSTRING(data, deviceId, RET_ERR);
    int32_t inputAbility;
    READINT32(data, inputAbility, RET_ERR);
    int32_t status;
    READINT32(data, status, RET_ERR);
    return HandleStartDinput(deviceId, inputAbility, status);
}

int32_t CallDinputStub::StubHandleStopDinput(MessageParcel& data, MessageParcel& reply)
{
    CALL_INFO_TRACE;
    std::string deviceId;
    READSTRING(data, deviceId, RET_ERR);
    int32_t inputAbility;
    READINT32(data, inputAbility, RET_ERR);
    int32_t status;
    READINT32(data, status, RET_ERR);
    return HandleStopDinput(deviceId, inputAbility, status);
}

int32_t CallDinputStub::StubHandleRemoteInputAbility(MessageParcel& data, MessageParcel& reply)
{
    CALL_INFO_TRACE;
    std::set<int32_t> remoteInputAbility;
    int32_t size;
    READINT32(data, size, RET_ERR);
    int32_t value;
    for (size_t i = 0; i < size; i++) {
        READINT32(data, value, RET_ERR);
        remoteInputAbility.insert(value);
    }
    return HandleRemoteInputAbility(remoteInputAbility);
}
} // namespace MMI
} // namespace OHOS