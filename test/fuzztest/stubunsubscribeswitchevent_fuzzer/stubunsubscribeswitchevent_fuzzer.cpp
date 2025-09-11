/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "stubunsubscribeswitchevent_fuzzer.h"

#include "mmi_log.h"
#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubUnsubscribeSwitchEventFuzzTest"

namespace OHOS {
namespace MMI {
namespace OHOS {
const std::u16string FORMMGR_INTERFACE_TOKEN = IMultimodalInputConnect::GetDescriptor();
bool StubUnsubscribeSwitchEventFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_UNSUBSCRIBE_SWITCH_EVENT), datas, reply, option);
    return true;
}

bool StubQuerySwitchStatusFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_QUERY_SWITCH_STATUS), datas, reply, option);
    return true;
}

bool StubSetTouchpadRotateSwitchFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_TOUCHPAD_ROTATE_SWITCH),
        datas, reply, option);
    return true;
}

bool StubGetTouchpadRotateSwitchFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_TOUCHPAD_ROTATE_SWITCH),
        datas, reply, option);
    return true;
}

bool StubGetKeyStateFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_KEY_STATE), datas, reply, option);
    return true;
}

bool StubAuthorizeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_AUTHORIZE), datas, reply, option);
    return true;
}

bool StubCancelInjectionFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_CANCEL_INJECTION), datas, reply, option);
    return true;
}

bool StubHasIrEmitterFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_HAS_IR_EMITTER), datas, reply, option);
    return true;
}

bool StubGetInfraredFrequenciesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_INFRARED_FREQUENCIES), datas, reply, option);
    return true;
}

bool StubTransmitInfraredFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_TRANSMIT_INFRARED), datas, reply, option);
    return true;
}

bool StubSetPixelMapDataFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_PIXEL_MAP_DATA), datas, reply, option);
    return true;
}

bool StubSetCurrentUserFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_CURRENT_USER), datas, reply, option);
    return true;
}

bool StubEnableHardwareCursorStatsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ENABLE_HARDWARE_CURSOR_STATS),
        datas, reply, option);
    return true;
}

bool StubGetHardwareCursorStatsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_HARDWARE_CURSOR_STATS), datas, reply, option);
    return true;
}

bool StubAddVirtualInputDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ADD_VIRTUAL_INPUT_DEVICE), datas, reply, option);
    return true;
}

bool StubRemoveVirtualInputDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_REMOVE_VIRTUAL_INPUT_DEVICE),
        datas, reply, option);
    return true;
}

bool StubTransferBinderClientServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_TRANSFER_BINDER_CLIENT_SRV),
        datas, reply, option);
    return true;
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
bool StubGetPointerSnapshotFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::GET_POINTER_SNAPSHOT), datas, reply, option);
    return true;
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

bool StubSkipPointerLayerFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SKIP_POINTER_LAYER), datas, reply, option);
    return true;
}

bool StubMarkEventConsumedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_MARK_EVENT_CONSUMED), datas, reply, option);
    return true;
}

bool StubGetDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_DEVICE), datas, reply, option);
    return true;
}

bool StubSetTouchpadThreeFingersTapSwitchFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_SET_TOUCHPAD_THREE_FINGERS_TAP_SWITCH),
        datas, reply, option);
    return true;
}

bool StubGetTouchpadThreeFingersTapSwitchFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_GET_TOUCHPAD_THREE_FINGERS_TAP_SWITCH),
        datas, reply, option);
    return true;
}

#ifdef OHOS_BUILD_ENABLE_ANCO
bool StubAncoAddChannelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ANCO_ADD_CHANNEL), datas, reply, option);
    return true;
}

bool StubAncoRemoveChannelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ANCO_REMOVE_CHANNEL), datas, reply, option);
    return true;
}
#endif // OHOS_BUILD_ENABLE_ANCO

bool switchDefaultFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    uint32_t code = 1000;
    MMIService::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::StubUnsubscribeSwitchEventFuzzTest(data, size);
    OHOS::StubQuerySwitchStatusFuzzTest(data, size);
    OHOS::StubSetTouchpadRotateSwitchFuzzTest(data, size);
    OHOS::StubGetTouchpadRotateSwitchFuzzTest(data, size);
    OHOS::StubGetKeyStateFuzzTest(data, size);
    OHOS::StubAuthorizeFuzzTest(data, size);
    OHOS::StubCancelInjectionFuzzTest(data, size);
    OHOS::StubHasIrEmitterFuzzTest(data, size);
    OHOS::StubGetInfraredFrequenciesFuzzTest(data, size);
    OHOS::StubTransmitInfraredFuzzTest(data, size);
    OHOS::StubSetPixelMapDataFuzzTest(data, size);
    OHOS::StubSetCurrentUserFuzzTest(data, size);
    OHOS::StubEnableHardwareCursorStatsFuzzTest(data, size);
    OHOS::StubGetHardwareCursorStatsFuzzTest(data, size);
    OHOS::StubAddVirtualInputDeviceFuzzTest(data, size);
    OHOS::StubRemoveVirtualInputDeviceFuzzTest(data, size);
    OHOS::StubTransferBinderClientServiceFuzzTest(data, size);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    OHOS::StubGetPointerSnapshotFuzzTest(data, size);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    OHOS::StubSkipPointerLayerFuzzTest(data, size);
    OHOS::StubMarkEventConsumedFuzzTest(data, size);
    OHOS::StubGetDeviceFuzzTest(data, size);
    OHOS::StubSetTouchpadThreeFingersTapSwitchFuzzTest(data, size);
    OHOS::StubGetTouchpadThreeFingersTapSwitchFuzzTest(data, size);
#ifdef OHOS_BUILD_ENABLE_ANCO
    OHOS::StubAncoAddChannelFuzzTest(data, size);
    OHOS::StubAncoRemoveChannelFuzzTest(data, size);
#endif // OHOS_BUILD_ENABLE_ANCO
    OHOS::switchDefaultFuzzTest(data, size);
    return 0;
}
} // namespace MMI
} // namespace OHOS