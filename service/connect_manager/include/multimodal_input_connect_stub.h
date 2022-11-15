/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_CONNECT_STUB_H
#define MULTIMODAL_INPUT_CONNECT_STUB_H

#include "iremote_stub.h"
#include "message_parcel.h"
#include "nocopyable.h"

#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "multimodal_input_connect_define.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectStub : public IRemoteStub<IMultimodalInputConnect> {
public:
    MultimodalInputConnectStub() = default;
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectStub);
    ~MultimodalInputConnectStub() = default;

    virtual bool IsRunning() const = 0;
    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& options) override;

protected:
    int32_t StubHandleAllocSocketFd(MessageParcel &data, MessageParcel &reply);
    int32_t StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerVisible(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerStyle(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerStyle(MessageParcel& data, MessageParcel& reply);
    int32_t StubIsPointerVisible(MessageParcel& data, MessageParcel& reply);
    int32_t StubSupportKeys(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetDeviceIds(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubRegisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnregisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetKeyboardType(MessageParcel& data, MessageParcel& reply);
    int32_t StubAddInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubMarkEventConsumed(MessageParcel& data, MessageParcel& reply);
    int32_t StubMoveMouseEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubInjectKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSubscribeKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubInjectPointerEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetAnrListener(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubRegisterCooperateMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnregisterCooperateMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubEnableInputDeviceCooperate(MessageParcel& data, MessageParcel& reply);
    int32_t StubStartInputDeviceCooperate(MessageParcel& data, MessageParcel& reply);
    int32_t StubStopDeviceCooperate(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetInputDeviceCooperateState(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetInputDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetFunctionKeyState(MessageParcel &data, MessageParcel &reply);
    int32_t StubSetFunctionKeyState(MessageParcel &data, MessageParcel &reply);
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_STUB_H
