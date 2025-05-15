/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_CONNECT_STUB_H
#define MULTIMODAL_INPUT_CONNECT_STUB_H

#include "iremote_stub.h"
#include "cJSON.h"

#include "i_multimodal_input_connect.h"
#include "multimodalinput_ipc_interface_code.h"

namespace OHOS {
namespace MMI {
struct ParseData {
    int32_t actionsTypeSize;
    uint32_t eventType;
    int32_t priority;
    int32_t deviceTags;
    std::vector<int32_t> actionsType;

    ParseData()
    {
        actionsTypeSize = -1;
        eventType = 0;
        priority = 0;
        deviceTags = 0;
    }
};

struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
        }
    }
    operator cJSON *()
    {
        return json_;
    }
    cJSON *json_ { nullptr };
};

struct DeviceConsumer {
    std::string name {};
    std::vector<int32_t> uids {};
};

struct ConsumersData {
    std::vector<DeviceConsumer> consumers {};
};
class MultimodalInputConnectStub : public IRemoteStub<IMultimodalInputConnect> {
public:
    MultimodalInputConnectStub() = default;
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectStub);
    virtual ~MultimodalInputConnectStub() = default;

    virtual bool IsRunning() const = 0;
    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& options) override;

protected:
    int32_t StubHandleAllocSocketFd(MessageParcel &data, MessageParcel &reply);
    int32_t StubAddInputEventFilter(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveInputEventFilter(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMouseScrollRows(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetMouseScrollRows(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerSize(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerSize(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetCursorSurfaceId(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetCustomCursor(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMouseIcon(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMouseHotSpot(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMousePrimaryButton(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetMousePrimaryButton(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetHoverScrollState(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetHoverScrollState(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerVisible(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerStyle(MessageParcel& data, MessageParcel& reply);
    int32_t StubNotifyNapOnline(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveInputEventObserver(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetNapStatus(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerStyle(MessageParcel& data, MessageParcel& reply);
    int32_t StubIsPointerVisible(MessageParcel& data, MessageParcel& reply);
    int32_t StubMarkProcessed(MessageParcel& data, MessageParcel& reply);
    int32_t StubSupportKeys(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetDeviceIds(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubRegisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnregisterInputDeviceMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetKeyboardType(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetKeyboardRepeatDelay(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetKeyboardRepeatRate(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetKeyboardRepeatDelay(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetKeyboardRepeatRate(MessageParcel& data, MessageParcel& reply);
    int32_t StubAddInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetInputDeviceConsumer(MessageParcel& data, MessageParcel& reply);
    int32_t StubClearInputDeviceConsumer(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubAddPreInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemovePreInputHandler(MessageParcel& data, MessageParcel& reply);
    int32_t StubAddGestureMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveGestureMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubMarkEventConsumed(MessageParcel& data, MessageParcel& reply);
    int32_t StubMoveMouseEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubInjectKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSubscribeKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeKeyEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSubscribeHotkey(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeHotkey(MessageParcel& data, MessageParcel& reply);
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    int32_t StubSubscribeKeyMonitor(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeKeyMonitor(MessageParcel& data, MessageParcel& reply);
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    int32_t StubSubscribeSwitchEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeSwitchEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubQuerySwitchStatus(MessageParcel& data, MessageParcel& reply);
    int32_t StubSubscribeTabletProximity(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnSubscribetabletProximity(MessageParcel& data, MessageParcel& reply);
    int32_t StubSubscribeLongPressEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubUnsubscribeLongPressEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubInjectPointerEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubInjectTouchPadEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetAnrListener(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetDisplayBindInfo(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetAllMmiSubscribedEvents(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetDisplayBind(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerColor(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerColor(MessageParcel& data, MessageParcel& reply);
    int32_t StubEnableCombineKey(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetFunctionKeyState(MessageParcel &data, MessageParcel &reply);
    int32_t StubSetFunctionKeyState(MessageParcel &data, MessageParcel &reply);
    int32_t StubSetPointerLocation(MessageParcel &data, MessageParcel &reply);
    int32_t StubSetMouseCaptureMode(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetWindowPid(MessageParcel& data, MessageParcel& reply);
    int32_t StubAppendExtraData(MessageParcel& data, MessageParcel& reply);
    int32_t StubEnableInputDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetKeyDownDuration(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadScrollSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadScrollDirection(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadTapSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadPointerSpeed(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadCDG(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadPinchSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadPinchSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadSwipeSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadSwipeSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadRightClickType(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadRightClickType(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadRotateSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadRotateSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadDoubleTapAndDragState(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadDoubleTapAndDragState(MessageParcel& data, MessageParcel& reply);
    int32_t StubClearWindowPointerStyle(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetShieldStatus(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetShieldStatus(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetKeyState(MessageParcel& data, MessageParcel& reply);
    int32_t StubAuthorize(MessageParcel& data, MessageParcel& reply);
    int32_t StubCancelInjection(MessageParcel& data, MessageParcel& reply);
    int32_t StubHasIrEmitter(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetInfraredFrequencies(MessageParcel& data, MessageParcel& reply);
    int32_t StubTransmitInfrared(MessageParcel& data, MessageParcel& reply);
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t StubCreateVKeyboardDevice(MessageParcel& data, MessageParcel& reply);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t StubSetPixelMapData(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMoveEventFilters(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetCurrentUser(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetTouchpadThreeFingersTapSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadThreeFingersTapSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubAddVirtualInputDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubRemoveVirtualInputDevice(MessageParcel& data, MessageParcel& reply);
    int32_t StubEnableHardwareCursorStats(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetHardwareCursorStats(MessageParcel& data, MessageParcel& reply);
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t StubGetPointerSnapshot(MessageParcel &data, MessageParcel &reply);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    int32_t StubSetTouchpadScrollRows(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetTouchpadScrollRows(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetClientInfo(MessageParcel &data, MessageParcel &reply);
#ifdef OHOS_BUILD_ENABLE_ANCO
    int32_t StubAncoAddChannel(MessageParcel& data, MessageParcel& reply);
    int32_t StubAncoRemoveChannel(MessageParcel& data, MessageParcel& reply);
    int32_t StubCheckKnuckleEvent(MessageParcel& data, MessageParcel& reply);
#endif // OHOS_BUILD_ENABLE_ANCO
    int32_t StubTransferBinderClientService(MessageParcel& data, MessageParcel& reply);
    int32_t StubSkipPointerLayer(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetIntervalSinceLastInput(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetAllSystemHotkeys(MessageParcel& data, MessageParcel& reply);
    int32_t ParseAddInputHandlerData(MessageParcel& data, ParseData& parseData);
    int32_t StubSetInputDeviceInputEnable(MessageParcel& data, MessageParcel& reply);
    int32_t StubShiftAppPointerEvent(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetCustomMouseCursor(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetMultiWindowScreenId(MessageParcel& data, MessageParcel& reply);
    int32_t StubSetKnuckleSwitch(MessageParcel& data, MessageParcel& reply);
    int32_t StubLaunchAiScreenAbility(MessageParcel& data, MessageParcel& reply);
    int32_t StubGetMaxMultiTouchPointNum(MessageParcel& data, MessageParcel& reply);

private:
    int32_t VerifyTouchPadSetting(void);
    int32_t HandleGestureMonitor(MultimodalinputConnectInterfaceCode code,
        MessageParcel& data, MessageParcel& reply);
    
    bool ParseDeviceConsumerConfig();
    std::vector<std::string> FilterConsumers(std::vector<std::string> &deviceNames);
    void UpdateConsumers(const cJSON* consumer);
    void DealConsumers(std::vector<std::string>& filterNames, const DeviceConsumer &consumer);
    
    ConsumersData consumersData_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_STUB_H
