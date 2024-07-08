/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_CONNECT_PROXY_H
#define MULTIMODAL_INPUT_CONNECT_PROXY_H

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"
#include "system_ability.h"

#include "i_multimodal_input_connect.h"
#include "mmi_event_observer.h"
#include "multimodalinput_ipc_interface_code.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectProxy final : public IRemoteProxy<IMultimodalInputConnect> {
public:
    explicit MultimodalInputConnectProxy(const sptr<IRemoteObject> &impl);
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectProxy);
    ~MultimodalInputConnectProxy() override;

    int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) override;
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
        uint32_t deviceTags) override;
    int32_t NotifyNapOnline() override;
    int32_t RemoveInputEventObserver() override;
    int32_t RemoveInputEventFilter(int32_t filterId) override;
    int32_t SetMouseScrollRows(int32_t rows) override;
    int32_t GetMouseScrollRows(int32_t &rows) override;
    int32_t SetPointerSize(int32_t size) override;
    int32_t SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus) override;
    int32_t GetPointerSize(int32_t &size) override;
    int32_t SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap) override;
    int32_t SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap) override;
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) override;
    int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) override;
    int32_t SetMousePrimaryButton(int32_t primaryButton) override;
    int32_t GetMousePrimaryButton(int32_t &primaryButton) override;
    int32_t SetHoverScrollState(bool state) override;
    int32_t GetHoverScrollState(bool &state) override;
    int32_t SetPointerVisible(bool visible, int32_t priority) override;
    int32_t IsPointerVisible(bool &visible) override;
    int32_t MarkProcessed(int32_t eventType, int32_t eventId) override;
    int32_t SetPointerColor(int32_t color) override;
    int32_t GetPointerColor(int32_t &color) override;
    int32_t SetPointerSpeed(int32_t speed) override;
    int32_t GetPointerSpeed(int32_t &speed) override;
    int32_t SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false) override;
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false) override;
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke) override;
    int32_t GetDeviceIds(std::vector<int32_t> &ids) override;
    int32_t GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice) override;
    int32_t RegisterDevListener() override;
    int32_t UnregisterDevListener() override;
    int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType) override;
    int32_t SetKeyboardRepeatDelay(int32_t delay) override;
    int32_t SetKeyboardRepeatRate(int32_t rate) override;
    int32_t GetKeyboardRepeatDelay(int32_t &delay) override;
    int32_t GetKeyboardRepeatRate(int32_t &rate) override;
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override;
    int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override;
    int32_t MarkEventConsumed(int32_t eventId) override;
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override;
    int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject) override;
    int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override;
    int32_t UnsubscribeKeyEvent(int32_t subscribeId) override;
    int32_t SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType) override;
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId) override;
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject) override;
    int32_t SetAnrObserver() override;
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos) override;
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas) override;
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) override;
    int32_t GetFunctionKeyState(int32_t funcKey, bool &state) override;
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override;
    int32_t SetPointerLocation(int32_t x, int32_t y) override;
    virtual int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) override;
    int32_t GetWindowPid(int32_t windowId) override;
    int32_t AppendExtraData(const ExtraData& extraData) override;
    int32_t EnableCombineKey(bool enable) override;
    int32_t EnableInputDevice(bool enable) override;
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay) override;
    int32_t SetTouchpadScrollSwitch(bool switchFlag) override;
    int32_t GetTouchpadScrollSwitch(bool &switchFlag) override;
    int32_t SetTouchpadScrollDirection(bool state) override;
    int32_t GetTouchpadScrollDirection(bool &state) override;
    int32_t SetTouchpadTapSwitch(bool switchFlag) override;
    int32_t GetTouchpadTapSwitch(bool &switchFlag) override;
    int32_t SetTouchpadPointerSpeed(int32_t speed) override;
    int32_t GetTouchpadPointerSpeed(int32_t &speed) override;
    int32_t SetTouchpadPinchSwitch(bool switchFlag) override;
    int32_t GetTouchpadPinchSwitch(bool &switchFlag) override;
    int32_t SetTouchpadSwipeSwitch(bool switchFlag) override;
    int32_t GetTouchpadSwipeSwitch(bool &switchFlag) override;
    int32_t SetTouchpadRightClickType(int32_t type) override;
    int32_t GetTouchpadRightClickType(int32_t &type) override;
    int32_t SetTouchpadRotateSwitch(bool rotateSwitch) override;
    int32_t GetTouchpadRotateSwitch(bool &rotateSwitch) override;
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield) override;
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield) override;
    int32_t GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState) override;
    int32_t Authorize(bool isAuthorize) override;
    int32_t CancelInjection() override;
    int32_t HasIrEmitter(bool &hasIrEmitter) override;
    int32_t GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys) override;
    int32_t TransmitInfrared(int64_t number, std::vector<int64_t>& pattern) override;
    int32_t SetPixelMapData(int32_t infoId, void* pixelMap) override;
    int32_t SetCurrentUser(int32_t userId) override;
    int32_t SetTouchpadThreeFingersTapSwitch(bool switchFlag) override;
    int32_t GetTouchpadThreeFingersTapSwitch(bool &switchFlag) override;
    
    int32_t EnableHardwareCursorStats(bool enable) override;
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) override;
    int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId) override;
    int32_t RemoveVirtualInputDevice(int32_t deviceId) override;
#ifdef OHOS_BUILD_ENABLE_ANCO
    int32_t AncoAddChannel(sptr<IAncoChannel> channel) override;
    int32_t AncoRemoveChannel(sptr<IAncoChannel> channel) override;
#endif // OHOS_BUILD_ENABLE_ANCO
	int32_t TransferBinderClientSrv(const sptr<IRemoteObject> &binderClientObject) override;

private:
    static inline BrokerDelegator<MultimodalInputConnectProxy> delegator_;
    int32_t SetTouchpadBoolData(bool date, int32_t type);
    int32_t GetTouchpadBoolData(bool &date, int32_t type);
    int32_t SetTouchpadInt32Data(int32_t date, int32_t type);
    int32_t GetTouchpadInt32Data(int32_t &date, int32_t type);
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_PROXY_H
