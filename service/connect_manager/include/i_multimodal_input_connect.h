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

#ifndef I_MULTIMODAL_INPUT_CONNECT_H
#define I_MULTIMODAL_INPUT_CONNECT_H

#include <system_ability_definition.h>

#include "extra_data.h"
#ifdef OHOS_BUILD_ENABLE_ANCO
#include "i_anco_channel.h"
#endif // OHOS_BUILD_ENABLE_ANCO
#include "i_event_filter.h"
#include "infrared_frequency_info.h"
#include "input_device.h"
#include "key_option.h"
#include "long_press_event.h"
#include "nap_process.h"
#include "pointer_style.h"
#include "touchpad_control_display_gain.h"
#include "shift_info.h"

namespace OHOS {
namespace MMI {
class IMultimodalInputConnect : public IRemoteBroker {
public:
    enum {
        CONNECT_MODULE_TYPE_MMI_CLIENT = 0,
    };
    static constexpr int32_t INVALID_SOCKET_FD = -1;
    static constexpr int32_t MULTIMODAL_INPUT_CONNECT_SERVICE_ID = MULTIMODAL_INPUT_SERVICE_ID;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.multimodalinput.IConnectManager");

    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) = 0;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority,
        uint32_t deviceTags) = 0;
    virtual int32_t NotifyNapOnline() = 0;
    virtual int32_t RemoveInputEventObserver() = 0;
    virtual int32_t RemoveInputEventFilter(int32_t filterId) = 0;
    virtual int32_t SetMouseScrollRows(int32_t rows) = 0;
    virtual int32_t GetMouseScrollRows(int32_t &rows) = 0;
    virtual int32_t SetCustomCursor(int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap) = 0;
    virtual int32_t SetCustomCursor(int32_t windowId, CustomCursor cursor, CursorOptions options) = 0;
    virtual int32_t SetMouseIcon(int32_t windowId, void* pixelMap) = 0;
    virtual int32_t SetPointerSize(int32_t size) = 0;
    virtual int32_t SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus) = 0;
    virtual int32_t GetPointerSize(int32_t &size) = 0;
    virtual int32_t GetCursorSurfaceId(uint64_t &surfaceId) = 0;
    virtual int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) = 0;
    virtual int32_t SetMousePrimaryButton(int32_t primaryButton) = 0;
    virtual int32_t GetMousePrimaryButton(int32_t &primaryButton) = 0;
    virtual int32_t SetHoverScrollState(bool state) = 0;
    virtual int32_t GetHoverScrollState(bool &state) = 0;
    virtual int32_t SetPointerVisible(bool visible, int32_t priority) = 0;
    virtual int32_t IsPointerVisible(bool &visible) = 0;
    virtual int32_t MarkProcessed(int32_t eventType, int32_t eventId) = 0;
    virtual int32_t SetPointerColor(int32_t color) = 0;
    virtual int32_t GetPointerColor(int32_t &color) = 0;
    virtual int32_t EnableCombineKey(bool enable) = 0;
    virtual int32_t SetPointerSpeed(int32_t speed) = 0;
    virtual int32_t GetPointerSpeed(int32_t &speed) = 0;
    virtual int32_t SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false) = 0;
    virtual int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false) = 0;
    virtual int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke) = 0;
    virtual int32_t GetDeviceIds(std::vector<int32_t> &ids) = 0;
    virtual int32_t GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice) = 0;
    virtual int32_t RegisterDevListener() = 0;
    virtual int32_t UnregisterDevListener() = 0;
    virtual int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType) = 0;
    virtual int32_t SetKeyboardRepeatDelay(int32_t delay) = 0;
    virtual int32_t SetKeyboardRepeatRate(int32_t rate) = 0;
    virtual int32_t GetKeyboardRepeatDelay(int32_t &delay) = 0;
    virtual int32_t GetKeyboardRepeatRate(int32_t &rate) = 0;
    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, std::vector<int32_t> actionsType = std::vector<int32_t>()) = 0;
    virtual int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, std::vector<int32_t> actionsType = std::vector<int32_t>()) = 0;
    virtual int32_t AddPreInputHandler(int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys) = 0;
    virtual int32_t RemovePreInputHandler(int32_t handlerId) = 0;
    virtual int32_t AddGestureMonitor(InputHandlerType handlerType,
        HandleEventType eventType, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual int32_t RemoveGestureMonitor(InputHandlerType handlerType,
        HandleEventType eventType, TouchGestureType gestureType, int32_t fingers) = 0;
    virtual int32_t MarkEventConsumed(int32_t eventId) = 0;
    virtual int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) = 0;
    virtual int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject) = 0;
    virtual int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) = 0;
    virtual int32_t UnsubscribeKeyEvent(int32_t subscribeId) = 0;
    virtual int32_t SubscribeHotkey(int32_t subscribeId, const std::shared_ptr<KeyOption> option) = 0;
    virtual int32_t UnsubscribeHotkey(int32_t subscribeId) = 0;
    virtual int32_t SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType) = 0;
    virtual int32_t UnsubscribeSwitchEvent(int32_t subscribeId) = 0;
    virtual int32_t SubscribeLongPressEvent(int32_t subscribeId, const LongPressRequest &longPressRequest) = 0;
    virtual int32_t UnsubscribeLongPressEvent(int32_t subscribeId) = 0;
    virtual int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject) = 0;
    virtual int32_t InjectTouchPadEvent(std::shared_ptr<PointerEvent> pointerEvent,
        const TouchpadCDG &touchpadCDG, bool isNativeInject) = 0;
    virtual int32_t SetAnrObserver() = 0;
    virtual int32_t GetDisplayBindInfo(DisplayBindInfos &infos) = 0;
    virtual int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas) = 0;
    virtual int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) = 0;
    virtual int32_t GetFunctionKeyState(int32_t funckey, bool &state) = 0;
    virtual int32_t SetFunctionKeyState(int32_t funcKey, bool enable) = 0;
    virtual int32_t SetPointerLocation(int32_t x, int32_t y, int32_t displayId) = 0;
    virtual int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) = 0;
    virtual int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) = 0;
    virtual int32_t GetWindowPid(int32_t windowId) = 0;
    virtual int32_t AppendExtraData(const ExtraData& extraData) = 0;
    virtual int32_t EnableInputDevice(bool enable) = 0;
    virtual int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay) = 0;
    virtual int32_t SetTouchpadScrollSwitch(bool switchFlag) = 0;
    virtual int32_t GetTouchpadScrollSwitch(bool &switchFlag) = 0;
    virtual int32_t SetTouchpadScrollDirection(bool state) = 0;
    virtual int32_t GetTouchpadScrollDirection(bool &state) = 0;
    virtual int32_t SetTouchpadTapSwitch(bool switchFlag) = 0;
    virtual int32_t GetTouchpadTapSwitch(bool &switchFlag) = 0;
    virtual int32_t SetTouchpadPointerSpeed(int32_t speed) = 0;
    virtual int32_t GetTouchpadPointerSpeed(int32_t &speed) = 0;
    virtual int32_t GetTouchpadCDG(TouchpadCDG &touchpadCDG) = 0;
    virtual int32_t SetTouchpadPinchSwitch(bool switchFlag) = 0;
    virtual int32_t GetTouchpadPinchSwitch(bool &switchFlag) = 0;
    virtual int32_t SetTouchpadSwipeSwitch(bool switchFlag) = 0;
    virtual int32_t GetTouchpadSwipeSwitch(bool &switchFlag) = 0;
    virtual int32_t SetTouchpadRightClickType(int32_t type) = 0;
    virtual int32_t GetTouchpadRightClickType(int32_t &type) = 0;
    virtual int32_t SetTouchpadRotateSwitch(bool rotateSwitch) = 0;
    virtual int32_t GetTouchpadRotateSwitch(bool &rotateSwitch) = 0;
    virtual int32_t SetTouchpadDoubleTapAndDragState(bool switchFlag) = 0;
    virtual int32_t GetTouchpadDoubleTapAndDragState(bool &switchFlag) = 0;
    virtual int32_t SetShieldStatus(int32_t shieldMode, bool isShield) = 0;
    virtual int32_t GetShieldStatus(int32_t shieldMode, bool &isShield) = 0;
    virtual int32_t GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState) = 0;
    virtual int32_t Authorize(bool isAuthorize) = 0;
    virtual int32_t CancelInjection() = 0;
    virtual int32_t HasIrEmitter(bool &hasIrEmitter) = 0;
    virtual int32_t GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys) = 0;
    virtual int32_t TransmitInfrared(int64_t number, std::vector<int64_t>& pattern) = 0;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    virtual int32_t CreateVKeyboardDevice(sptr<IRemoteObject> &vkeyboardDevice) = 0;
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    virtual int32_t SetPixelMapData(int32_t infoId, void* pixelMap) = 0;
    virtual int32_t SetMoveEventFilters(bool flag) = 0;
    virtual int32_t SetCurrentUser(int32_t userId) = 0;
    virtual int32_t SetTouchpadThreeFingersTapSwitch(bool switchFlag) = 0;
    virtual int32_t GetTouchpadThreeFingersTapSwitch(bool &switchFlag) = 0;
    virtual int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId) = 0;
    virtual int32_t RemoveVirtualInputDevice(int32_t deviceId) = 0;
    virtual int32_t EnableHardwareCursorStats(bool enable) = 0;
    virtual int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) = 0;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    virtual int32_t GetPointerSnapshot(void *pixelMapPtr) = 0;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    virtual int32_t SetTouchpadScrollRows(int32_t rows) = 0;
    virtual int32_t GetTouchpadScrollRows(int32_t &rows) = 0;
    virtual int32_t SetClientInfo(int32_t pid, uint64_t readThreadId) = 0;
    virtual int32_t GetIntervalSinceLastInput(int64_t &timeInterval) = 0;
#ifdef OHOS_BUILD_ENABLE_ANCO
    virtual int32_t AncoAddChannel(sptr<IAncoChannel> channel) = 0;
    virtual int32_t AncoRemoveChannel(sptr<IAncoChannel> channel) = 0;
    virtual int32_t CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType) = 0;
#endif // OHOS_BUILD_ENABLE_ANCO
    virtual int32_t TransferBinderClientSrv(const sptr<IRemoteObject> &binderClientObject) = 0;
    virtual int32_t SkipPointerLayer(bool isSkip) = 0;
    virtual int32_t GetAllSystemHotkeys(std::vector<std::unique_ptr<KeyOption>> &keyOptions) = 0;
    virtual int32_t SetInputDeviceEnabled(int32_t deviceId, bool enable, int32_t index) = 0;
    virtual int32_t ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown) = 0;
    virtual int32_t SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_MULTIMODAL_INPUT_CONNECT_H
