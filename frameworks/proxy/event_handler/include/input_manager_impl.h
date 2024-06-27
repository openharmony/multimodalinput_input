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

#ifndef INPUT_MANAGER_IMPL_H
#define INPUT_MANAGER_IMPL_H

#include <list>
#include <vector>

#include "singleton.h"

#include "net_packet.h"

#include "event_filter_service.h"
#include "event_handler.h"
#include "extra_data.h"
#include "i_anco_channel.h"
#include "i_anr_observer.h"
#include "i_input_event_consumer.h"
#include "i_input_service_watcher.h"
#include "i_window_checker.h"
#include "if_mmi_client.h"
#include "infrared_frequency_info.h"
#include "input_device_impl.h"
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
#include "input_interceptor_manager.h"
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
#include "input_monitor_manager.h"
#endif // OHOS_BUILD_ENABLE_MONITOR
#include "key_option.h"
#include "mmi_event_observer.h"
#include "nap_process.h"
#include "pointer_event.h"
#include "pointer_style.h"
#include "switch_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class InputManagerImpl final {
    DECLARE_SINGLETON(InputManagerImpl);

public:
    DISALLOW_MOVE(InputManagerImpl);

    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t GetWindowPid(int32_t windowId);
    int32_t UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
    int32_t UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo);
    void SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    void SetEnhanceConfig(uint8_t *cfg, uint32_t cfgLen);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    int32_t SubscribeKeyEvent(
        std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback
    );
    void UnsubscribeKeyEvent(int32_t subscriberId);
    int32_t SubscribeSwitchEvent(int32_t switchType, std::function<void(std::shared_ptr<SwitchEvent>)> callback);
    void UnsubscribeSwitchEvent(int32_t subscriberId);
    int32_t AddInputEventFilter(std::shared_ptr<IInputEventFilter> filter, int32_t priority, uint32_t deviceTags);
    int32_t RemoveInputEventFilter(int32_t filterId);
    int32_t AddInputEventObserver(std::shared_ptr<MMIEventObserver> observer);
    int32_t RemoveInputEventObserver(std::shared_ptr<MMIEventObserver> observer);
    int32_t NotifyNapOnline();
    void NotifyBundleName(int32_t pid, int32_t uid, const std::string &bundleName, int32_t syncStatus);
    void SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
        std::shared_ptr<AppExecFwk::EventHandler> eventHandler);
    void ClearWindowPointerStyle(int32_t pid, int32_t windowId);
    int32_t SetNapStatus(int32_t pid, int32_t uid, const std::string &bundleName, int32_t napStatus);

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    int32_t PackDisplayData(NetPacket &pkt);

    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);
    int32_t AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor);
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> consumer,
        HandleEventType eventType = HANDLE_EVENT_TYPE_ALL);

    void RemoveMonitor(int32_t monitorId);
    void MarkConsumed(int32_t monitorId, int32_t eventId);
    void MoveMouse(int32_t offsetX, int32_t offsetY);

    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor,
        int32_t priority = DEFUALT_INTERCEPTOR_PRIORITY,
        uint32_t deviceTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX));
    int32_t AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor,
        int32_t priority = DEFUALT_INTERCEPTOR_PRIORITY,
        uint32_t deviceTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX));
    void RemoveInterceptor(int32_t interceptorId);

    void SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject = false);
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject = false);
    void HandleSimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void OnConnected();
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    template<typename T>
    bool RecoverPointerEvent(std::initializer_list<T> pointerActionEvents, T pointerActionEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void OnDisconnected();

    int32_t RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener);
    int32_t UnregisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener = nullptr);
    int32_t GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback);
    int32_t GetDevice(int32_t deviceId, std::function<void(std::shared_ptr<InputDevice>)> callback);
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
        std::function<void(std::vector<bool>&)> callback);
    int32_t GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback);
    int32_t SetKeyboardRepeatDelay(int32_t delay);
    int32_t SetKeyboardRepeatRate(int32_t rate);
    int32_t GetKeyboardRepeatDelay(std::function<void(int32_t)> callback);
    int32_t GetKeyboardRepeatRate(std::function<void(int32_t)> callback);

    int32_t SetMouseScrollRows(int32_t rows);
    int32_t GetMouseScrollRows(int32_t &rows);
    int32_t SetPointerSize(int32_t size);
    int32_t GetPointerSize(int32_t &size);
    int32_t SetCustomCursor(int32_t windowId, int32_t focusX, int32_t focusY, void* pixelMap);
    int32_t SetMouseIcon(int32_t windowId, void* pixelMap);
    int32_t SetMouseHotSpot(int32_t windowId, int32_t hotSpotX, int32_t hotSpotY);
    int32_t SetMousePrimaryButton(int32_t primaryButton);
    int32_t GetMousePrimaryButton(int32_t &primaryButton);
    int32_t SetHoverScrollState(bool state);
    int32_t GetHoverScrollState(bool &state);

    int32_t SetPointerVisible(bool visible, int32_t priority);
    bool IsPointerVisible();
    int32_t SetPointerStyle(int32_t windowId, const PointerStyle& pointerStyle, bool isUiExtension = false);
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false);

    int32_t SetPointerColor(int32_t color);
    int32_t GetPointerColor(int32_t &color);
    int32_t EnableCombineKey(bool enable);
    int32_t SetPointerSpeed(int32_t speed);
    int32_t GetPointerSpeed(int32_t &speed);

    int32_t SetTouchpadScrollSwitch(bool switchFlag);
    int32_t GetTouchpadScrollSwitch(bool &switchFlag);
    int32_t SetTouchpadScrollDirection(bool state);
    int32_t GetTouchpadScrollDirection(bool &state);
    int32_t SetTouchpadTapSwitch(bool switchFlag);
    int32_t GetTouchpadTapSwitch(bool &switchFlag);
    int32_t SetTouchpadPointerSpeed(int32_t speed);
    int32_t GetTouchpadPointerSpeed(int32_t &speed);
    int32_t SetTouchpadPinchSwitch(bool switchFlag);
    int32_t GetTouchpadPinchSwitch(bool &switchFlag);
    int32_t SetTouchpadSwipeSwitch(bool switchFlag);
    int32_t GetTouchpadSwipeSwitch(bool &switchFlag);
    int32_t SetTouchpadRightClickType(int32_t type);
    int32_t GetTouchpadRightClickType(int32_t &type);
    int32_t SetTouchpadRotateSwitch(bool rotateSwitch);
    int32_t GetTouchpadRotateSwitch(bool &rotateSwitch);
    int32_t EnableHardwareCursorStats(bool enable);
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount);

    void SetAnrObserver(std::shared_ptr<IAnrObserver> observer);
    void OnAnr(int32_t pid);

    int32_t EnterCaptureMode(int32_t windowId);
    int32_t LeaveCaptureMode(int32_t windowId);
    bool GetFunctionKeyState(int32_t funcKey);
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable);
    int32_t SetPointerLocation(int32_t x, int32_t y);
    int32_t EnableInputDevice(bool enable);
    // 快捷键拉起Ability
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay);

    void AppendExtraData(const ExtraData& extraData);
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield);
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield);

    void AddServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher);
    void RemoveServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher);

    int32_t MarkProcessed(int32_t eventId, int64_t actionTime);

    int32_t GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState);
    void Authorize(bool isAuthorize);
    int32_t CancelInjection();

    int32_t HasIrEmitter(bool &hasIrEmitter);
    int32_t GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys);
    int32_t TransmitInfrared(int64_t number, std::vector<int64_t>& pattern);
    int32_t SetPixelMapData(int32_t infoId, void* pixelMap);
    int32_t SetCurrentUser(int32_t userId);
    int32_t GetWinSyncBatchSize(int32_t maxAreasCount, int32_t displayCount);
    int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId);
    int32_t RemoveVirtualInputDevice(int32_t deviceId);
    int32_t AncoAddChannel(std::shared_ptr<IAncoConsumer> consumer);
    int32_t AncoRemoveChannel(std::shared_ptr<IAncoConsumer> consumer);

private:
    int32_t PackWindowInfo(NetPacket &pkt);
    int32_t PackWindowGroupInfo(NetPacket &pkt);
    int32_t PackDisplayInfo(NetPacket &pkt);
    void PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo);
    void PrintForemostThreeWindowInfo(const std::vector<WindowInfo> &windowsInfo);
    void PrintDisplayInfo();
    void PrintWindowGroupInfo();
    int32_t SendDisplayInfo();
    int32_t SendWindowInfo();
    void SendWindowAreaInfo(WindowArea area, int32_t pid, int32_t windowId);
    bool IsValiadWindowAreas(const std::vector<WindowInfo> &windows);
    int32_t GetDisplayMaxSize();
    int32_t GetWindowMaxSize(int32_t maxAreasCount);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    int32_t PackEnhanceConfig(NetPacket &pkt);
    void SendEnhanceConfig();
    void PrintEnhanceConfig();
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    void ReAddInputEventFilter();

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnKeyEventTask(std::shared_ptr<IInputEventConsumer> consumer,
        std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnPointerEventTask(std::shared_ptr<IInputEventConsumer> consumer,
        std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_ANCO
    bool IsValidAncoWindow(const std::vector<WindowInfo> &windows);
#endif // OHOS_BUILD_ENABLE_ANCO

private:
    std::map<int32_t, std::tuple<sptr<IEventFilter>, int32_t, uint32_t>> eventFilterServices_;
    std::shared_ptr<MMIEventObserver> eventObserver_ { nullptr };
    std::shared_ptr<IInputEventConsumer> consumer_ { nullptr };
    std::vector<std::shared_ptr<IAnrObserver>> anrObservers_;
    std::shared_ptr<IWindowChecker> winChecker_ { nullptr };
    DisplayGroupInfo displayGroupInfo_ {};
    WindowGroupInfo windowGroupInfo_ {};
    std::mutex mtx_;
    std::mutex handleMtx_;
    mutable std::mutex resourceMtx_;
    std::condition_variable cv_;
    std::thread ehThread_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_ { nullptr };
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    uint8_t* enhanceCfg_ = nullptr;
    uint32_t enhanceCfgLen_ = 0;
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#ifdef OHOS_BUILD_ENABLE_ANCO
    std::map<std::shared_ptr<IAncoConsumer>, sptr<IAncoChannel>> ancoChannels_;
#endif // OHOS_BUILD_ENABLE_ANCO
};

#define InputMgrImpl ::OHOS::Singleton<InputManagerImpl>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_IMPL_H
