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

#ifndef INPUT_MANAGER_IMPL_H
#define INPUT_MANAGER_IMPL_H

#include <list>
#include <vector>

#include "singleton.h"

#include "net_packet.h"

#include "window_info.h"
#include "event_filter_service.h"
#include "event_handler.h"
#include "extra_data.h"
#include "if_mmi_client.h"
#include "input_device_impl.h"
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
#include "input_interceptor_manager.h"
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
#include "input_monitor_manager.h"
#endif // OHOS_BUILD_ENABLE_MONITOR
#include "i_anr_observer.h"
#include "key_option.h"
#include "pointer_event.h"
#include "pointer_style.h"
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#include "sec_comp_enhance_adapter.h"
#include "sec_comp_input_enhance.h"
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#include "switch_event.h"

namespace OHOS {
namespace MMI {
class InputManagerImpl final {
    DECLARE_SINGLETON(InputManagerImpl);

public:
    DISALLOW_MOVE(InputManagerImpl);

    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t GetWindowPid(int32_t windowId);
    void UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    void SetEnhanceConfig(SecCompEnhanceCfgBase *cfg);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    int32_t SubscribeKeyEvent(
        std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback
    );
    void UnsubscribeKeyEvent(int32_t subscriberId);
    int32_t SubscribeSwitchEvent(std::function<void(std::shared_ptr<SwitchEvent>)> callback);
    void UnsubscribeSwitchEvent(int32_t subscriberId);
    int32_t AddInputEventFilter(std::shared_ptr<IInputEventFilter> filter, int32_t priority, uint32_t deviceTags);
    int32_t RemoveInputEventFilter(int32_t filterId);

    void SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
        std::shared_ptr<AppExecFwk::EventHandler> eventHandler);

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    void OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    int32_t PackDisplayData(NetPacket &pkt);

    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);
    int32_t AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor);
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> consumer);

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

    void SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent);
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void OnConnected();

    int32_t RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener);
    int32_t UnregisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener = nullptr);
    int32_t GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback);
    int32_t GetDevice(int32_t deviceId, std::function<void(std::shared_ptr<InputDevice>)> callback);
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes,
        std::function<void(std::vector<bool>&)> callback);
    int32_t GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback);

    int32_t SetMouseScrollRows(int32_t rows);
    int32_t GetMouseScrollRows(int32_t &rows);
    int32_t SetMouseIcon(int32_t windowId, void* pixelMap);
    int32_t SetMousePrimaryButton(int32_t primaryButton);
    int32_t GetMousePrimaryButton(int32_t &primaryButton);
    int32_t SetHoverScrollState(bool state);
    int32_t GetHoverScrollState(bool &state);

    int32_t SetPointerVisible(bool visible);
    bool IsPointerVisible();
    int32_t SetPointerStyle(int32_t windowId, const PointerStyle& pointerStyle);
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle);

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

    void SetAnrObserver(std::shared_ptr<IAnrObserver> observer);
    void OnAnr(int32_t pid);

    int32_t EnterCaptureMode(int32_t windowId);
    int32_t LeaveCaptureMode(int32_t windowId);
    bool GetFunctionKeyState(int32_t funcKey);
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable);
    void SetPointerLocation(int32_t x, int32_t y);
    int32_t EnableInputDevice(bool enable);
    // 快捷键拉起Ability
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay);

    EventHandlerPtr GetEventHandler() const;
    void AppendExtraData(const ExtraData& extraData);
private:
    int32_t PackWindowInfo(NetPacket &pkt);
    int32_t PackDisplayInfo(NetPacket &pkt);
    void PrintDisplayInfo();
    void SendDisplayInfo();
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
private:
    std::map<int32_t, std::tuple<sptr<IEventFilter>, int32_t, uint32_t>> eventFilterServices_;
    std::shared_ptr<IInputEventConsumer> consumer_ { nullptr };
    std::vector<std::shared_ptr<IAnrObserver>> anrObservers_;

    DisplayGroupInfo displayGroupInfo_ {};
    std::mutex mtx_;
    std::mutex handleMtx_;
    std::condition_variable cv_;
    std::thread ehThread_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    Security::SecurityComponentEnhance::SecCompEnhanceCfg* secCompEnhanceCfgBase_ {};
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
};

#define InputMgrImpl ::OHOS::Singleton<InputManagerImpl>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_IMPL_H
