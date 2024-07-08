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

#ifndef INPUT_MANAGER_H
#define INPUT_MANAGER_H

#include <list>
#include <map>
#include <memory>
#include <vector>

#include "event_handler.h"
#include "nocopyable.h"

#include "error_multimodal.h"
#include "extra_data.h"
#include "i_anco_consumer.h"
#include "i_anr_observer.h"
#include "i_input_device_listener.h"
#include "i_input_event_consumer.h"
#include "i_input_event_filter.h"
#include "i_input_service_watcher.h"
#include "i_window_checker.h"
#include "infrared_frequency_info.h"
#include "input_device.h"
#include "input_handler_type.h"
#include "key_option.h"
#include "mmi_event_observer.h"
#include "pointer_style.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class InputManager {
public:
    /**
     * @brief Obtains an <b>InputManager</b> instance.
     * @return Returns the pointer to the <b>InputManager</b> instance.
     * @since 9
     */
    static InputManager *GetInstance();
    virtual ~InputManager() = default;

    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);

    /**
     * @brief Updates the screen and window information.
     * @param displayGroupInfo Indicates the logical screen information.
     * @since 9
     */
    int32_t UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo);

    /**
     * @brief Updates the windows information.
     * @param windowGroupInfo Indicates the window group information.
     * @since 9
     */
    int32_t UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo);

    int32_t AddInputEventFilter(std::shared_ptr<IInputEventFilter> filter, int32_t priority, uint32_t deviceTags);
    int32_t RemoveInputEventFilter(int32_t filterId);

    /**
     * @brief Updates the process info to other server.
     * @param observer Indicates the progess info.
     * @return the observer setting successed or not.
     * @since 10
     */
    int32_t AddInputEventObserver(std::shared_ptr<MMIEventObserver> observer);

    /**
     * @brief Callback interface of the remove module.
     * @param observer Indicates the progess info.
     * @return EC_OK if unsubscribe successfully, else return other errcodes.
     * @since 10
     */
    int32_t RemoveInputEventObserver(std::shared_ptr<MMIEventObserver> observer = nullptr);

    /**
     * @brief Set the process info to mmi server.
     * @param pid Indicates pid.
     * @param uid Indicates uid.
     * @param bundleName Indicates bundleName.
     * @param napStatus Indicates napStatus.
     * @since 10
     */
    void SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus);

    /**
     * @brief Get the process info datas to other server.
     * @param callback Indicates the callback used to receive the reported data.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 10
     */
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas);

    /**
     * @brief Sets a consumer for the window input event of the current process.
     * @param inputEventConsumer Indicates the consumer to set. The window input event of the current process
     * will be called back to the consumer object for processing.
     * @since 9
     */
    void SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer);

    /**
     * @brief Sets a window input event consumer that runs on the specified thread.
     * @param inputEventConsumer Indicates the consumer to set.
     * @param eventHandler Indicates the thread running the consumer.
     * @since 9
     */
    void SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
        std::shared_ptr<AppExecFwk::EventHandler> eventHandler);

    /**
     * @brief Subscribes to the key input event that meets a specific condition. When such an event occurs,
     * the <b>callback</b> specified is invoked to process the event.
     * @param keyOption Indicates the condition of the key input event.
     * @param callback Indicates the callback.
     * @return Returns the subscription ID, which uniquely identifies a subscription in the process.
     * If the value is greater than or equal to <b>0</b>,
     * the subscription is successful. Otherwise, the subscription fails.
     * @since 9
     */
    int32_t SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);

    /**
     * @brief Unsubscribes from a key input event.
     * @param subscriberId Indicates the subscription ID, which is the return value of <b>SubscribeKeyEvent</b>.
     * @return void
     * @since 9
     */
    void UnsubscribeKeyEvent(int32_t subscriberId);

    /**
     * @brief Subscribes to the switch input event that meets a specific condition. When such an event occurs,
     * the <b>callback</b> specified is invoked to process the event.
     * @param callback Indicates the callback.
     * @param switchType Indicates the type of switch input event.
     * @return Returns the subscription ID, which uniquely identifies a subscription in the process.
     * If the value is greater than or equal to <b>0</b>,
     * the subscription is successful. Otherwise, the subscription fails.
     * @since 9
     */
    int32_t SubscribeSwitchEvent(std::function<void(std::shared_ptr<SwitchEvent>)> callback,
        SwitchEvent::SwitchType switchType = SwitchEvent::SwitchType::SWITCH_DEFAULT);

    /**
     * @brief Unsubscribes from a switch input event.
     * @param subscriberId Indicates the subscription ID, which is the return value of <b>SubscribeKeyEvent</b>.
     * @return void
     * @since 9
     */
    void UnsubscribeSwitchEvent(int32_t subscriberId);

    /**
     * @brief Adds an input event monitor. After such a monitor is added,
     * an input event is copied and distributed to the monitor while being distributed to the original target.
     * @param monitor Indicates the input event monitor. After an input event is generated,
     * the functions of the monitor object will be called.
     * @return Returns the monitor ID, which uniquely identifies a monitor in the process.
     * If the value is greater than or equal to <b>0</b>, the monitor is successfully added. Otherwise,
     * the monitor fails to be added.
     * @since 9
     */
    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);

    /**
     * @brief Adds an input event monitor. After such a monitor is added,
     * an input event is copied and distributed to the monitor while being distributed to the original target.
     * @param monitor Indicates the input event monitor. After an input event is generated,
     * the functions of the monitor object will be called.
     * @return Returns the monitor ID, which uniquely identifies a monitor in the process.
     * If the value is greater than or equal to <b>0</b>, the monitor is successfully added. Otherwise,
     * the monitor fails to be added.
     * @since 9
     */
    int32_t AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor);

    /**
     * @brief Adds an input event monitor. After such a monitor is added,
     * an input event is copied and distributed to the monitor while being distributed to the original target.
     * @param monitor Indicates the input event monitor. After an input event is generated,
     * the functions of the monitor object will be called.
     * @param eventType Indicates the eventType for monitor.
     * @return Returns the monitor ID, which uniquely identifies a monitor in the process.
     * If the value is greater than or equal to <b>0</b>, the monitor is successfully added. Otherwise,
     * the monitor fails to be added.
     * @since 9
     */
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> monitor, HandleEventType eventType = HANDLE_EVENT_TYPE_ALL);

    /**
     * @brief Removes a monitor.
     * @param monitorId Indicates the monitor ID, which is the return value of <b>AddMonitor</b>.
     * @return void
     * @since 9
     */
    void RemoveMonitor(int32_t monitorId);

    /**
     * @brief Marks that a monitor has consumed a touchscreen input event. After being consumed,
     * the touchscreen input event will not be distributed to the original target.
     * @param monitorId Indicates the monitor ID.
     * @param eventId Indicates the ID of the consumed touchscreen input event.
     * @return void
     * @since 9
     */
    void MarkConsumed(int32_t monitorId, int32_t eventId);

    /**
     * @brief Moves the cursor to the specified position.
     * @param offsetX Indicates the offset on the X axis.
     * @param offsetY Indicates the offset on the Y axis.
     * @return void
     * @since 9
     */
    void MoveMouse(int32_t offsetX, int32_t offsetY);

    /**
     * @brief Adds an input event interceptor. After such an interceptor is added,
     * an input event will be distributed to the interceptor instead of the original target and monitor.
     * @param interceptor Indicates the input event interceptor. After an input event is generated,
     * the functions of the interceptor object will be called.
     * @return Returns the interceptor ID, which uniquely identifies an interceptor in the process.
     * If the value is greater than or equal to <b>0</b>,the interceptor is successfully added. Otherwise,
     * the interceptor fails to be added.
     * @since 9
     */
    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor);
    int32_t AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor);
    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor, int32_t priority, uint32_t deviceTags);

    /**
     * @brief Removes an interceptor.
     * @param interceptorId Indicates the interceptor ID, which is the return value of <b>AddInterceptor</b>.
     * @return void
     * @since 9
     */
    void RemoveInterceptor(int32_t interceptorId);

    /**
     * @brief Simulates a key input event. This event will be distributed and
     * processed in the same way as the event reported by the input device.
     * @param keyEvent Indicates the key input event to simulate.
     * @return void
     * @since 9
     */
    void SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent);

    /**
     * @brief Simulates a touchpad input event, touchscreen input event, or mouse device input event.
     * This event will be distributed and processed in the same way as the event reported by the input device.
     * @param pointerEvent Indicates the touchpad input event, touchscreen input event,
     * or mouse device input event to simulate.
     * @return void
     * @since 9
     */
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent);

    /**
     * @brief Simulates a touchpad input event, touchscreen input event, or mouse device input event.
     * This event will be distributed and processed in the same way as the event reported by the input device.
     * @param pointerEvent Indicates the touchpad input event, touchscreen input event,
     * or mouse device input event to simulate.
     * @param zOrder Indicates the point event will inject to the window whose index value is less than the zOrder
     * @return void
     * @since 9
     */
    void SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent, float zOrder);

    /**
     * @brief Starts listening for an input device event.
     * @param type Indicates the type of the input device event, which is <b>change</b>.
     * @param listener Indicates the listener for the input device event.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener);

    /**
     * @brief Stops listening for an input device event.
     * @param type Indicates the type of the input device event, which is <b>change</b>.
     * @param listener Indicates the listener for the input device event.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t UnregisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener = nullptr);

    /**
     * @brief Obtains the information about an input device.
     * @param callback Indicates the callback used to receive the reported data.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback);

    /**
     * @brief Obtains the information about an input device.
     * @param deviceId Indicates the ID of the input device whose information is to be obtained.
     * @param callback Indicates the callback used to receive the reported data.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetDevice(int32_t deviceId, std::function<void(std::shared_ptr<InputDevice>)> callback);

    /**
     * @brief Checks whether the specified key codes of an input device are supported.
     * @param deviceId Indicates the ID of the input device.
     * @param keyCodes Indicates the key codes of the input device.
     * @param callback Indicates the callback used to receive the reported data.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes,
        std::function<void(std::vector<bool>&)> callback);

    /**
     * @brief Sets the number of the mouse scrolling rows.
     * @param rows Indicates the number of the mouse scrolling rows.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetMouseScrollRows(int32_t rows);

    /**
     * @brief Set pixelMap to override ohos mouse icon resouce.
     * @param windowId Indicates the windowId of the window
     * @param pixelMap Indicates the image resouce for this mouse icon. which realtype must be OHOS::Media::PixelMap*
     * @param focusX Indicates focus x
     * @param focusY Indicates focus y
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetCustomCursor(int32_t windowId, void* pixelMap, int32_t focusX = 0, int32_t focusY = 0);

    /**
     * @brief Set pixelMap to override ohos mouse icon resouce.
     * @param windowId Indicates the windowId of the window
     * @param pixelMap Indicates the image resouce for this mouse icon. which realtype must be OHOS::Media::PixelMap*
     * @return vint32_t
     * @since 10
     */
    int32_t SetMouseIcon(int32_t windowId, void* pixelMap);

    /**
     * @brief Set mouse icon hot spot.
     * @param windowId Indicates the windowId of the window
     * @param hotSpotX Indicates the hot spot x for this mouse icon.
     * @param hotSpotY Indicates the hot spot y for this mouse icon.
     * @return vint32_t
     * @since 10
     */
    int32_t SetMouseHotSpot(int32_t windowId, int32_t hotSpotX, int32_t hotSpotY);

    /**
     * @brief Gets the number of the mouse scrolling rows.
     * @param rows Indicates the number of the mouse scrolling rows.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetMouseScrollRows(int32_t &rows);

    /**
     * @brief Sets pointer size.
     * @param size Indicates pointer size.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetPointerSize(int32_t size);

    /**
     * @brief Gets pointer size.
     * @param size Indicates pointer size.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetPointerSize(int32_t &size);

    /**
     * @brief Enable combine key
     * @param enable Indicates whether the combine key is enabled. The value true indicates that the combine key
     * is enabled, and the value false indicates the opposite.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 11
     */
    int32_t EnableCombineKey(bool enable);

    /**
     * @brief Sets mouse primary button.
     * @param primaryButton Indicates the ID of the mouse primary button.The value 0 indicates that
     * the primary button is left button.The value 1 indicates that the primary button is right button.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetMousePrimaryButton(int32_t primaryButton);

    /**
     * @brief Gets mouse primary button.
     * @param primaryButton Indicates the ID of the mouse primary button.The value 0 indicates that
     * the primary button is left button.The value 1 indicates that the primary button is right button.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetMousePrimaryButton(int32_t &primaryButton);

    /**
     * @brief Sets whether the mouse hover scroll is enabled in inactive window.
     * @param state Indicates whether the mouse hover scroll is enabled in inactive window. The value true
     * indicates that the mouse hover scroll is enabled, and the value false indicates the opposite.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetHoverScrollState(bool state);

    /**
     * @brief Gets a status whether the mouse hover scroll is enabled in inactive window.
     * @param state Indicates whether the mouse hover scroll is enabled in inactive window. The value true
     * indicates that the mouse hover scroll is enabled, and the value false indicates the opposite.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetHoverScrollState(bool &state);

    /**
     * @brief Sets whether the pointer icon is visible.
     * @param visible Indicates whether the pointer icon is visible. The value <b>true</b> indicates that
     * the pointer icon is visible, and the value <b>false</b> indicates the opposite.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetPointerVisible(bool visible, int32_t priority = 0);

    /**
     * @brief Checks whether the pointer icon is visible.
     * @return Returns <b>true</b> if the pointer icon is visible; returns <b>false</b> otherwise.
     * @since 9
     */
    bool IsPointerVisible();

    /**
     * @brief Sets the mouse pointer style.
     * @param windowId Indicates the ID of the window for which the mouse pointer style is set.
     * @param pointerStyle Indicates the ID of the mouse pointer style.
     * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
     * @since 9
     */
    int32_t SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false);

    /**
     * @brief Obtains the mouse pointer style.
     * @param windowId Indicates the ID of the window for which the mouse pointer style is obtained.
     * @param pointerStyle Indicates the ID of the mouse pointer style.
     * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
     * @since 9
     */
    int32_t GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension = false);

    /**
     * @brief Sets pointer color.
     * @param color Indicates pointer color.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetPointerColor(int32_t color);

    /**
     * @brief Gets pointer color.
     * @param color Indicates pointer color.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetPointerColor(int32_t &color);

    /**
     * @brief Sets the mouse pointer speed, which ranges from 1 to 11.
     * @param speed Indicates the mouse pointer speed to set.
     * @return Returns <b>RET_OK</b> if success; returns <b>RET_ERR</b> otherwise.
     * @since 9
     */
    int32_t SetPointerSpeed(int32_t speed);

    /**
     * @brief Obtains the mouse pointer speed.
     * @param speed Indicates the mouse pointer speed to get.
     * @return Returns the mouse pointer speed if the operation is successful; returns <b>RET_ERR</b> otherwise.
     * @since 9
     */
    int32_t GetPointerSpeed(int32_t &speed);

    /**
     * @brief Queries the keyboard type.
     * @param deviceId Indicates the keyboard device ID.
     * @param callback Callback used to return the keyboard type.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback);

    /**
     * @brief Sets the observer for events indicating that the application does not respond.
     * @param observer Indicates the observer for events indicating that the application does not respond.
     * @return void
     * @since 9
     */
    void SetAnrObserver(std::shared_ptr<IAnrObserver> observer);

    /**
     * @brief Obtains the enablement status of the specified function key on the keyboard.
     * @param funcKey Indicates the function key. Currently, the following function keys are supported:
     * NUM_LOCK_FUNCTION_KEY
     * CAPS_LOCK_FUNCTION_KEY
     * SCROLL_LOCK_FUNCTION_KEY
     * @return Returns <b>true</b> if the function key is enabled;
     * returns <b>false</b> otherwise.
     */
    bool GetFunctionKeyState(int32_t funcKey);

    /**
     * @brief Sets the enablement status of the specified function key on the keyboard.
     * @param funcKey Indicates the function key. Currently, the following function keys are supported:
     * NUM_LOCK_FUNCTION_KEY
     * CAPS_LOCK_FUNCTION_KEY
     * SCROLL_LOCK_FUNCTION_KEY
     * @param isEnable Indicates the enablement status to set.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     */
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable);

    /**
     * @brief Sets the absolute coordinate of mouse.
     * @param x Specifies the x coordinate of the mouse to be set.
     * @param y Specifies the y coordinate of the mouse to be set.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetPointerLocation(int32_t x, int32_t y);

    /**
     * @brief 进入捕获模式
     * @param windowId 窗口id.
     * @return 进入捕获模式成功或失败.
     * @since 9
     */
    int32_t EnterCaptureMode(int32_t windowId);

    /**
     * @brief 退出捕获模式
     * @param windowId 窗口id.
     * @return 退出捕获模式成功或失败.
     * @since 9
     */
    int32_t LeaveCaptureMode(int32_t windowId);

    int32_t GetWindowPid(int32_t windowId);

    /**
     * @brief pointer event添加辅助信息
     * @param extraData 添加的信息.
     * @return void
     * @since 9
     */
    void AppendExtraData(const ExtraData& extraData);

    /**
     * @brief 使能或者禁用输入设备
     * @param enable 输入设备的使能状态
     * @return 返回0表示接口调用成功，否则，表示接口调用失败。
     * @since 9
     */
    int32_t EnableInputDevice(bool enable);

     /**
     * @brief 自定义设置快捷键拉起ability延迟时间
     * @param businessId 应用在ability_launch_config.json中注册的唯一标识符.
     * @param delay 延迟时间 0-4000ms
     * @return 设置快捷键拉起ability延迟时间成功或失败
     * @since 10
     */
    int32_t SetKeyDownDuration(const std::string &businessId, int32_t delay);

    /**
     * @brief Sets the keyboard repeat delay, which ranges from 300 to 1000.
     * @param delay Indicates the keyboard repeat delay to set.
     * @return Returns <b>RET_OK</b> if success; returns <b>RET_ERR</b> otherwise.
     * @since 10
     */
    int32_t SetKeyboardRepeatDelay(int32_t delay);

    /**
     * @brief Sets the keyboard repeat rate, which ranges from 36 to 100.
     * @param rate Indicates the keyboard repeat rate to set.
     * @return Returns <b>RET_OK</b> if success; returns <b>RET_ERR</b> otherwise.
     * @since 10
     */
    int32_t SetKeyboardRepeatRate(int32_t rate);

    /**
     * @brief Gets the keyboard repeat delay.
     * @param callback Callback used to return the keyboard repeat delay.
     * @return Returns <b>RET_OK</b> if success; returns <b>RET_ERR</b> otherwise.
     * @since 10
     */
    int32_t GetKeyboardRepeatDelay(std::function<void(int32_t)> callback);

    /**
     * @brief Gets the keyboard repeat rate.
     * @param callback Callback used to return the keyboard repeat rate.
     * @return Returns <b>RET_OK</b> if success; returns <b>RET_ERR</b> otherwise.
     * @since 10
     */
    int32_t GetKeyboardRepeatRate(std::function<void(int32_t)> callback);

    /**
     * @brief Set the switch of touchpad scroll.
     * @param switchFlag Indicates the touchpad scroll switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadScrollSwitch(bool switchFlag);

    /**
     * @brief Get the switch of touchpad scroll.
     * @param switchFlag Indicates the touchpad scroll switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadScrollSwitch(bool &switchFlag);

    /**
     * @brief Set the switch of touchpad scroll direction.
     * @param state Indicates the touchpad scroll switch direction state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadScrollDirection(bool state);

    /**
     * @brief Get the switch of touchpad scroll direction.
     * @param state Indicates the touchpad scroll switch direction state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadScrollDirection(bool &state);

    /**
     * @brief Set the switch of touchpad tap.
     * @param switchFlag Indicates the touchpad tap switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadTapSwitch(bool switchFlag);

    /**
     * @brief Get the switch of touchpad tap.
     * @param switchFlag Indicates the touchpad tap switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadTapSwitch(bool &switchFlag);

    /**
     * @brief Set the touchpad poniter speed.
     * @param speed Indicates the touchpad pointer speed.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadPointerSpeed(int32_t speed);

    /**
     * @brief Get the touchpad poniter speed.
     * @param speed Indicates the touchpad pointer speed.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadPointerSpeed(int32_t &speed);

    /**
     * @brief Set the switch of touchpad pinch.
     * @param switchFlag Indicates the touchpad pinch switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadPinchSwitch(bool switchFlag);

    /**
     * @brief Get the switch of touchpad pinch.
     * @param switchFlag Indicates the touchpad pinch switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadPinchSwitch(bool &switchFlag);

    /**
     * @brief Set the switch of touchpad swipe.
     * @param switchFlag Indicates the touchpad swipe switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadSwipeSwitch(bool switchFlag);

    /**
     * @brief Get the switch of touchpad swipe.
     * @param switchFlag Indicates the touchpad swipe switch state.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadSwipeSwitch(bool &switchFlag);

    /**
     * @brief Set the touchpad right click type.
     * @param type Indicates the touchpad right menu type.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetTouchpadRightClickType(int32_t type);

    /**
     * @brief Get the touchpad right click type.
     * @param type Indicates the touchpad right menu type.
     * @return if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t GetTouchpadRightClickType(int32_t &type);
     /**
     * @brief SetWindowPointerStyle.
     * @param area Indicates area.
     * @param pid Indicates pid.
     * @param windowId Indicates windowId.
     * @return void.
     * @since 9
     */
    void SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId);

     /**
     * @brief Turn on or off hard cursor statistics.
     * @param frameCount Counting the frame rate of continuous mouse movement.
     * @param frameCount Statistics of mouse continuous movement synchronization frame rate.
     * @return if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t EnableHardwareCursorStats(bool enable);
    /**
     * @brief Get the mouse hard cursor information.
     * @param frameCount Counting the frame rate of continuous mouse movement.
     * @param frameCount Statistics of mouse continuous movement synchronization frame rate.
     * @return if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount);

    /**
     * @brief ClearWindowPointerStyle.
     * @param pid Indicates pid.
     * @param windowId Indicates windowId.
     * @return void.
     * @since 9
     */
    void ClearWindowPointerStyle(int32_t pid, int32_t windowId);

    /**
     * @brief Sets whether shield key event interception, only support shield key event.
     * @param shieldMode Indicates shield mode.
     * @param isShield Indicates whether key event handler chain is shield. The value <b>true</b> indicates that
     * the key event build chain is shield, all key events derictly dispatch to window,
     * if the value <b>false</b> indicates not shield key event interception, handle by the chain.
     * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
     * @since 9
     */
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield);

    /**
    * Gets shield event interception status corresponding to shield mode
    *
    * @param shieldMode - Accroding the shield mode select shield status.
    * @param isShield - shield status of shield mode param.
    * @return Returns <b>0</b> if success; returns a non-0 value otherwise.
    * @since 9
    */
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield);

    int32_t MarkProcessed(int32_t eventId, int64_t actionTime, bool enable = true);

    int32_t GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState);

    void Authorize(bool isAuthorize);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    /**
     * @brief Sets the enhance config of the security component.
     * @param cfg Indicates the security component enhance config.
     * @param cfgLen Indicates the security component enhance config len.
     * @return void.
     * @since 9
     */
    void SetEnhanceConfig(uint8_t *cfg, uint32_t cfgLen);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

#ifdef OHOS_BUILD_ENABLE_ANCO
    void SimulateInputEventExt(std::shared_ptr<KeyEvent> keyEvent);
    void SimulateInputEventExt(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_ANCO

    void AddServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher);
    void RemoveServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher);

    /**
     * @brief Set the switch of touchpad rotate.
     * @param rotateSwitch Indicates the touchpad rotate switch state.
     * @return 0 if success; returns a non-0 value otherwise.
     * @since 11
     */
    int32_t SetTouchpadRotateSwitch(bool rotateSwitch);

    /**
     * @brief Get the switch of touchpad rotate.
     * @param rotateSwitch Indicates the touchpad rotate switch state.
     * @return 0 if success; returns a non-0 value otherwise.
     * @since 11
     */
    int32_t GetTouchpadRotateSwitch(bool &rotateSwitch);

    /**
     * @brief Get whether System has IrEmitter.
     * @param hasIrEmitter the para takes the value which Indicates the device has IrEmitter or not.
     * @return 0 if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t HasIrEmitter(bool &hasIrEmitter);

    /**
     * @brief Get InfraredFrequency of the IrEmitter in device.
     * @param requencys take out the IrEmitter's Frequency.
     * @return 0 if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys);

    /**
     * @brief user IrEmitter with parameter number and pattern.
     * @param number   Frequency of IrEmitter works .
     * @param pattern Pattern of signal transmission in alternate on/off mode, in microseconds.
     * @return 0 if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t TransmitInfrared(int64_t number, std::vector<int64_t>& pattern);

    int32_t SetCurrentUser(int32_t userId);
    
    /**
     * @brief Set the switch of touchpad three finger tap.
     * @param switchFlag Indicates the touchpad three finger tap switch state.
     *  true: user can use three finger function. otherwise can't use
     * @return if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t SetTouchpadThreeFingersTapSwitch(bool switchFlag);

    /**
     * @brief Get the switch of touchpad three finger tap.
     * @param switchFlag Indicates the touchpad three finger tap switch state.
     * true: user can use three finger function. otherwise can't use
     * @return if success; returns a non-0 value otherwise.
     * @since 12
     */
    int32_t GetTouchpadThreeFingersTapSwitch(bool &switchFlag);
    
    int32_t GetWinSyncBatchSize(int32_t maxAreasCount, int32_t displayCount);
    
    /**
     * @brief 添加虚拟输入设备
     * @param device 输入设备信息
     * @param deviceId 出参，所创建的虚拟输入设备对应的设备Id
     * @return 返回0表示接口调用成功，否则，表示接口调用失败。
     * @since 12
     */
    int32_t AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId);

    /**
     * @brief 移除虚拟输入设备
     * @param deviceId 要移除的虚拟输入设备对应的设备Id
     * @return 返回0表示接口调用成功，否则，表示接口调用失败。
     * @since 12
     */
    int32_t RemoveVirtualInputDevice(int32_t deviceId);

    int32_t AncoAddConsumer(std::shared_ptr<IAncoConsumer> consumer);
    int32_t AncoRemoveConsumer(std::shared_ptr<IAncoConsumer> consumer);

private:
    InputManager() = default;
    DISALLOW_COPY_AND_MOVE(InputManager);
    static InputManager *instance_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MANAGER_H
