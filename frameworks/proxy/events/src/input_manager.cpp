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

#include "input_manager.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_handler_type.h"
#include "input_manager_impl.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManager"

namespace OHOS {
namespace MMI {
InputManager *InputManager::instance_ = new (std::nothrow) InputManager();
InputManager *InputManager::GetInstance()
{
    return instance_;
}

int32_t InputManager::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    return InputMgrImpl.GetDisplayBindInfo(infos);
}

int32_t InputManager::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas)
{
    return InputMgrImpl.GetAllMmiSubscribedEvents(datas);
}

int32_t InputManager::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    return InputMgrImpl.SetDisplayBind(deviceId, displayId, msg);
}

int32_t InputManager::GetWindowPid(int32_t windowId)
{
    return InputMgrImpl.GetWindowPid(windowId);
}

int32_t InputManager::UpdateDisplayInfo(const DisplayGroupInfo &displayGroupInfo)
{
    return InputMgrImpl.UpdateDisplayInfo(displayGroupInfo);
}

int32_t InputManager::UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo)
{
    return InputMgrImpl.UpdateWindowInfo(windowGroupInfo);
}

int32_t InputManager::AddInputEventFilter(std::shared_ptr<IInputEventFilter> filter, int32_t priority,
    uint32_t deviceTags)
{
    return InputMgrImpl.AddInputEventFilter(filter, priority, deviceTags);
}

int32_t InputManager::RemoveInputEventFilter(int32_t filterId)
{
    return InputMgrImpl.RemoveInputEventFilter(filterId);
}

int32_t InputManager::AddInputEventObserver(std::shared_ptr<MMIEventObserver> observer)
{
    return InputMgrImpl.AddInputEventObserver(observer);
}

int32_t InputManager::RemoveInputEventObserver(std::shared_ptr<MMIEventObserver> observer)
{
    return InputMgrImpl.RemoveInputEventObserver(observer);
}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer)
{
    InputMgrImpl.SetWindowInputEventConsumer(inputEventConsumer, nullptr);
}

void InputManager::SetWindowInputEventConsumer(std::shared_ptr<IInputEventConsumer> inputEventConsumer,
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler)
{
    CHKPV(eventHandler);
    InputMgrImpl.SetWindowInputEventConsumer(inputEventConsumer, eventHandler);
}

int32_t InputManager::SubscribeKeyEvent(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    return InputMgrImpl.SubscribeKeyEvent(keyOption, callback);
}

void InputManager::UnsubscribeKeyEvent(int32_t subscriberId)
{
    InputMgrImpl.UnsubscribeKeyEvent(subscriberId);
}

int32_t InputManager::SubscribeSwitchEvent(std::function<void(std::shared_ptr<SwitchEvent>)> callback,
    SwitchEvent::SwitchType switchType)
{
    return InputMgrImpl.SubscribeSwitchEvent(static_cast<int32_t>(switchType), callback);
}

void InputManager::UnsubscribeSwitchEvent(int32_t subscriberId)
{
    InputMgrImpl.UnsubscribeSwitchEvent(subscriberId);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor)
{
    return InputMgrImpl.AddMonitor(monitor);
}

int32_t InputManager::AddMonitor(std::function<void(std::shared_ptr<PointerEvent>)> monitor)
{
    return InputMgrImpl.AddMonitor(monitor);
}

int32_t InputManager::AddMonitor(std::shared_ptr<IInputEventConsumer> monitor, HandleEventType eventType)
{
    return InputMgrImpl.AddMonitor(monitor, eventType);
}

void InputManager::RemoveMonitor(int32_t monitorId)
{
    InputMgrImpl.RemoveMonitor(monitorId);
}

void InputManager::MarkConsumed(int32_t monitorId, int32_t eventId)
{
    InputMgrImpl.MarkConsumed(monitorId, eventId);
}

void InputManager::MoveMouse(int32_t offsetX, int32_t offsetY)
{
    InputMgrImpl.MoveMouse(offsetX, offsetY);
}

int32_t InputManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    return InputMgrImpl.AddInterceptor(interceptor);
}

int32_t InputManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    return InputMgrImpl.AddInterceptor(interceptor);
}

int32_t InputManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor, int32_t priority,
    uint32_t deviceTags)
{
    return InputMgrImpl.AddInterceptor(interceptor, priority, deviceTags);
}

void InputManager::RemoveInterceptor(int32_t interceptorId)
{
    InputMgrImpl.RemoveInterceptor(interceptorId);
}

void InputManager::SimulateInputEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    InputMgrImpl.SimulateInputEvent(keyEvent);
}

void InputManager::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    InputMgrImpl.SimulateInputEvent(pointerEvent);
}

void InputManager::SimulateInputEvent(std::shared_ptr<PointerEvent> pointerEvent, float zOrder)
{
    CHKPV(pointerEvent);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);
    pointerEvent->SetZOrder(zOrder);
    InputMgrImpl.SimulateInputEvent(pointerEvent);
}

int32_t InputManager::RegisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener)
{
    return InputMgrImpl.RegisterDevListener(type, listener);
}

int32_t InputManager::UnregisterDevListener(std::string type, std::shared_ptr<IInputDeviceListener> listener)
{
    return InputMgrImpl.UnregisterDevListener(type, listener);
}

int32_t InputManager::GetDeviceIds(std::function<void(std::vector<int32_t>&)> callback)
{
    return InputMgrImpl.GetDeviceIds(callback);
}

int32_t InputManager::GetDevice(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    return InputMgrImpl.GetDevice(deviceId, callback);
}

int32_t InputManager::SupportKeys(int32_t deviceId, std::vector<int32_t> keyCodes,
    std::function<void(std::vector<bool>&)> callback)
{
    return InputMgrImpl.SupportKeys(deviceId, keyCodes, callback);
}

int32_t InputManager::SetMouseScrollRows(int32_t Rows)
{
    return InputMgrImpl.SetMouseScrollRows(Rows);
}

int32_t InputManager::GetMouseScrollRows(int32_t &Rows)
{
    return InputMgrImpl.GetMouseScrollRows(Rows);
}

int32_t InputManager::SetCustomCursor(int32_t windowId, void* pixelMap, int32_t focusX, int32_t focusY)
{
    return InputMgrImpl.SetCustomCursor(windowId, focusX, focusY, pixelMap);
}

int32_t InputManager::SetMouseIcon(int32_t windowId, void* pixelMap)
{
    return InputMgrImpl.SetMouseIcon(windowId, pixelMap);
}

int32_t InputManager::SetPointerSize(int32_t size)
{
    return InputMgrImpl.SetPointerSize(size);
}

int32_t InputManager::GetPointerSize(int32_t &size)
{
    return InputMgrImpl.GetPointerSize(size);
}

int32_t InputManager::SetMouseHotSpot(int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    return InputMgrImpl.SetMouseHotSpot(windowId, hotSpotX, hotSpotY);
}

int32_t InputManager::SetMousePrimaryButton(int32_t primaryButton)
{
    return InputMgrImpl.SetMousePrimaryButton(primaryButton);
}

int32_t InputManager::GetMousePrimaryButton(int32_t &primaryButton)
{
    return InputMgrImpl.GetMousePrimaryButton(primaryButton);
}

int32_t InputManager::SetHoverScrollState(bool state)
{
    return InputMgrImpl.SetHoverScrollState(state);
}

int32_t InputManager::GetHoverScrollState(bool &state)
{
    return InputMgrImpl.GetHoverScrollState(state);
}

int32_t InputManager::SetPointerVisible(bool visible, int32_t priority)
{
    return InputMgrImpl.SetPointerVisible(visible, priority);
}

bool InputManager::IsPointerVisible()
{
    return InputMgrImpl.IsPointerVisible();
}

int32_t InputManager::SetPointerColor(int32_t color)
{
    return InputMgrImpl.SetPointerColor(color);
}

int32_t InputManager::GetPointerColor(int32_t &color)
{
    return InputMgrImpl.GetPointerColor(color);
}

int32_t InputManager::EnableCombineKey(bool enable)
{
    return InputMgrImpl.EnableCombineKey(enable);
}

int32_t InputManager::SetPointerSpeed(int32_t speed)
{
    return InputMgrImpl.SetPointerSpeed(speed);
}

int32_t InputManager::GetPointerSpeed(int32_t &speed)
{
    return InputMgrImpl.GetPointerSpeed(speed);
}

int32_t InputManager::GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> callback)
{
    return InputMgrImpl.GetKeyboardType(deviceId, callback);
}

void InputManager::SetAnrObserver(std::shared_ptr<IAnrObserver> observer)
{
    InputMgrImpl.SetAnrObserver(observer);
}

int32_t InputManager::SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    return InputMgrImpl.SetPointerStyle(windowId, pointerStyle, isUiExtension);
}

int32_t InputManager::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    return InputMgrImpl.GetPointerStyle(windowId, pointerStyle, isUiExtension);
}

bool InputManager::GetFunctionKeyState(int32_t funcKey)
{
    return InputMgrImpl.GetFunctionKeyState(funcKey);
}

int32_t InputManager::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    return InputMgrImpl.SetFunctionKeyState(funcKey, enable);
}

int32_t InputManager::SetPointerLocation(int32_t x, int32_t y)
{
    return InputMgrImpl.SetPointerLocation(x, y);
}

int32_t InputManager::EnterCaptureMode(int32_t windowId)
{
    return InputMgrImpl.EnterCaptureMode(windowId);
}

int32_t InputManager::LeaveCaptureMode(int32_t windowId)
{
    return InputMgrImpl.LeaveCaptureMode(windowId);
}

void InputManager::AppendExtraData(const ExtraData& extraData)
{
    InputMgrImpl.AppendExtraData(extraData);
}

int32_t InputManager::EnableInputDevice(bool enable)
{
    return InputMgrImpl.EnableInputDevice(enable);
}

int32_t InputManager::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    return InputMgrImpl.AddVirtualInputDevice(device, deviceId);
}

int32_t InputManager::RemoveVirtualInputDevice(int32_t deviceId)
{
    return InputMgrImpl.RemoveVirtualInputDevice(deviceId);
}

int32_t InputManager::SetKeyDownDuration(const std::string& businessId, int32_t delay)
{
    return InputMgrImpl.SetKeyDownDuration(businessId, delay);
}

int32_t InputManager::SetKeyboardRepeatDelay(int32_t delay)
{
    return InputMgrImpl.SetKeyboardRepeatDelay(delay);
}

int32_t InputManager::SetKeyboardRepeatRate(int32_t rate)
{
    return InputMgrImpl.SetKeyboardRepeatRate(rate);
}

int32_t InputManager::GetKeyboardRepeatDelay(std::function<void(int32_t)> callback)
{
    return InputMgrImpl.GetKeyboardRepeatDelay(callback);
}

int32_t InputManager::GetKeyboardRepeatRate(std::function<void(int32_t)> callback)
{
    return InputMgrImpl.GetKeyboardRepeatRate(callback);
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
void InputManager::SetEnhanceConfig(uint8_t *cfg, uint32_t cfgLen)
{
    InputMgrImpl.SetEnhanceConfig(cfg, cfgLen);
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

int32_t InputManager::SetTouchpadScrollSwitch(bool switchFlag)
{
    return InputMgrImpl.SetTouchpadScrollSwitch(switchFlag);
}

int32_t InputManager::GetTouchpadScrollSwitch(bool &switchFlag)
{
    return InputMgrImpl.GetTouchpadScrollSwitch(switchFlag);
}
int32_t InputManager::SetTouchpadScrollDirection(bool state)
{
    return InputMgrImpl.SetTouchpadScrollDirection(state);
}

int32_t InputManager::GetTouchpadScrollDirection(bool &state)
{
    return InputMgrImpl.GetTouchpadScrollDirection(state);
}
int32_t InputManager::SetTouchpadTapSwitch(bool switchFlag)
{
    return InputMgrImpl.SetTouchpadTapSwitch(switchFlag);
}

int32_t InputManager::GetTouchpadTapSwitch(bool &switchFlag)
{
    return InputMgrImpl.GetTouchpadTapSwitch(switchFlag);
}

int32_t InputManager::SetTouchpadPointerSpeed(int32_t speed)
{
    return InputMgrImpl.SetTouchpadPointerSpeed(speed);
}

int32_t InputManager::GetTouchpadPointerSpeed(int32_t &speed)
{
    return InputMgrImpl.GetTouchpadPointerSpeed(speed);
}

int32_t InputManager::SetTouchpadPinchSwitch(bool switchFlag)
{
    return InputMgrImpl.SetTouchpadPinchSwitch(switchFlag);
}

int32_t InputManager::GetTouchpadPinchSwitch(bool &switchFlag)
{
    return InputMgrImpl.GetTouchpadPinchSwitch(switchFlag);
}

int32_t InputManager::SetTouchpadSwipeSwitch(bool switchFlag)
{
    return InputMgrImpl.SetTouchpadSwipeSwitch(switchFlag);
}

int32_t InputManager::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    return InputMgrImpl.GetTouchpadSwipeSwitch(switchFlag);
}

int32_t InputManager::SetTouchpadRightClickType(int32_t type)
{
    return InputMgrImpl.SetTouchpadRightClickType(type);
}

int32_t InputManager::GetTouchpadRightClickType(int32_t &type)
{
    return InputMgrImpl.GetTouchpadRightClickType(type);
}

int32_t InputManager::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    return InputMgrImpl.SetTouchpadRotateSwitch(rotateSwitch);
}

int32_t InputManager::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    return InputMgrImpl.GetTouchpadRotateSwitch(rotateSwitch);
}

int32_t InputManager::EnableHardwareCursorStats(bool enable)
{
    return InputMgrImpl.EnableHardwareCursorStats(enable);
}

int32_t InputManager::GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    return InputMgrImpl.GetHardwareCursorStats(frameCount, vsyncCount);
}

int32_t InputManager::GetPointerSnapshot(void *pixelMapPtr)
{
    return InputMgrImpl.GetPointerSnapshot(pixelMapPtr);
}

int32_t InputManager::SetTouchpadScrollRows(int32_t rows)
{
    return InputMgrImpl.SetTouchpadScrollRows(rows);
}

int32_t InputManager::GetTouchpadScrollRows(int32_t &rows)
{
    return InputMgrImpl.GetTouchpadScrollRows(rows);
}

void InputManager::SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId)
{
    InputMgrImpl.SetWindowPointerStyle(area, pid, windowId);
}

void InputManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    InputMgrImpl.ClearWindowPointerStyle(pid, windowId);
}

void InputManager::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    InputMgrImpl.SetNapStatus(pid, uid, bundleName, napStatus);
}

int32_t InputManager::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    return InputMgrImpl.SetShieldStatus(shieldMode, isShield);
}

int32_t InputManager::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    return InputMgrImpl.GetShieldStatus(shieldMode, isShield);
}

void InputManager::AddServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    InputMgrImpl.AddServiceWatcher(watcher);
}

void InputManager::RemoveServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    InputMgrImpl.RemoveServiceWatcher(watcher);
}

int32_t InputManager::MarkProcessed(int32_t eventId, int64_t actionTime, bool enable)
{
    LogTracer lt(eventId, 0, 0);
    if (enable) {
        return InputMgrImpl.MarkProcessed(eventId, actionTime);
    }
    MMI_HILOGD("Skip MarkProcessed eventId:%{public}d", eventId);
    return RET_OK;
}

int32_t InputManager::GetKeyState(std::vector<int32_t> &pressedKeys, std::map<int32_t, int32_t> &specialKeysState)
{
    return InputMgrImpl.GetKeyState(pressedKeys, specialKeysState);
}

void InputManager::Authorize(bool isAuthorize)
{
    InputMgrImpl.Authorize(isAuthorize);
}

int32_t InputManager::HasIrEmitter(bool &hasIrEmitter)
{
    return InputMgrImpl.HasIrEmitter(hasIrEmitter);
}

int32_t InputManager::GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys)
{
    return InputMgrImpl.GetInfraredFrequencies(requencys);
}

int32_t InputManager::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    return InputMgrImpl.TransmitInfrared(number, pattern);
}

int32_t InputManager::SetCurrentUser(int32_t userId)
{
    return InputMgrImpl.SetCurrentUser(userId);
}

int32_t InputManager::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    return InputMgrImpl.SetTouchpadThreeFingersTapSwitch(switchFlag);
}

int32_t InputManager::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
{
    return InputMgrImpl.GetTouchpadThreeFingersTapSwitch(switchFlag);
}

int32_t InputManager::GetWinSyncBatchSize(int32_t maxAreasCount, int32_t displayCount)
{
    return InputMgrImpl.GetWinSyncBatchSize(maxAreasCount, displayCount);
}

int32_t InputManager::AncoAddConsumer(std::shared_ptr<IAncoConsumer> consumer)
{
    return InputMgrImpl.AncoAddChannel(consumer);
}

int32_t InputManager::AncoRemoveConsumer(std::shared_ptr<IAncoConsumer> consumer)
{
    return InputMgrImpl.AncoRemoveChannel(consumer);
}
} // namespace MMI
} // namespace OHOS
