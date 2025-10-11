/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "multimodal_input_connect_manager.h"


#include "iservice_registry.h"

#include "input_binder_client_server.h"
#include "multimodal_input_connect_death_recipient.h"
#include "pixel_map.h"
#include "mmi_event_map.h"
#include "mmi_log.h"
#include "error_multimodal.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputConnectManager"

namespace OHOS {
namespace MMI {
namespace {
std::shared_ptr<MultimodalInputConnectManager> g_instance = nullptr;
} // namespace

std::shared_ptr<MultimodalInputConnectManager> MultimodalInputConnectManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() { g_instance.reset(new (std::nothrow) MultimodalInputConnectManager()); });

    CHKPP(g_instance);
    if (g_instance != nullptr) {
        g_instance->ConnectMultimodalInputService();
    }
    return g_instance;
}

int32_t MultimodalInputConnectManager::AllocSocketPair(const int32_t moduleType)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    const std::string programName(GetProgramName());
    int32_t result = multimodalInputConnectService_->AllocSocketFd(programName, moduleType, socketFd_, tokenType_);
    if (result != RET_OK) {
        MMI_HILOGE("AllocSocketFd has error:%{public}d", result);
        return RET_ERR;
    }
    MMI_HILOGD("AllocSocketPair success. socketFd_:%{public}d tokenType_:%{public}d", socketFd_, tokenType_);
    return RET_OK;
}

int32_t MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair() const
{
    CALL_DEBUG_ENTER;
    return socketFd_;
}

int32_t MultimodalInputConnectManager::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    infos.clear();
    int32_t ret = multimodalInputConnectService_->GetDisplayBindInfo(infos);
    return ret;
}

int32_t MultimodalInputConnectManager::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>,
    int32_t> &datas)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    struct MmiEventMap mmiEventMap;
    auto ret = multimodalInputConnectService_->GetAllMmiSubscribedEvents(mmiEventMap);
    datas.clear();
    datas = std::move(mmiEventMap.datas);
    return ret;
}

int32_t MultimodalInputConnectManager::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetDisplayBind(deviceId, displayId, msg);
}

int32_t MultimodalInputConnectManager::GetWindowPid(int32_t windowId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    int32_t windowPid = INVALID_PID;
    multimodalInputConnectService_->GetWindowPid(windowId, windowPid);
    return windowPid;
}

int32_t MultimodalInputConnectManager::AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId,
    int32_t priority, uint32_t deviceTags)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddInputEventFilter(filter, filterId, priority, deviceTags);
}

int32_t MultimodalInputConnectManager::NotifyNapOnline()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->NotifyNapOnline();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::RemoveInputEventObserver()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveInputEventObserver();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::RemoveInputEventFilter(int32_t filterId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveInputEventFilter(filterId);
}

int32_t MultimodalInputConnectManager::SetMouseScrollRows(int32_t rows)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseScrollRows(rows);
}

int32_t MultimodalInputConnectManager::SetCustomCursor(int32_t windowId, int32_t focusX, int32_t focusY,
    void* pixelMap)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    CursorPixelMap curPixelMap {};
    curPixelMap.pixelMap = pixelMap;
    return multimodalInputConnectService_->SetCustomCursorPixelMap(windowId, focusX, focusY, curPixelMap);
}

int32_t MultimodalInputConnectManager::SetMouseIcon(int32_t windowId, void* pixelMap)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    CursorPixelMap curPixelMap {};
    curPixelMap.pixelMap = pixelMap;
    return multimodalInputConnectService_->SetMouseIcon(windowId, curPixelMap);
}

int32_t MultimodalInputConnectManager::SetMouseHotSpot(
    int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
}

int32_t MultimodalInputConnectManager::GetMouseScrollRows(int32_t &rows)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetMouseScrollRows(rows);
}

int32_t MultimodalInputConnectManager::SetPointerSize(int32_t size)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerSize(size);
}

int32_t MultimodalInputConnectManager::SetNapStatus(int32_t pid, int32_t uid,
    const std::string &bundleName, int32_t napStatus)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetNapStatus(pid, uid, bundleName, napStatus);
}

int32_t MultimodalInputConnectManager::GetPointerSize(int32_t &size)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerSize(size);
}

int32_t MultimodalInputConnectManager::GetCursorSurfaceId(uint64_t &surfaceId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetCursorSurfaceId(surfaceId);
}

int32_t MultimodalInputConnectManager::SetMousePrimaryButton(int32_t primaryButton)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMousePrimaryButton(primaryButton);
}

int32_t MultimodalInputConnectManager::GetMousePrimaryButton(int32_t &primaryButton)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetMousePrimaryButton(primaryButton);
}

int32_t MultimodalInputConnectManager::SetHoverScrollState(bool state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetHoverScrollState(state);
}

int32_t MultimodalInputConnectManager::GetHoverScrollState(bool &state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetHoverScrollState(state);
}

int32_t MultimodalInputConnectManager::SetPointerVisible(bool visible, int32_t priority)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerVisible(visible, priority);
}

int32_t MultimodalInputConnectManager::IsPointerVisible(bool &visible)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->IsPointerVisible(visible);
}

int32_t MultimodalInputConnectManager::MarkProcessed(int32_t eventType, int32_t eventId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MarkProcessed(eventType, eventId);
}

int32_t MultimodalInputConnectManager::SetPointerColor(int32_t color)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerColor(color);
}

int32_t MultimodalInputConnectManager::GetPointerColor(int32_t &color)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerColor(color);
}

int32_t MultimodalInputConnectManager::SetPointerSpeed(int32_t speed)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::GetPointerSpeed(int32_t &speed)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerStyle(windowId, pointerStyle, isUiExtension);
}

int32_t MultimodalInputConnectManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->ClearWindowPointerStyle(pid, windowId);
}

int32_t MultimodalInputConnectManager::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerStyle(windowId, pointerStyle, isUiExtension);
}

int32_t MultimodalInputConnectManager::RegisterDevListener()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RegisterDevListener();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::UnregisterDevListener()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnregisterDevListener();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::SupportKeys(int32_t deviceId, std::vector<int32_t> &keys,
    std::vector<bool> &keystroke)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SupportKeys(deviceId, keys, keystroke);
}

int32_t MultimodalInputConnectManager::GetDeviceIds(std::vector<int32_t> &ids)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetDeviceIds(ids);
}

int32_t MultimodalInputConnectManager::GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    InputDevice device = {};
    auto ret = multimodalInputConnectService_->GetDevice(deviceId, device);
    if (ret == RET_OK) {
        inputDevice = std::make_shared<InputDevice>(device);
        CHKPR(inputDevice, ERROR_NULL_POINTER);
    }
    return ret;
}

int32_t MultimodalInputConnectManager::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetKeyboardType(deviceId, keyboardType);
}

int32_t MultimodalInputConnectManager::SetKeyboardRepeatDelay(int32_t delay)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKeyboardRepeatDelay(delay);
}

int32_t MultimodalInputConnectManager::SetKeyboardRepeatRate(int32_t rate)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKeyboardRepeatRate(rate);
}

int32_t MultimodalInputConnectManager::GetKeyboardRepeatDelay(int32_t &delay)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetKeyboardRepeatDelay(delay);
}

int32_t MultimodalInputConnectManager::GetKeyboardRepeatRate(int32_t &rate)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetKeyboardRepeatRate(rate);
}

int32_t MultimodalInputConnectManager::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddInputHandler(handlerType, eventType, priority, deviceTags, actionsType);
}

int32_t MultimodalInputConnectManager::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags, std::vector<int32_t> actionsType)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveInputHandler(handlerType, eventType, priority, deviceTags,
        actionsType);
}

int32_t MultimodalInputConnectManager::AddPreInputHandler(int32_t handlerId, HandleEventType eventType,
    std::vector<int32_t> keys)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddPreInputHandler(handlerId, eventType, keys);
}

int32_t MultimodalInputConnectManager::RemovePreInputHandler(int32_t handlerId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemovePreInputHandler(handlerId);
}

int32_t MultimodalInputConnectManager::AddGestureMonitor(InputHandlerType handlerType,
    HandleEventType eventType, TouchGestureType gestureType, int32_t fingers)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddGestureMonitor(handlerType, eventType, gestureType, fingers);
}

int32_t MultimodalInputConnectManager::RemoveGestureMonitor(InputHandlerType handlerType,
    HandleEventType eventType, TouchGestureType gestureType, int32_t fingers)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveGestureMonitor(handlerType, eventType, gestureType, fingers);
}

int32_t MultimodalInputConnectManager::MarkEventConsumed(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MarkEventConsumed(eventId);
}

int32_t MultimodalInputConnectManager::SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(option, ERR_INVALID_VALUE);
    return multimodalInputConnectService_->SubscribeKeyEvent(subscribeId, *option);
}

int32_t MultimodalInputConnectManager::UnsubscribeKeyEvent(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeKeyEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::SubscribeHotkey(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(option, ERR_INVALID_VALUE);
    return multimodalInputConnectService_->SubscribeHotkey(subscribeId, *option);
}

int32_t MultimodalInputConnectManager::UnsubscribeHotkey(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeHotkey(subscribeId);
}

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
int32_t MultimodalInputConnectManager::SubscribeKeyMonitor(const KeyMonitorOption &keyOption)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeKeyMonitor(keyOption);
}

int32_t MultimodalInputConnectManager::UnsubscribeKeyMonitor(const KeyMonitorOption &keyOption)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeKeyMonitor(keyOption);
}
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER

int32_t MultimodalInputConnectManager::SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeSwitchEvent(subscribeId, switchType);
}

int32_t MultimodalInputConnectManager::UnsubscribeSwitchEvent(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeSwitchEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::QuerySwitchStatus(int32_t switchType, int32_t& state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->QuerySwitchStatus(switchType, state);
}

int32_t MultimodalInputConnectManager::SubscribeTabletProximity(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeTabletProximity(subscribeId);
}

int32_t MultimodalInputConnectManager::UnsubscribetabletProximity(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribetabletProximity(subscribeId);
}

int32_t MultimodalInputConnectManager::SubscribeLongPressEvent(int32_t subscribeId,
    const LongPressRequest &longPressRequest)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeLongPressEvent(subscribeId, longPressRequest);
}
 
int32_t MultimodalInputConnectManager::UnsubscribeLongPressEvent(int32_t subscribeId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeLongPressEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MoveMouseEvent(offsetX, offsetY);
}

int32_t MultimodalInputConnectManager::InjectKeyEvent(const std::shared_ptr<KeyEvent> event, bool isNativeInject)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(event, ERR_INVALID_VALUE);
    return multimodalInputConnectService_->InjectKeyEvent(*event, isNativeInject);
}

int32_t MultimodalInputConnectManager::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent,
    bool isNativeInject, int32_t useCoordinate)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(pointerEvent, ERR_INVALID_VALUE);
    return multimodalInputConnectService_->InjectPointerEvent(*pointerEvent, isNativeInject, useCoordinate);
}

int32_t MultimodalInputConnectManager::InjectTouchPadEvent(std::shared_ptr<PointerEvent> pointerEvent,
    const TouchpadCDG &touchpadCDG, bool isNativeInject)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(pointerEvent, ERR_INVALID_VALUE);
    return multimodalInputConnectService_->InjectTouchPadEvent(*pointerEvent.get(), touchpadCDG, isNativeInject);
}

int32_t MultimodalInputConnectManager::SetAnrObserver()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetAnrObserver();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::GetFunctionKeyState(int32_t funcKey, bool &state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetFunctionKeyState(funcKey, state);
}

int32_t MultimodalInputConnectManager::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetFunctionKeyState(funcKey, enable);
}

int32_t MultimodalInputConnectManager::SetPointerLocation(int32_t x, int32_t y, int32_t displayId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerLocation(x, y, displayId);
}

int32_t MultimodalInputConnectManager::GetPointerLocation(int32_t &displayId, double &displayX, double &displayY)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerLocation(displayId, displayX, displayY);
}

bool MultimodalInputConnectManager::ConnectMultimodalInputService() __attribute__((no_sanitize("cfi")))
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        return true;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPF(sm);
    auto sa = sm->CheckSystemAbility(MultimodalInputConnectManager::MULTIMODAL_INPUT_CONNECT_SERVICE_ID);
    CHKPF(sa);

    std::weak_ptr<MultimodalInputConnectManager> weakPtr = shared_from_this();
    auto deathCallback = [weakPtr](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr != nullptr) {
            sharedPtr->OnDeath(object);
        }
    };

    multimodalInputConnectRecipient_ = new (std::nothrow) MultimodalInputConnectDeathRecipient(deathCallback);
    CHKPF(multimodalInputConnectRecipient_);
    if (!sa->AddDeathRecipient(multimodalInputConnectRecipient_)) {
        MMI_HILOGE("Failed to add death recipient");
        return false;
    }
    multimodalInputConnectService_ = iface_cast<IMultimodalInputConnect>(sa);
    CHKPF(multimodalInputConnectService_);
    sptr<IRemoteObject> remoteObject = INPUT_BINDER_CLIENT_SERVICE->GetClientSrv();
    CHKPF(remoteObject);
    multimodalInputConnectService_->TransferBinderClientSrv(remoteObject);
    MMI_HILOGD("Get multimodalinput service successful");
    return true;
}

void MultimodalInputConnectManager::OnDeath(const wptr<IRemoteObject> &remoteObj)
{
    CALL_DEBUG_ENTER;
    Clean(remoteObj);
    NotifyServiceDeath();
    NotifyDeath();
}

void MultimodalInputConnectManager::Clean(const wptr<IRemoteObject> &remoteObj)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        auto serviceObj = multimodalInputConnectService_->AsObject();
        if (serviceObj != nullptr) {
            if (serviceObj != remoteObj.promote()) {
                return;
            }
            if (multimodalInputConnectRecipient_ != nullptr) {
                MMI_HILOGI("Remove death recipient on service death");
                serviceObj->RemoveDeathRecipient(multimodalInputConnectRecipient_);
            }
        }
        MMI_HILOGI("Reset proxy on service death");
        multimodalInputConnectRecipient_ = nullptr;
        multimodalInputConnectService_ = nullptr;
    }
}

void MultimodalInputConnectManager::NotifyServiceDeath()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    for (const auto &watcher : watchers_) {
        watcher->OnServiceDied();
    }
    // LCOV_EXCL_STOP
}

void MultimodalInputConnectManager::NotifyDeath()
{
    // LCOV_EXCL_START
    CALL_DEBUG_ENTER;
    int32_t retryCount = 50;
    do {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (ConnectMultimodalInputService()) {
            MMI_HILOGD("Connect multimodalinput service successful");
            return;
        }
    } while (--retryCount > 0);
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseCaptureMode(windowId, isCaptureMode);
}

int32_t MultimodalInputConnectManager::AppendExtraData(const ExtraData &extraData)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AppendExtraData(extraData);
}

int32_t MultimodalInputConnectManager::EnableCombineKey(bool enable)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->EnableCombineKey(enable);
}

int32_t MultimodalInputConnectManager::EnableInputDevice(bool enable)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->EnableInputDevice(enable);
}

int32_t MultimodalInputConnectManager::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKeyDownDuration(businessId, delay);
}

int32_t MultimodalInputConnectManager::SetTouchpadScrollSwitch(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadScrollSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadScrollSwitch(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadScrollSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadScrollDirection(bool state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadScrollDirection(state);
}

int32_t MultimodalInputConnectManager::GetTouchpadScrollDirection(bool &state)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadScrollDirection(state);
}

int32_t MultimodalInputConnectManager::SetTouchpadTapSwitch(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadTapSwitch(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadPointerSpeed(int32_t speed)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::GetTouchpadPointerSpeed(int32_t &speed)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::GetTouchpadCDG(TouchpadCDG &touchpadCDG)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadCDG(touchpadCDG);
}

int32_t MultimodalInputConnectManager::SetTouchpadPinchSwitch(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadPinchSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadPinchSwitch(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadPinchSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadSwipeSwitch(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadSwipeSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadSwipeSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadRightClickType(int32_t type)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadRightClickType(type);
}

int32_t MultimodalInputConnectManager::GetTouchpadRightClickType(int32_t &type)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadRightClickType(type);
}

int32_t MultimodalInputConnectManager::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadRotateSwitch(rotateSwitch);
}

int32_t MultimodalInputConnectManager::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadRotateSwitch(rotateSwitch);
}

int32_t MultimodalInputConnectManager::SetTouchpadDoubleTapAndDragState(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadDoubleTapAndDragState(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadDoubleTapAndDragState(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadDoubleTapAndDragState(switchFlag);
}

int32_t MultimodalInputConnectManager::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetShieldStatus(shieldMode, isShield);
}

int32_t MultimodalInputConnectManager::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetShieldStatus(shieldMode, isShield);
}

int32_t MultimodalInputConnectManager::GetKeyState(std::vector<int32_t> &pressedKeys,
    std::map<int32_t, int32_t> &specialKeysState)
{
    std::lock_guard<std::mutex> guard(lock_);
    std::unordered_map<int32_t, int32_t> unorderedSpecialKeysState;
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    auto ret = multimodalInputConnectService_->GetKeyState(pressedKeys, unorderedSpecialKeysState);
    specialKeysState.clear();
    for (const auto& [key, value] : unorderedSpecialKeysState) {
        specialKeysState[key] = value;
    }
    return ret;
}

void MultimodalInputConnectManager::AddServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    CHKPV(watcher);
    std::lock_guard<std::mutex> guard(lock_);
    watchers_.insert(watcher);
}

void MultimodalInputConnectManager::RemoveServiceWatcher(std::shared_ptr<IInputServiceWatcher> watcher)
{
    std::lock_guard<std::mutex> guard(lock_);
    watchers_.erase(watcher);
}

int32_t MultimodalInputConnectManager::Authorize(bool isAuthorize)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->Authorize(isAuthorize);
}

int32_t MultimodalInputConnectManager::CancelInjection()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->CancelInjection();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::RequestInjection(int32_t &status, int32_t &reqId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RequestInjection(status, reqId);
}

int32_t MultimodalInputConnectManager::QueryAuthorizedStatus(int32_t &status)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->QueryAuthorizedStatus(status);
}

int32_t MultimodalInputConnectManager::HasIrEmitter(bool &hasIrEmitter)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->HasIrEmitter(hasIrEmitter);
}

int32_t MultimodalInputConnectManager::GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    std::vector<InfraredFrequency> infos = {};
    auto ret = multimodalInputConnectService_->GetInfraredFrequencies(infos);
    if (infos.size() < 0) {
        MMI_HILOGE("GetInfraredFrequencies failed");
        return RET_ERR;
    }
    for (auto& info : infos) {
        requencys.push_back(info);
    }
    return ret;
}

int32_t MultimodalInputConnectManager::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->TransmitInfrared(number, pattern);
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
int32_t MultimodalInputConnectManager::CreateVKeyboardDevice(sptr<IRemoteObject> &vkeyboardDevice)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->CreateVKeyboardDevice(vkeyboardDevice);
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

int32_t MultimodalInputConnectManager::SetPixelMapData(int32_t infoId, void* pixelMap)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(pixelMap, ERR_INVALID_VALUE);
    CursorPixelMap curPixelMap {};
    curPixelMap.pixelMap = pixelMap;
    return multimodalInputConnectService_->SetPixelMapData(infoId, curPixelMap);
}

int32_t MultimodalInputConnectManager::SetCurrentUser(int32_t userId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetCurrentUser(userId);
}

int32_t MultimodalInputConnectManager::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadThreeFingersTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadThreeFingersTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetMoveEventFilters(bool flag)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMoveEventFilters(flag);
}

int32_t MultimodalInputConnectManager::EnableHardwareCursorStats(bool enable)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->EnableHardwareCursorStats(enable);
}

int32_t MultimodalInputConnectManager::GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetHardwareCursorStats(frameCount, vsyncCount);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t MultimodalInputConnectManager::GetPointerSnapshot(void *pixelMapPtr)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CursorPixelMap curPixelMap {};
    auto ret = multimodalInputConnectService_->GetPointerSnapshot(curPixelMap);
    CHKPR(curPixelMap.pixelMap, ERR_INVALID_VALUE);
    pixelMapPtr = curPixelMap.pixelMap;
    return ret;
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

int32_t MultimodalInputConnectManager::SetTouchpadScrollRows(int32_t rows)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadScrollRows(rows);
}

int32_t MultimodalInputConnectManager::GetTouchpadScrollRows(int32_t &rows)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadScrollRows(rows);
}

int32_t MultimodalInputConnectManager::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(device, ERROR_NULL_POINTER);
    return multimodalInputConnectService_->AddVirtualInputDevice(*device, deviceId);
}

int32_t MultimodalInputConnectManager::RemoveVirtualInputDevice(int32_t deviceId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveVirtualInputDevice(deviceId);
}

#ifdef OHOS_BUILD_ENABLE_ANCO
int32_t MultimodalInputConnectManager::AncoAddChannel(sptr<IAncoChannel> channel)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AncoAddChannel(channel);
}

int32_t MultimodalInputConnectManager::AncoRemoveChannel(sptr<IAncoChannel> channel)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AncoRemoveChannel(channel);
}

int32_t MultimodalInputConnectManager::CheckKnuckleEvent(float pointX, float pointY, bool &touchType)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->CheckKnuckleEvent(pointX, pointY, touchType);
}
#endif // OHOS_BUILD_ENABLE_ANCO

int32_t MultimodalInputConnectManager::SkipPointerLayer(bool isSkip)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SkipPointerLayer(isSkip);
}

int32_t MultimodalInputConnectManager::SetClientInfo(int32_t pid, uint64_t readThreadId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetClientInfo(pid, readThreadId);
}

int32_t MultimodalInputConnectManager::GetIntervalSinceLastInput(int64_t &timeInterval)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetIntervalSinceLastInput(timeInterval);
}

int32_t MultimodalInputConnectManager::GetAllSystemHotkeys(std::vector<std::unique_ptr<KeyOption>> &keyOptions)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    std::vector<KeyOption> keyOptionsArray;
    auto ret = multimodalInputConnectService_->GetAllSystemHotkeys(keyOptionsArray);
    for (auto& opt : keyOptionsArray) {
        keyOptions.push_back(std::make_unique<KeyOption>(std::move(opt)));
    }

    return ret;
}

int32_t MultimodalInputConnectManager::SetInputDeviceEnabled(int32_t deviceId, bool enable, int32_t index)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetInputDeviceEnabled(deviceId, enable, index);
}

int32_t MultimodalInputConnectManager::ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->ShiftAppPointerEvent(param, autoGenDown);
}

int32_t MultimodalInputConnectManager::SetCustomCursor(int32_t windowId, CustomCursor cursor, CursorOptions options)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    CHKPR(cursor.pixelMap, RET_ERR);
    CustomCursorParcel curParcel(cursor.pixelMap, cursor.focusX, cursor.focusY);
    CursorOptionsParcel cOptionParcel {};
    cOptionParcel.followSystem = options.followSystem;
    return multimodalInputConnectService_->SetCustomCursor(windowId, curParcel, cOptionParcel);
}

int32_t MultimodalInputConnectManager::SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMultiWindowScreenId(screenId, displayNodeScreenId);
}

int32_t MultimodalInputConnectManager::SetKnuckleSwitch(bool knuckleSwitch)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKnuckleSwitch(knuckleSwitch);
}

int32_t MultimodalInputConnectManager::LaunchAiScreenAbility()
{
    // LCOV_EXCL_START
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->LaunchAiScreenAbility();
    // LCOV_EXCL_STOP
}

int32_t MultimodalInputConnectManager::GetMaxMultiTouchPointNum(int32_t &pointNum)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetMaxMultiTouchPointNum(pointNum);
}

int32_t MultimodalInputConnectManager::SubscribeInputActive(int32_t subscribeId, int64_t interval)
{
    sptr<IMultimodalInputConnect> multimodalInputConnectService = nullptr;
    {
        std::lock_guard<std::mutex> guard(lock_);
        CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
        multimodalInputConnectService = multimodalInputConnectService_;
    }
    return multimodalInputConnectService->SubscribeInputActive(subscribeId, interval);
}

int32_t MultimodalInputConnectManager::UnsubscribeInputActive(int32_t subscribeId)
{
    sptr<IMultimodalInputConnect> multimodalInputConnectService = nullptr;
    {
        std::lock_guard<std::mutex> guard(lock_);
        CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
        multimodalInputConnectService = multimodalInputConnectService_;
    }
    return multimodalInputConnectService->UnsubscribeInputActive(subscribeId);
}

int32_t MultimodalInputConnectManager::SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseAccelerateMotionSwitch(deviceId, enable);
}

int32_t MultimodalInputConnectManager::SwitchScreenCapturePermission(uint32_t permissionType, bool enable)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SwitchScreenCapturePermission(permissionType, enable);
}

int32_t MultimodalInputConnectManager::ClearMouseHideFlag(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->ClearMouseHideFlag(eventId);
}

int32_t MultimodalInputConnectManager::QueryPointerRecord(
    int32_t count, std::vector<std::shared_ptr<PointerEvent>> &pointerList)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->QueryPointerRecord(count, pointerList);
}

int32_t MultimodalInputConnectManager::AddKeyEventHook(int32_t &hookId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddKeyEventHook(hookId);
}

int32_t MultimodalInputConnectManager::RemoveKeyEventHook(int32_t hookId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveKeyEventHook(hookId);
}

int32_t MultimodalInputConnectManager::DispatchToNextHandler(int32_t eventId)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->DispatchToNextHandler(eventId);
}

int32_t MultimodalInputConnectManager::GetExternalObject(
    const std::string &pluginName, sptr<IRemoteObject> &pluginRemoteStub)
{
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetExternalObject(pluginName, pluginRemoteStub);
}

int32_t MultimodalInputConnectManager::SetKeyStatusRecord(bool enable, int32_t timeout)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKeyStatusRecord(enable, timeout);
}
} // namespace MMI
} // namespace OHOS
