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

#include "multimodal_input_connect_manager.h"

#include <chrono>
#include <thread>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "mmi_log.h"
#include "multimodal_input_connect_death_recipient.h"
#include "multimodal_input_connect_define.h"
#include "util.h"

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
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("Client has not connect server");
        return RET_ERR;
    }

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
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->GetDisplayBindInfo(infos);
}

int32_t MultimodalInputConnectManager::GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>,
    int32_t> &datas)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->GetAllMmiSubscribedEvents(datas);
}

int32_t MultimodalInputConnectManager::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->SetDisplayBind(deviceId, displayId, msg);
}

int32_t MultimodalInputConnectManager::GetWindowPid(int32_t windowId)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->GetWindowPid(windowId);
}

int32_t MultimodalInputConnectManager::AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId,
    int32_t priority, uint32_t deviceTags)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->AddInputEventFilter(filter, filterId, priority, deviceTags);
}

int32_t MultimodalInputConnectManager::NotifyNapOnline()
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->NotifyNapOnline();
}

int32_t MultimodalInputConnectManager::RemoveInputEventObserver()
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->RemoveInputEventObserver();
}

int32_t MultimodalInputConnectManager::RemoveInputEventFilter(int32_t filterId)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->RemoveInputEventFilter(filterId);
}

int32_t MultimodalInputConnectManager::SetMouseScrollRows(int32_t rows)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseScrollRows(rows);
}

int32_t MultimodalInputConnectManager::SetCustomCursor(int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY,
    void* pixelMap)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetCustomCursor(pid, windowId, focusX, focusY, pixelMap);
}

int32_t MultimodalInputConnectManager::SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseIcon(pid, windowId, pixelMap);
}

int32_t MultimodalInputConnectManager::SetMouseHotSpot(
    int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
}

int32_t MultimodalInputConnectManager::GetMouseScrollRows(int32_t &rows)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetMouseScrollRows(rows);
}

int32_t MultimodalInputConnectManager::SetPointerSize(int32_t size)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerSize(size);
}

int32_t MultimodalInputConnectManager::SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napStatus)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetNapStatus(pid, uid, bundleName, napStatus);
}

int32_t MultimodalInputConnectManager::GetPointerSize(int32_t &size)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerSize(size);
}

int32_t MultimodalInputConnectManager::SetMousePrimaryButton(int32_t primaryButton)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMousePrimaryButton(primaryButton);
}

int32_t MultimodalInputConnectManager::GetMousePrimaryButton(int32_t &primaryButton)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetMousePrimaryButton(primaryButton);
}

int32_t MultimodalInputConnectManager::SetHoverScrollState(bool state)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetHoverScrollState(state);
}

int32_t MultimodalInputConnectManager::GetHoverScrollState(bool &state)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetHoverScrollState(state);
}

int32_t MultimodalInputConnectManager::SetPointerVisible(bool visible, int32_t priority)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerVisible(visible, priority);
}

int32_t MultimodalInputConnectManager::IsPointerVisible(bool &visible)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->IsPointerVisible(visible);
}

int32_t MultimodalInputConnectManager::MarkProcessed(int32_t eventType, int32_t eventId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MarkProcessed(eventType, eventId);
}

int32_t MultimodalInputConnectManager::SetPointerColor(int32_t color)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerColor(color);
}

int32_t MultimodalInputConnectManager::GetPointerColor(int32_t &color)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetPointerColor(color);
}

int32_t MultimodalInputConnectManager::SetPointerSpeed(int32_t speed)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::GetPointerSpeed(int32_t &speed)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::SetPointerStyle(int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetPointerStyle(windowId, pointerStyle, isUiExtension);
}

int32_t MultimodalInputConnectManager::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->ClearWindowPointerStyle(pid, windowId);
}

int32_t MultimodalInputConnectManager::GetPointerStyle(int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetPointerStyle(windowId, pointerStyle, isUiExtension);
}

int32_t MultimodalInputConnectManager::RegisterDevListener()
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->RegisterDevListener();
}

int32_t MultimodalInputConnectManager::UnregisterDevListener()
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->UnregisterDevListener();
}

int32_t MultimodalInputConnectManager::SupportKeys(int32_t deviceId, std::vector<int32_t> &keys,
    std::vector<bool> &keystroke)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SupportKeys(deviceId, keys, keystroke);
}

int32_t MultimodalInputConnectManager::GetDeviceIds(std::vector<int32_t> &ids)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetDeviceIds(ids);
}

int32_t MultimodalInputConnectManager::GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetDevice(deviceId, inputDevice);
}

int32_t MultimodalInputConnectManager::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetKeyboardType(deviceId, keyboardType);
}

int32_t MultimodalInputConnectManager::SetKeyboardRepeatDelay(int32_t delay)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetKeyboardRepeatDelay(delay);
}

int32_t MultimodalInputConnectManager::SetKeyboardRepeatRate(int32_t rate)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetKeyboardRepeatRate(rate);
}

int32_t MultimodalInputConnectManager::GetKeyboardRepeatDelay(int32_t &delay)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetKeyboardRepeatDelay(delay);
}

int32_t MultimodalInputConnectManager::GetKeyboardRepeatRate(int32_t &rate)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetKeyboardRepeatRate(rate);
}

int32_t MultimodalInputConnectManager::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddInputHandler(handlerType, eventType, priority, deviceTags);
}

int32_t MultimodalInputConnectManager::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
    int32_t priority, uint32_t deviceTags)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveInputHandler(handlerType, eventType, priority, deviceTags);
}

int32_t MultimodalInputConnectManager::MarkEventConsumed(int32_t eventId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MarkEventConsumed(eventId);
}

int32_t MultimodalInputConnectManager::SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeKeyEvent(subscribeId, option);
}

int32_t MultimodalInputConnectManager::UnsubscribeKeyEvent(int32_t subscribeId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->UnsubscribeKeyEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::SubscribeSwitchEvent(int32_t subscribeId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeSwitchEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::UnsubscribeSwitchEvent(int32_t subscribeId)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SubscribeSwitchEvent(subscribeId);
}

int32_t MultimodalInputConnectManager::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MoveMouseEvent(offsetX, offsetY);
}

int32_t MultimodalInputConnectManager::InjectKeyEvent(const std::shared_ptr<KeyEvent> event, bool isNativeInject)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->InjectKeyEvent(event, isNativeInject);
}

int32_t MultimodalInputConnectManager::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent,
    bool isNativeInject)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->InjectPointerEvent(pointerEvent, isNativeInject);
}

int32_t MultimodalInputConnectManager::SetAnrObserver()
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetAnrObserver();
}

int32_t MultimodalInputConnectManager::GetFunctionKeyState(int32_t funcKey, bool &state)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetFunctionKeyState(funcKey, state);
}

int32_t MultimodalInputConnectManager::SetFunctionKeyState(int32_t funcKey, bool enable)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetFunctionKeyState(funcKey, enable);
}

int32_t MultimodalInputConnectManager::SetPointerLocation(int32_t x, int32_t y)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerLocation(x, y);
}

bool MultimodalInputConnectManager::ConnectMultimodalInputService()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        return true;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        MMI_HILOGE("Get system ability manager failed");
        return false;
    }
    auto sa = sm->GetSystemAbility(IMultimodalInputConnect::MULTIMODAL_INPUT_CONNECT_SERVICE_ID);
    if (sa == nullptr) {
        MMI_HILOGE("Get sa failed");
        return false;
    }

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
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("Get multimodalinput service failed");
        return false;
    }
    MMI_HILOGI("Get multimodalinput service successful");
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
    std::lock_guard<std::mutex> guard(lock_);
    for (const auto &watcher : watchers_) {
        watcher->OnServiceDied();
    }
}

void MultimodalInputConnectManager::NotifyDeath()
{
    CALL_DEBUG_ENTER;
    int32_t retryCount = 50;
    do {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (ConnectMultimodalInputService()) {
            MMI_HILOGD("Connect multimodalinput service successful");
            return;
        }
    } while (--retryCount > 0);
}

int32_t MultimodalInputConnectManager::SetMouseCaptureMode(int32_t windowId, bool isCaptureMode)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetMouseCaptureMode(windowId, isCaptureMode);
}

int32_t MultimodalInputConnectManager::AppendExtraData(const ExtraData &extraData)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AppendExtraData(extraData);
}

int32_t MultimodalInputConnectManager::EnableCombineKey(bool enable)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->EnableCombineKey(enable);
}

int32_t MultimodalInputConnectManager::EnableInputDevice(bool enable)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->EnableInputDevice(enable);
}

int32_t MultimodalInputConnectManager::SetKeyDownDuration(const std::string &businessId, int32_t delay)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetKeyDownDuration(businessId, delay);
}

int32_t MultimodalInputConnectManager::SetTouchpadScrollSwitch(bool switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadScrollSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadScrollSwitch(bool &switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadScrollSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadScrollDirection(bool state)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadScrollDirection(state);
}

int32_t MultimodalInputConnectManager::GetTouchpadScrollDirection(bool &state)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadScrollDirection(state);
}

int32_t MultimodalInputConnectManager::SetTouchpadTapSwitch(bool switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadTapSwitch(bool &switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadTapSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadPointerSpeed(int32_t speed)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::GetTouchpadPointerSpeed(int32_t &speed)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadPointerSpeed(speed);
}

int32_t MultimodalInputConnectManager::SetTouchpadPinchSwitch(bool switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadPinchSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadPinchSwitch(bool &switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadPinchSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadSwipeSwitch(bool switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadSwipeSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadSwipeSwitch(switchFlag);
}

int32_t MultimodalInputConnectManager::SetTouchpadRightClickType(int32_t type)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadRightClickType(type);
}

int32_t MultimodalInputConnectManager::GetTouchpadRightClickType(int32_t &type)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadRightClickType(type);
}

int32_t MultimodalInputConnectManager::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetTouchpadRotateSwitch(rotateSwitch);
}

int32_t MultimodalInputConnectManager::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetTouchpadRotateSwitch(rotateSwitch);
}

int32_t MultimodalInputConnectManager::SetShieldStatus(int32_t shieldMode, bool isShield)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetShieldStatus(shieldMode, isShield);
}

int32_t MultimodalInputConnectManager::GetShieldStatus(int32_t shieldMode, bool &isShield)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->GetShieldStatus(shieldMode, isShield);
}

int32_t MultimodalInputConnectManager::GetKeyState(std::vector<int32_t> &pressedKeys,
    std::map<int32_t, int32_t> &specialKeysState)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetKeyState(pressedKeys, specialKeysState);
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
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->Authorize(isAuthorize);
}

int32_t MultimodalInputConnectManager::CancelInjection()
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->CancelInjection();
}

int32_t MultimodalInputConnectManager::HasIrEmitter(bool &hasIrEmitter)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->HasIrEmitter(hasIrEmitter);
}

int32_t MultimodalInputConnectManager::GetInfraredFrequencies(std::vector<InfraredFrequency>& requencys)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetInfraredFrequencies(requencys);
}

int32_t MultimodalInputConnectManager::TransmitInfrared(int64_t number, std::vector<int64_t>& pattern)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->TransmitInfrared(number, pattern);
}

int32_t MultimodalInputConnectManager::SetPixelMapData(int32_t infoId, void* pixelMap)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetPixelMapData(infoId, pixelMap);
}

int32_t MultimodalInputConnectManager::SetCurrentUser(int32_t userId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetCurrentUser(userId);
}
} // namespace MMI
} // namespace OHOS
