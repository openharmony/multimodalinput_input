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

#include "multimodal_input_connect_manager.h"

#include <chrono>
#include <thread>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "mmi_log.h"
#include "multimodal_input_connect_death_recipient.h"
#include "multimodal_input_connect_define.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
std::shared_ptr<MultimodalInputConnectManager> g_instance = nullptr;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectManager"};
} // namespace

std::shared_ptr<MultimodalInputConnectManager> MultimodalInputConnectManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new (std::nothrow) MultimodalInputConnectManager());
    });

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

    MMI_HILOGI("AllocSocketPair success. socketFd_:%{public}d tokenType_:%{public}d", socketFd_, tokenType_);
    return RET_OK;
}

int32_t MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair() const
{
    CALL_DEBUG_ENTER;
    return socketFd_;
}

int32_t MultimodalInputConnectManager::AddInputEventFilter(sptr<IEventFilter> filter)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("The multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->AddInputEventFilter(filter);
}

int32_t MultimodalInputConnectManager::SetPointerVisible(bool visible)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetPointerVisible(visible);
}

int32_t MultimodalInputConnectManager::IsPointerVisible(bool &visible)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->IsPointerVisible(visible);
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

int32_t MultimodalInputConnectManager::SetPointerStyle(int32_t windowId, int32_t pointerStyle)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetPointerStyle(windowId, pointerStyle);
}

int32_t MultimodalInputConnectManager::GetPointerStyle(int32_t windowId, int32_t &pointerStyle)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetPointerStyle(windowId, pointerStyle);
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

int32_t MultimodalInputConnectManager::SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> &keys)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SupportKeys(userData, deviceId, keys);
}

int32_t MultimodalInputConnectManager::GetDeviceIds(int32_t userData)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetDeviceIds(userData);
}

int32_t MultimodalInputConnectManager::GetDevice(int32_t userData, int32_t id)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetDevice(userData, id);
}

int32_t MultimodalInputConnectManager::GetKeyboardType(int32_t userData, int32_t deviceId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetKeyboardType(userData, deviceId);
}

int32_t MultimodalInputConnectManager::AddInputHandler(InputHandlerType handlerType, HandleEventType eventType)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->AddInputHandler(handlerType, eventType);
}

int32_t MultimodalInputConnectManager::RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->RemoveInputHandler(handlerType, eventType);
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

int32_t MultimodalInputConnectManager::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->MoveMouseEvent(offsetX, offsetY);
}

int32_t MultimodalInputConnectManager::InjectKeyEvent(const std::shared_ptr<KeyEvent> event)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->InjectKeyEvent(event);
}

int32_t MultimodalInputConnectManager::InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->InjectPointerEvent(pointerEvent);
}

int32_t MultimodalInputConnectManager::SetAnrObserver()
{
    CHKPR(multimodalInputConnectService_, INVALID_HANDLER_ID);
    return multimodalInputConnectService_->SetAnrObserver();
}

int32_t MultimodalInputConnectManager::RegisterCooperateListener()
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->RegisterCooperateListener();
}

int32_t MultimodalInputConnectManager::UnregisterCooperateListener()
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->UnregisterCooperateListener();
}

int32_t MultimodalInputConnectManager::EnableInputDeviceCooperate(int32_t userData, bool enabled)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->EnableInputDeviceCooperate(userData, enabled);
}

int32_t MultimodalInputConnectManager::StartInputDeviceCooperate(int32_t userData,
    const std::string &sinkDeviceId, int32_t srcInputDeviceId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->StartInputDeviceCooperate(userData, sinkDeviceId, srcInputDeviceId);
}

int32_t MultimodalInputConnectManager::StopDeviceCooperate(int32_t userData)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->StopDeviceCooperate(userData);
}

int32_t MultimodalInputConnectManager::GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->GetInputDeviceCooperateState(userData, deviceId);
}

int32_t MultimodalInputConnectManager::SetInputDevice(const std::string& dhid, const std::string& screenId)
{
    CHKPR(multimodalInputConnectService_, RET_ERR);
    return multimodalInputConnectService_->SetInputDevice(dhid, screenId);
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
            sharedPtr->OnDeath();
        }
    };

    multimodalInputConnectRecipient_ = new (std::nothrow) MultimodalInputConnectDeathRecipient(deathCallback);
    CHKPF(multimodalInputConnectRecipient_);
    sa->AddDeathRecipient(multimodalInputConnectRecipient_);
    multimodalInputConnectService_ = iface_cast<IMultimodalInputConnect>(sa);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_HILOGE("Get multimodalinput service failed");
        return false;
    }
    MMI_HILOGI("Get multimodalinput service successful");
    return true;
}

void MultimodalInputConnectManager::OnDeath()
{
    CALL_DEBUG_ENTER;
    Clean();
    NotifyDeath();
}

void MultimodalInputConnectManager::Clean()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        multimodalInputConnectService_.clear();
        multimodalInputConnectService_ = nullptr;
    }

    if (multimodalInputConnectRecipient_ != nullptr) {
        multimodalInputConnectRecipient_.clear();
        multimodalInputConnectRecipient_ = nullptr;
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
} // namespace MMI
} // namespace OHOS
