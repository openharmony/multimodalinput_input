/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "joystick_event_interface.h"

#include "ffrt.h"
#include "input_device_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventInterface"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_UNLOAD_DELAY_TIME { 180000 }; // 3 minutes
constexpr int32_t REPEAT_ONCE { 1 };
constexpr char LIB_JOYSTICK_EVENT_NORMALIZATION_NAME[] { "libmmi_joystick_event_normalization.z.so" };
} // namespace

JoystickEventInterface::InputDeviceObserver::InputDeviceObserver(std::shared_ptr<JoystickEventInterface> parent)
    : parent_(parent) {}

void JoystickEventInterface::InputDeviceObserver::OnDeviceAdded(int32_t deviceId)
{
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceAdded(parent, deviceId);
    }
}

void JoystickEventInterface::InputDeviceObserver::OnDeviceRemoved(int32_t deviceId)
{
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceRemoved(parent, deviceId);
    }
}

std::shared_ptr<JoystickEventInterface> JoystickEventInterface::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<JoystickEventInterface> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<JoystickEventInterface>();
        instance_->SetUpDeviceObserver(instance_);
    });
    return instance_;
}

JoystickEventInterface::~JoystickEventInterface()
{
    RemoveUnloadingTimer();
    TearDownDeviceObserver();
}

void JoystickEventInterface::AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env)
{
    std::lock_guard guard { mutex_ };
    env_ = env;
}

std::shared_ptr<KeyEvent> JoystickEventInterface::OnButtonEvent(struct libinput_event *event)
{
    auto joystick = GetJoystick();
    if (joystick == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return nullptr;
    }
    return joystick->OnButtonEvent(event);
}

std::shared_ptr<PointerEvent> JoystickEventInterface::OnAxisEvent(struct libinput_event *event)
{
    auto joystick = GetJoystick();
    if (joystick == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return nullptr;
    }
    return joystick->OnAxisEvent(event);
}

void JoystickEventInterface::CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
    std::function<void(std::shared_ptr<KeyEvent>)> handler)
{
    auto joystick = GetJoystick();
    if (joystick == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return;
    }
    joystick->CheckIntention(pointerEvent, handler);
}

ComponentManager::Handle<IJoystickEventNormalize> JoystickEventInterface::GetJoystick()
{
    std::lock_guard guard { mutex_ };
    return joystick_;
}

void JoystickEventInterface::SetUpDeviceObserver(std::shared_ptr<JoystickEventInterface> self)
{
    std::lock_guard guard { mutex_ };
    if (inputDevObserver_ != nullptr) {
        return;
    }
    inputDevObserver_ = std::make_shared<InputDeviceObserver>(self);
    INPUT_DEV_MGR->Attach(inputDevObserver_);
}

void JoystickEventInterface::TearDownDeviceObserver()
{
    std::lock_guard guard { mutex_ };
    if (inputDevObserver_ != nullptr) {
        INPUT_DEV_MGR->Detach(inputDevObserver_);
        inputDevObserver_ = nullptr;
    }
}

void JoystickEventInterface::OnDeviceAdded(std::shared_ptr<JoystickEventInterface> self, int32_t deviceId)
{
    auto isJoystick = INPUT_DEV_MGR->CheckDevice(deviceId,
        [this](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsJoystick();
        });
    if (!isJoystick) {
        MMI_HILOGI("Device[%{private}d] Not joystick", deviceId);
        return;
    }
    RemoveUnloadingTimer();
    auto joystick = GetJoystick();
    if (joystick != nullptr) {
        joystick->OnDeviceAdded(deviceId);
    } else if (!loading_.load()) {
        loading_.store(true);
        ffrt::submit([self]() {
            self->LoadJoystick();
            self->loading_.store(false);
        });
    }
}

void JoystickEventInterface::OnDeviceRemoved(std::shared_ptr<JoystickEventInterface> self, int32_t deviceId)
{
    auto joystick = GetJoystick();
    if (joystick == nullptr) {
        return;
    }
    joystick->OnDeviceRemoved(deviceId);
    if (joystick->HasJoystick()) {
        return;
    }
    ScheduleUnloadingTimer(self);
}

void JoystickEventInterface::LoadJoystick()
{
    MMI_HILOGI("Start loading Joystick");
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    auto joystick = ComponentManager::LoadLibrary<IJoystickEventNormalize>(
        env.get(), LIB_JOYSTICK_EVENT_NORMALIZATION_NAME);
    if (joystick == nullptr) {
        MMI_HILOGE("Failed to load Joystick");
        return;
    }
    {
        std::lock_guard guard { mutex_ };
        joystick_ = std::move(joystick);
    }
    MMI_HILOGI("Joystick loaded");
    OnJoystickLoaded();
}

void JoystickEventInterface::OnJoystickLoaded()
{
    auto joystick = GetJoystick();
    if (joystick == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return;
    }
    INPUT_DEV_MGR->ForEachDevice(
        [joystick](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            if (dev.IsJoystick()) {
                joystick->OnDeviceAdded(id);
            }
        });
}

void JoystickEventInterface::UnloadJoystick()
{
    MMI_HILOGI("Unload Joystick");
    std::lock_guard guard { mutex_ };
    unloadTimerId_ = -1;
    joystick_ = { nullptr, ComponentManager::Component<IJoystickEventNormalize>() };
}

void JoystickEventInterface::ScheduleUnloadingTimer(std::shared_ptr<JoystickEventInterface> self)
{
    {
        std::lock_guard guard { mutex_ };
        if (unloadTimerId_ >= 0) {
            return;
        }
    }
    MMI_HILOGI("Schedule unloading Joystick");
    auto timerId = TimerMgr->AddLongTimer(DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
        [self]() {
            self->UnloadJoystick();
        }, std::string("UnloadJoystick"));
    if (timerId < 0) {
        MMI_HILOGE("AddLongTimer fail");
        return;
    }
    {
        std::lock_guard guard { mutex_ };
        if (unloadTimerId_ < 0) {
            unloadTimerId_ = timerId;
            timerId = -1;
        }
    }
    if (timerId >= 0) {
        TimerMgr->RemoveTimer(timerId);
    }
}

void JoystickEventInterface::RemoveUnloadingTimer()
{
    int32_t timerId { -1 };

    {
        std::lock_guard guard { mutex_ };
        timerId = unloadTimerId_;
        unloadTimerId_ = -1;
    }
    if (timerId >= 0) {
        TimerMgr->RemoveTimer(timerId);
    }
}
} // namespace MMI
} // namespace OHOS
