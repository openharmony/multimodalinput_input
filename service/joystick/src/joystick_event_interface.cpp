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
    TearDownDeviceObserver();
}

void JoystickEventInterface::AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env)
{
    std::lock_guard guard { mutex_ };
    env_ = env;
}

std::shared_ptr<KeyEvent> JoystickEventInterface::OnButtonEvent(struct libinput_event *event)
{
    std::lock_guard guard { mutex_ };
    if (joystick_ == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return nullptr;
    }
    return joystick_->OnButtonEvent(event);
}

std::shared_ptr<PointerEvent> JoystickEventInterface::OnAxisEvent(struct libinput_event *event)
{
    std::lock_guard guard { mutex_ };
    if (joystick_ == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return nullptr;
    }
    return joystick_->OnAxisEvent(event);
}

void JoystickEventInterface::CheckIntention(std::shared_ptr<PointerEvent> pointerEvent,
    std::function<void(std::shared_ptr<KeyEvent>)> handler)
{
    std::lock_guard guard { mutex_ };
    if (joystick_ == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return;
    }
    joystick_->CheckIntention(pointerEvent, handler);
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
    std::lock_guard guard { mutex_ };
    if (unloadTimerId_ >= 0) {
        TimerMgr->RemoveTimer(unloadTimerId_);
        unloadTimerId_ = -1;
    }
    if (joystick_ != nullptr) {
        joystick_->OnDeviceAdded(deviceId);
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
    std::lock_guard guard { mutex_ };
    if (joystick_ != nullptr) {
        joystick_->OnDeviceRemoved(deviceId);
        if (!joystick_->HasJoystick()) {
            MMI_HILOGI("Schedule unloading Joystick");
            unloadTimerId_ = TimerMgr->AddLongTimer(DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
                [self]() {
                    self->UnloadJoystick();
                }, std::string("UnloadJoystick"));
        }
    }
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
    std::lock_guard guard { mutex_ };
    if (joystick_ == nullptr) {
        MMI_HILOGE("Joystick module not loaded");
        return;
    }
    INPUT_DEV_MGR->ForEachDevice(
        [this](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            if (dev.IsJoystick()) {
                joystick_->OnDeviceAdded(id);
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
} // namespace MMI
} // namespace OHOS
