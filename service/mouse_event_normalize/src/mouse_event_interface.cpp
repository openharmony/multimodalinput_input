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

#include "mouse_event_interface.h"

#include "mouse_preference_accessor.h"

#include "ffrt.h"
#include "input_device_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseEventInterface"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_UNLOAD_DELAY_TIME { 180000 }; // 3 minutes
constexpr int32_t REPEAT_ONCE { 1 };
constexpr char LIB_MOUSE_EVENT_NORMALIZATION_NAME[] { "libmmi_mouse_event_normalizer.z.so" };
} // namespace

MouseEventInterface::InputDeviceObserver::InputDeviceObserver(std::shared_ptr<MouseEventInterface> parent)
    : parent_(parent) {}

void MouseEventInterface::InputDeviceObserver::OnDeviceAdded(int32_t deviceId)
{
    CALL_INFO_TRACE;
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceAdded(parent, deviceId);
    }
}

void MouseEventInterface::InputDeviceObserver::OnDeviceRemoved(int32_t deviceId)
{
    CALL_INFO_TRACE;
    if (auto parent = parent_.lock(); parent != nullptr) {
        parent->OnDeviceRemoved(parent, deviceId);
    }
}

bool MouseEventInterface::HasMouse()
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse->HasMouse();
}

int32_t MouseEventInterface::OnEvent(struct libinput_event *event)
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->OnEvent(event);
}

std::shared_ptr<PointerEvent> MouseEventInterface::GetPointerEvent()
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return nullptr;
    }
    return mouse->GetPointerEvent();
}

std::shared_ptr<PointerEvent> MouseEventInterface::GetPointerEvent(int32_t deviceId)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return nullptr;
    }
    return mouse->GetPointerEvent(deviceId);
}

void MouseEventInterface::Dump(int32_t fd, const std::vector<std::string> &args)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse->Dump(fd, args);
}

int32_t MouseEventInterface::NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->NormalizeRotateEvent(event, type, angle);
}

bool MouseEventInterface::CheckAndPackageAxisEvent(libinput_event* event)
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse->CheckAndPackageAxisEvent(event);
}

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
bool MouseEventInterface::CheckFilterMouseEvent(struct libinput_event *event)
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse->CheckFilterMouseEvent(event);
}

#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool MouseEventInterface::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse->NormalizeMoveMouse(offsetX, offsetY);
}

void MouseEventInterface::OnDisplayLost(int32_t displayId)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse->OnDisplayLost(displayId);
}

int32_t MouseEventInterface::GetDisplayId()
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->GetDisplayId();
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MouseEventInterface::SetPointerLocation(int32_t x, int32_t y, int32_t displayId)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->SetPointerLocation(x, y, displayId);
}

int32_t MouseEventInterface::GetPointerLocation(int32_t &displayId, double &displayX, double &displayY)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->GetPointerLocation(displayId, displayX, displayY);
}

int32_t MouseEventInterface::SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->SetMouseAccelerateMotionSwitch(deviceId, enable);
}

int32_t MouseEventInterface::SetMouseScrollRows(int32_t rows)
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetMouseScrollRows(*env, rows);
}

int32_t MouseEventInterface::GetMouseScrollRows() const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetMouseScrollRows(*env);
}

int32_t MouseEventInterface::SetMousePrimaryButton(int32_t primaryButton)
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetMousePrimaryButton(*env, primaryButton);
}

int32_t MouseEventInterface::GetMousePrimaryButton() const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetMousePrimaryButton(*env);
}

int32_t MouseEventInterface::SetPointerSpeed(int32_t speed)
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    auto ret = MousePreferenceAccessor::SetPointerSpeed(*env, speed);
    if (ret != RET_OK) {
        return ret;
    }
    auto mouse = GetMouse();
    if (mouse != nullptr) {
        mouse->SetPointerSpeed(speed);
    }
    return RET_OK;
}

int32_t MouseEventInterface::GetPointerSpeed() const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetPointerSpeed(*env);
}

int32_t MouseEventInterface::GetTouchpadSpeed() const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetTouchpadSpeed(*env);
}

int32_t MouseEventInterface::SetTouchpadScrollSwitch(int32_t pid, bool switchFlag) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    auto ret = MousePreferenceAccessor::SetTouchpadScrollSwitch(*env, pid, switchFlag);
    if (ret != RET_OK) {
        MMI_HILOGE("MousePref SetTouchpadScrollSwitch fail");
        return ret;
    }
    if (!switchFlag) {
        auto mouse = GetMouse();
        if (mouse != nullptr) {
            mouse->SetScrollSwitchSetterPid(pid);
        }
    }
    return RET_OK;
}

void MouseEventInterface::GetTouchpadScrollSwitch(bool &switchFlag) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadScrollSwitch(*env, switchFlag);
}

int32_t MouseEventInterface::SetTouchpadScrollDirection(bool state) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadScrollDirection(*env, state);
}

void MouseEventInterface::GetTouchpadScrollDirection(bool &state) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadScrollDirection(*env, state);
}

int32_t MouseEventInterface::SetTouchpadTapSwitch(bool switchFlag) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadTapSwitch(*env, switchFlag);
}

void MouseEventInterface::GetTouchpadTapSwitch(bool &switchFlag) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadTapSwitch(*env, switchFlag);
}

int32_t MouseEventInterface::SetTouchpadRightClickType(int32_t type) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadRightClickType(*env, type);
}

void MouseEventInterface::GetTouchpadRightClickType(int32_t &type) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadRightClickType(*env, type);
}

int32_t MouseEventInterface::SetTouchpadPointerSpeed(int32_t speed) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadPointerSpeed(*env, speed);
}

void MouseEventInterface::GetTouchpadPointerSpeed(int32_t &speed) const
{
    auto env = GetEnv();
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadPointerSpeed(*env, speed);
}

void  MouseEventInterface::ReadTouchpadCDG(TouchpadCDG &touchpadCDG) const
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
}

int32_t MouseEventInterface::GetMouseCoordsX()
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->GetMouseCoordsX();
}

int32_t MouseEventInterface::GetMouseCoordsY()
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->GetMouseCoordsY();
}

void MouseEventInterface::SetMouseCoords(int32_t x, int32_t y)
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse->SetMouseCoords(x, y);
}

bool MouseEventInterface::IsLeftBtnPressed()
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse->IsLeftBtnPressed();
}

void MouseEventInterface::GetPressedButtons(std::vector<int32_t>& pressedButtons)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse->GetPressedButtons(pressedButtons);
}

void MouseEventInterface::MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState)
{
    LoadMouse();
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse->MouseBtnStateCounts(btnCode, btnState);
}

int32_t MouseEventInterface::LibinputChangeToPointer(const uint32_t keyValue)
{
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse->LibinputChangeToPointer(keyValue);
}

std::shared_ptr<MouseEventInterface> MouseEventInterface::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<MouseEventInterface> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<MouseEventInterface>();
        instance_->SetUpDeviceObserver(instance_);
    });
    return instance_;
}

MouseEventInterface::~MouseEventInterface()
{
    TearDownDeviceObserver();
    RemoveUnloadingTimer();
}

void MouseEventInterface::AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env)
{
    std::lock_guard guard { mutex_ };
    env_ = env;
}

std::shared_ptr<IInputServiceContext> MouseEventInterface::GetEnv() const
{
    std::lock_guard guard { mutex_ };
    return env_.lock();
}

ComponentManager::Handle<IMouseEventNormalize> MouseEventInterface::GetMouse() const
{
    std::lock_guard guard { mutex_ };
    return mouse_;
}

void MouseEventInterface::SetUpDeviceObserver(std::shared_ptr<MouseEventInterface> self)
{
    std::lock_guard guard { mutex_ };
    if (inputDevObserver_ == nullptr) {
        inputDevObserver_ = std::make_shared<InputDeviceObserver>(self);
        INPUT_DEV_MGR->Attach(inputDevObserver_);
    }
}

void MouseEventInterface::TearDownDeviceObserver()
{
    std::lock_guard guard { mutex_ };
    if (inputDevObserver_ != nullptr) {
        INPUT_DEV_MGR->Detach(inputDevObserver_);
        inputDevObserver_ = nullptr;
    }
}

void MouseEventInterface::OnDeviceAdded(std::shared_ptr<MouseEventInterface> self, int32_t deviceId)
{
    auto isMouse = INPUT_DEV_MGR->CheckDevice(deviceId,
        [this](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsMouse();
        });
    if (!isMouse) {
        MMI_HILOGI("Device[%{private}d] Not mouse", deviceId);
        return;
    }
    RemoveUnloadingTimer();
    auto mouse = GetMouse();
    if (mouse != nullptr) {
        mouse->OnDeviceAdded(deviceId);
    } else if (!loading_.load()) {
        loading_.store(true);
        ffrt::submit([self]() {
            self->LoadMouse();
            self->loading_.store(false);
        });
    }
}

void MouseEventInterface::OnDeviceRemoved(std::shared_ptr<MouseEventInterface> self, int32_t deviceId)
{
    CALL_INFO_TRACE;
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGI("Mouse is nullptr");
        return;
    }
    mouse->OnDeviceRemoved(deviceId);
    if (mouse->HasMouse()) {
        MMI_HILOGI("Mouse existed yet, do not unload");
        return;
    }
    ScheduleUnloadingTimer();
}

void MouseEventInterface::LoadMouse()
{
    std::shared_ptr<IInputServiceContext> env {};
    {
        std::lock_guard guard { mutex_ };
        if (mouse_ != nullptr) {
            return;
        }
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MMI_HILOGI("Start loading Mouse");
    auto mouse = ComponentManager::LoadLibrary<IMouseEventNormalize>(
        env.get(), LIB_MOUSE_EVENT_NORMALIZATION_NAME);
    if (mouse == nullptr) {
        MMI_HILOGE("Failed to load Mouse");
        return;
    }
    {
        std::lock_guard guard { mutex_ };
        mouse_ = std::move(mouse);
    }
    MMI_HILOGI("Mouse loaded");
    OnMouseLoaded();
}

void MouseEventInterface::LoadMouseExplicitly()
{
    CALL_INFO_TRACE;
    auto mouse = GetMouse();
    if (mouse != nullptr) {
        ResetUnloadingTimer();
        return;
    }
    RemoveUnloadingTimer();
    LoadMouse();
    mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Load mouse failed");
        return;
    }
    if (mouse->HasMouse()) {
        return;
    }
    ScheduleUnloadingTimer();
}

void MouseEventInterface::OnMouseLoaded()
{
    CALL_INFO_TRACE;
    auto mouse = GetMouse();
    if (mouse == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    INPUT_DEV_MGR->ForEachDevice(
        [mouse](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            if (dev.IsMouse()) {
                mouse->OnDeviceAdded(id);
            }
        });
}

void MouseEventInterface::UnloadMouse()
{
    MMI_HILOGI("Unload Mouse");
    std::lock_guard guard { mutex_ };
    unloadTimerId_ = -1;
    mouse_ = { nullptr, ComponentManager::Component<IMouseEventNormalize>() };
}

void MouseEventInterface::ScheduleUnloadingTimer()
{
    {
        std::lock_guard guard { mutex_ };
        if (unloadTimerId_ >= 0) {
            return;
        }
    }
    MMI_HILOGI("Schedule unloading Mouse");
    auto timerId = TimerMgr->AddLongTimer(DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
        [this]() {
            this->UnloadMouse();
        }, std::string("UnloadMouse"));
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

void MouseEventInterface::RemoveUnloadingTimer()
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

void MouseEventInterface::ResetUnloadingTimer()
{
    int32_t timerId { -1 };

    {
        std::lock_guard guard { mutex_ };
        timerId = unloadTimerId_;
    }
    if (timerId >= 0) {
        TimerMgr->ResetTimer(timerId);
    }
}
} // namespace MMI
} // namespace OHOS