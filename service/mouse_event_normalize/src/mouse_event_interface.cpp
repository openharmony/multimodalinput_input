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
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse_->HasMouse();
}

int32_t MouseEventInterface::OnEvent(struct libinput_event *event)
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->OnEvent(event);
}

std::shared_ptr<PointerEvent> MouseEventInterface::GetPointerEvent()
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return nullptr;
    }
    return mouse_->GetPointerEvent();
}

std::shared_ptr<PointerEvent> MouseEventInterface::GetPointerEvent(int32_t deviceId)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return nullptr;
    }
    return mouse_->GetPointerEvent(deviceId);
}

void MouseEventInterface::Dump(int32_t fd, const std::vector<std::string> &args)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse_->Dump(fd, args);
}

int32_t MouseEventInterface::NormalizeRotateEvent(struct libinput_event *event, int32_t type, double angle)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->NormalizeRotateEvent(event, type, angle);
}

bool MouseEventInterface::CheckAndPackageAxisEvent(libinput_event* event)
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse_->CheckAndPackageAxisEvent(event);
}

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
bool MouseEventInterface::CheckFilterMouseEvent(struct libinput_event *event)
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse_->CheckFilterMouseEvent(event);
}

#endif // OHOS_BUILD_MOUSE_REPORTING_RATE

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool MouseEventInterface::NormalizeMoveMouse(int32_t offsetX, int32_t offsetY)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse_->NormalizeMoveMouse(offsetX, offsetY);
}

void MouseEventInterface::OnDisplayLost(int32_t displayId)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse_->OnDisplayLost(displayId);
}

int32_t MouseEventInterface::GetDisplayId()
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->GetDisplayId();
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t MouseEventInterface::SetPointerLocation(int32_t x, int32_t y, int32_t displayId)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->SetPointerLocation(x, y, displayId);
}

int32_t MouseEventInterface::GetPointerLocation(int32_t &displayId, double &displayX, double &displayY)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->GetPointerLocation(displayId, displayX, displayY);
}

int32_t MouseEventInterface::SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->SetMouseAccelerateMotionSwitch(deviceId, enable);
}

int32_t MouseEventInterface::SetMouseScrollRows(int32_t rows)
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetMouseScrollRows(*env, rows);
}

int32_t MouseEventInterface::GetMouseScrollRows() const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetMouseScrollRows(*env);
}

int32_t MouseEventInterface::SetMousePrimaryButton(int32_t primaryButton)
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetMousePrimaryButton(*env, primaryButton);
}

int32_t MouseEventInterface::GetMousePrimaryButton() const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetMousePrimaryButton(*env);
}

int32_t MouseEventInterface::SetPointerSpeed(int32_t speed)
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    auto ret = MousePreferenceAccessor::SetPointerSpeed(*env, speed);
    if (ret == RET_OK && mouse_ != nullptr) {
        mouse_->SetPointerSpeed(speed);
    }
    return ret;
}

int32_t MouseEventInterface::GetPointerSpeed() const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetPointerSpeed(*env);
}

int32_t MouseEventInterface::GetTouchpadSpeed() const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::GetTouchpadSpeed(*env);
}

int32_t MouseEventInterface::SetTouchpadScrollSwitch(int32_t pid, bool switchFlag) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    auto ret = MousePreferenceAccessor::SetTouchpadScrollSwitch(*env, pid, switchFlag);
    {
        std::lock_guard guard { mutex_ };
        if (ret == RET_OK && mouse_ != nullptr && !switchFlag) {
            mouse_->SetScrollSwitchSetterPid(pid);
        }
    }
    return ret;
}

void MouseEventInterface::GetTouchpadScrollSwitch(bool &switchFlag) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadScrollSwitch(*env, switchFlag);
}

int32_t MouseEventInterface::SetTouchpadScrollDirection(bool state) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadScrollDirection(*env, state);
}

void MouseEventInterface::GetTouchpadScrollDirection(bool &state) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadScrollDirection(*env, state);
}

int32_t MouseEventInterface::SetTouchpadTapSwitch(bool switchFlag) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadTapSwitch(*env, switchFlag);
}

void MouseEventInterface::GetTouchpadTapSwitch(bool &switchFlag) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadTapSwitch(*env, switchFlag);
}

int32_t MouseEventInterface::SetTouchpadRightClickType(int32_t type) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadRightClickType(*env, type);
}

void MouseEventInterface::GetTouchpadRightClickType(int32_t &type) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadRightClickType(*env, type);
}

int32_t MouseEventInterface::SetTouchpadPointerSpeed(int32_t speed) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return RET_ERR;
    }
    return MousePreferenceAccessor::SetTouchpadPointerSpeed(*env, speed);
}

void MouseEventInterface::GetTouchpadPointerSpeed(int32_t &speed) const
{
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
    MousePreferenceAccessor::GetTouchpadPointerSpeed(*env, speed);
}

int32_t MouseEventInterface::GetMouseCoordsX()
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->GetMouseCoordsX();
}

int32_t MouseEventInterface::GetMouseCoordsY()
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->GetMouseCoordsY();
}

void MouseEventInterface::SetMouseCoords(int32_t x, int32_t y)
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse_->SetMouseCoords(x, y);
}

bool MouseEventInterface::IsLeftBtnPressed()
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return false;
    }
    return mouse_->IsLeftBtnPressed();
}

void MouseEventInterface::GetPressedButtons(std::vector<int32_t>& pressedButtons)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    mouse_->GetPressedButtons(pressedButtons);
}

void MouseEventInterface::MouseBtnStateCounts(uint32_t btnCode, const BUTTON_STATE btnState)
{
    LoadMouse();
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }

    mouse_->MouseBtnStateCounts(btnCode, btnState);
}

int32_t MouseEventInterface::LibinputChangeToPointer(const uint32_t keyValue)
{
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return RET_ERR;
    }
    return mouse_->LibinputChangeToPointer(keyValue);
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
    if (unloadTimerId_ >= 0) {
        TimerMgr->RemoveTimer(unloadTimerId_);
        unloadTimerId_ = -1;
    }
}

void MouseEventInterface::AttachInputServiceContext(std::shared_ptr<IInputServiceContext> env)
{
    {
        std::lock_guard guard { mutex_ };
        env_ = env;
    }
}

void MouseEventInterface::SetUpDeviceObserver(std::shared_ptr<MouseEventInterface> self)
{
    if (inputDevObserver_ == nullptr) {
        inputDevObserver_ = std::make_shared<InputDeviceObserver>(self);
        INPUT_DEV_MGR->Attach(inputDevObserver_);
    }
}

void MouseEventInterface::TearDownDeviceObserver()
{
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
    std::lock_guard guard { mutex_ };
    if (unloadTimerId_ >= 0) {
        TimerMgr->RemoveTimer(unloadTimerId_);
        unloadTimerId_ = -1;
    }
    if (mouse_ != nullptr) {
        mouse_->OnDeviceAdded(deviceId);
    } else {
        ffrt::submit([self]() {
            self->LoadMouse();
        });
    }
}

void MouseEventInterface::OnDeviceRemoved(std::shared_ptr<MouseEventInterface> self, int32_t deviceId)
{
    CALL_INFO_TRACE;
    std::lock_guard guard { mutex_ };
    if (mouse_ != nullptr) {
        mouse_->OnDeviceRemoved(deviceId);
        if (!mouse_->HasMouse() && unloadTimerId_ < 0) {
            MMI_HILOGI("Schedule unloading Mouse");
            unloadTimerId_ = TimerMgr->AddLongTimer(DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
                [self]() {
                    self->unloadTimerId_ = -1;
                    self->UnloadMouse();
                }, std::string("UnloadMouse"));
        } else {
            MMI_HILOGI("Mouse existed yet, do not unload");
        }
    } else {
        MMI_HILOGI("Mouse is nullptr");
    }
}

void MouseEventInterface::LoadMouse()
{
    MMI_HILOGI("Start loading Mouse");
    std::shared_ptr<IInputServiceContext> env;
    {
        std::lock_guard guard { mutex_ };
        if (mouse_ != nullptr) {
            MMI_HILOGI("Mouse loaded already");
            return;
        }
        env = env_.lock();
    }
    if (env == nullptr) {
        MMI_HILOGE("No input service context");
        return;
    }
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
    {
        std::lock_guard guard { mutex_ };
        if (mouse_!= nullptr) {
            MMI_HILOGI("Mouse loaded already");
            if (unloadTimerId_ >= 0) {
                TimerMgr->ResetTimer(unloadTimerId_);
            }
            return;
        }
        TimerMgr->RemoveTimer(unloadTimerId_);
        unloadTimerId_ = -1;
    }
    LoadMouse();
    {
        std::lock_guard guard { mutex_ };
        if (mouse_== nullptr) {
            MMI_HILOGE("Load mouse failed");
            return;
        }
        if (!mouse_->HasMouse()) {
            MMI_HILOGI("Schedule unloading Mouse");
            unloadTimerId_ = TimerMgr->AddLongTimer(DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
                [this] () {
                    this->unloadTimerId_ = -1;
                    this->UnloadMouse();
                }, std::string("UnloadMouse"));
        }
    }
}

void MouseEventInterface::OnMouseLoaded()
{
    CALL_INFO_TRACE;
    std::lock_guard guard { mutex_ };
    if (mouse_ == nullptr) {
        MMI_HILOGE("Mouse module not loaded");
        return;
    }
    INPUT_DEV_MGR->ForEachDevice(
        [this](int32_t id, const IInputDeviceManager::IInputDevice &dev) {
            if (dev.IsMouse()) {
                mouse_->OnDeviceAdded(id);
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
} // namespace MMI
} // namespace OHOS