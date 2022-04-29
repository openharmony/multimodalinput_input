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

#include "input_device_manager.h"

#include "key_event_value_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceManager"};
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr int32_t SUPPORT_KEY = 1;

constexpr int32_t ABS_MT_TOUCH_MAJOR = 0x30;
constexpr int32_t ABS_MT_TOUCH_MINOR = 0x31;
constexpr int32_t ABS_MT_ORIENTATION = 0x34;
constexpr int32_t ABS_MT_POSITION_X  = 0x35;
constexpr int32_t ABS_MT_POSITION_Y = 0x36;
constexpr int32_t ABS_MT_PRESSURE = 0x3a;
constexpr int32_t ABS_MT_WIDTH_MAJOR = 0x32;
constexpr int32_t ABS_MT_WIDTH_MINOR = 0x33;

std::list<int32_t> axisType = {
    ABS_MT_TOUCH_MAJOR,
    ABS_MT_TOUCH_MINOR,
    ABS_MT_ORIENTATION,
    ABS_MT_POSITION_X,
    ABS_MT_POSITION_Y,
    ABS_MT_PRESSURE,
    ABS_MT_WIDTH_MAJOR,
    ABS_MT_WIDTH_MINOR,
};
} // namespace

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t id) const
{
    CALL_LOG_ENTER;
    auto iter = inputDevice_.find(id);
    if (iter == inputDevice_.end()) {
        MMI_HILOGE("failed to search for the device");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    CHKPP(inputDevice);
    inputDevice->SetId(iter->first);
    inputDevice->SetType(static_cast<int32_t>(libinput_device_get_tags(iter->second)));
    inputDevice->SetName(libinput_device_get_name(iter->second));
    inputDevice->SetBustype(libinput_device_get_id_bustype(iter->second));
    inputDevice->SetVersion(libinput_device_get_id_version(iter->second));
    inputDevice->SetProduct(libinput_device_get_id_product(iter->second));
    inputDevice->SetVendor(libinput_device_get_id_vendor(iter->second));
    auto phys = libinput_device_get_phys(iter->second);
    inputDevice->SetPhys((phys == nullptr) ? ("null") : (phys));
    auto uniq = libinput_device_get_uniq(iter->second);
    inputDevice->SetUniq((uniq == nullptr) ? ("null") : (uniq));

    InputDevice::AxisInfo axis;
    for (const auto &item : axisType) {
        auto min = libinput_device_get_axis_min(iter->second, item);
        if (min == -1) {
            MMI_HILOGW("The device does not support this axis");
            continue;
        }
        axis.SetAxisType(item);
        axis.SetMinimum(min);
        axis.SetMaximum(libinput_device_get_axis_max(iter->second, item));
        axis.SetFuzz(libinput_device_get_axis_fuzz(iter->second, item));
        axis.SetFlat(libinput_device_get_axis_flat(iter->second, item));
        axis.SetResolution(libinput_device_get_axis_resolution(iter->second, item));
        inputDevice->AddAxisInfo(axis);
    }
    return inputDevice;
}

std::vector<int32_t> InputDeviceManager::GetInputDeviceIds() const
{
    CALL_LOG_ENTER;
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        ids.push_back(item.first);
    }
    return ids;
}

std::vector<bool> InputDeviceManager::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes)
{
    CALL_LOG_ENTER;
    std::vector<bool> keystrokeAbility;
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        keystrokeAbility.insert(keystrokeAbility.end(), keyCodes.size(), false);
        return keystrokeAbility;
    }
    for (const auto& item : keyCodes) {
        auto sysKeyCode = InputTransformationKeyValue(item);
        bool ret = libinput_device_has_key(iter->second, sysKeyCode) == SUPPORT_KEY;
        keystrokeAbility.push_back(ret);
    }
    return keystrokeAbility;
}

void InputDeviceManager::AddDevMonitor(SessionPtr sess, std::function<void(std::string, int32_t)> callback)
{
    CALL_LOG_ENTER;
    auto iter = devMonitor_.find(sess);
    if (iter == devMonitor_.end()) {
        devMonitor_[sess] = callback;
    }
}

void InputDeviceManager::RemoveDevMonitor(SessionPtr sess)
{
    CALL_LOG_ENTER;
    auto iter = devMonitor_.find(sess);
    if (iter == devMonitor_.end()) {
        MMI_HILOGE("session does not exist");
        return;
    }
    devMonitor_.erase(iter);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputDeviceManager::HasPointerDevice()
{
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (IsPointerDevice(it->second)) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void InputDeviceManager::OnInputDeviceAdded(struct libinput_device *inputDevice)
{
    CALL_LOG_ENTER;
    CHKPV(inputDevice);
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_HILOGI("the device already exists");
            return;
        }
    }
    if (nextId_ == INT32_MAX) {
        MMI_HILOGE("the nextId_ exceeded the upper limit");
        return;
    }
    inputDevice_[nextId_] = inputDevice;
    for (const auto &item : devMonitor_) {
        CHKPC(item.first);
        item.second("add", nextId_);
    }
    ++nextId_;

    if (IsPointerDevice(inputDevice)) {
        NotifyPointerDevice(true);
    }
}

void InputDeviceManager::OnInputDeviceRemoved(struct libinput_device *inputDevice)
{
    CALL_LOG_ENTER;
    CHKPV(inputDevice);
    int32_t deviceId = INVALID_DEVICE_ID;
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second == inputDevice) {
            deviceId = it->first;
            inputDevice_.erase(it);
            break;
        }
    }
    for (const auto &item : devMonitor_) {
        CHKPC(item.first);
        item.second("remove", deviceId);
    }
    ScanPointerDevice();
}

void InputDeviceManager::ScanPointerDevice()
{
    bool hasPointerDevice = false;
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (IsPointerDevice(it->second)) {
            hasPointerDevice = true;
            break;
        }
    }
    if (!hasPointerDevice) {
        NotifyPointerDevice(false);
    }
}

bool InputDeviceManager::IsPointerDevice(struct libinput_device* device)
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_HILOGD("udev tag:%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK | 
    EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD);
}

void InputDeviceManager::Attach(std::shared_ptr<IDeviceObserver> observer)
{
    CALL_LOG_ENTER;
    observers_.push_back(observer);
}

void InputDeviceManager::Detach(std::shared_ptr<IDeviceObserver> observer)
{
    CALL_LOG_ENTER;
    observers_.remove(observer);
}

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice)
{
    MMI_HILOGI("observers_ size:%{public}zu", observers_.size());
    for (auto observer = observers_.begin(); observer != observers_.end(); observer++) {
        (*observer)->UpdatePointerDevice(hasPointerDevice);
    }
}

int32_t InputDeviceManager::FindInputDeviceId(struct libinput_device* inputDevice)
{
    CALL_LOG_ENTER;
    CHKPR(inputDevice, INVALID_DEVICE_ID);
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_HILOGI("find input device id success");
            return item.first;
        }
    }
    MMI_HILOGE("find input device id failed");
    return INVALID_DEVICE_ID;
}
} // namespace MMI
} // namespace OHOS
