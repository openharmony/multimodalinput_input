/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input_device_manager.h"

#include <linux/input.h>
#include <regex>

#include "input_event_handler.h"
#include "key_auto_repeat.h"
#ifndef OHOS_BUILD_ENABLE_WATCH
#include "pointer_drawing_manager.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "util_ex.h"
#include "dfx_hisysevent_device.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_DEVICE_ID { -1 };
constexpr int32_t SUPPORT_KEY { 1 };
const char* INPUT_VIRTUAL_DEVICE_NAME { "DistributedInput " };
constexpr int32_t MIN_VIRTUAL_INPUT_DEVICE_ID { 1000 };
constexpr int32_t MAX_VIRTUAL_INPUT_DEVICE_NUM { 128 };
constexpr int32_t COMMON_PARAMETER_ERROR { 401 };

std::unordered_map<int32_t, std::string> axisType{
    { ABS_MT_TOUCH_MAJOR, "TOUCH_MAJOR" }, { ABS_MT_TOUCH_MINOR, "TOUCH_MINOR" }, { ABS_MT_ORIENTATION, "ORIENTATION" },
    { ABS_MT_POSITION_X, "POSITION_X" }, { ABS_MT_POSITION_Y, "POSITION_Y" }, { ABS_MT_PRESSURE, "PRESSURE" },
    { ABS_MT_WIDTH_MAJOR, "WIDTH_MAJOR" }, { ABS_MT_WIDTH_MINOR, "WIDTH_MINOR" }
};

std::vector<std::pair<enum libinput_device_capability, InputDeviceCapability>> devCapEnumMaps{
    { LIBINPUT_DEVICE_CAP_KEYBOARD, InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD },
    { LIBINPUT_DEVICE_CAP_POINTER, InputDeviceCapability::INPUT_DEV_CAP_POINTER },
    { LIBINPUT_DEVICE_CAP_TOUCH, InputDeviceCapability::INPUT_DEV_CAP_TOUCH },
    { LIBINPUT_DEVICE_CAP_TABLET_TOOL, InputDeviceCapability::INPUT_DEV_CAP_TABLET_TOOL },
    { LIBINPUT_DEVICE_CAP_TABLET_PAD, InputDeviceCapability::INPUT_DEV_CAP_TABLET_PAD },
    { LIBINPUT_DEVICE_CAP_GESTURE, InputDeviceCapability::INPUT_DEV_CAP_GESTURE },
    { LIBINPUT_DEVICE_CAP_SWITCH, InputDeviceCapability::INPUT_DEV_CAP_SWITCH },
    { LIBINPUT_DEVICE_CAP_JOYSTICK, InputDeviceCapability::INPUT_DEV_CAP_JOYSTICK },
};

constexpr size_t EXPECTED_N_SUBMATCHES{ 2 };
constexpr size_t EXPECTED_SUBMATCH{ 1 };
} // namespace

std::shared_ptr<InputDeviceManager> InputDeviceManager::instance_ = nullptr;
std::mutex InputDeviceManager::mutex_;

std::shared_ptr<InputDeviceManager> InputDeviceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<InputDeviceManager>();
        }
    }
    return instance_;
}

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t deviceId, bool checked) const
{
    CALL_DEBUG_ENTER;
    if (virtualInputDevices_.find(deviceId) != virtualInputDevices_.end()) {
        MMI_HILOGI("Virtual device with id:%{public}d", deviceId);
        std::shared_ptr<InputDevice> dev = virtualInputDevices_.at(deviceId);
        CHKPP(dev);
        MMI_HILOGI("DeviceId:%{public}d, name:%{public}s", dev->GetId(), dev->GetName().c_str());
        return dev;
    }
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the device");
        return nullptr;
    }
    if (checked && !iter->second.enable) {
        MMI_HILOGE("The current device has been disabled");
        return nullptr;
    }
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetId(iter->first);
    struct libinput_device *inputDeviceOrigin = iter->second.inputDeviceOrigin;
    FillInputDevice(inputDevice, inputDeviceOrigin);

    InputDevice::AxisInfo axis;
    for (const auto &item : axisType) {
        int32_t min = libinput_device_get_axis_min(inputDeviceOrigin, item.first);
        if (min == -1) {
            MMI_HILOGD("The device does not support this axis");
            continue;
        }
        if (item.first == ABS_MT_PRESSURE) {
            axis.SetMinimum(0);
            axis.SetMaximum(1);
        } else {
            axis.SetMinimum(min);
            axis.SetMaximum(libinput_device_get_axis_max(inputDeviceOrigin, item.first));
        }
        axis.SetAxisType(item.first);
        axis.SetFuzz(libinput_device_get_axis_fuzz(inputDeviceOrigin, item.first));
        axis.SetFlat(libinput_device_get_axis_flat(inputDeviceOrigin, item.first));
        axis.SetResolution(libinput_device_get_axis_resolution(inputDeviceOrigin, item.first));
        inputDevice->AddAxisInfo(axis);
    }
    return inputDevice;
}

void InputDeviceManager::FillInputDevice(std::shared_ptr<InputDevice> inputDevice, libinput_device *deviceOrigin) const
{
    CHKPV(inputDevice);
    CHKPV(deviceOrigin);
    inputDevice->SetType(static_cast<int32_t>(libinput_device_get_tags(deviceOrigin)));
    const char *name = libinput_device_get_name(deviceOrigin);
    inputDevice->SetName((name == nullptr) ? ("null") : (name));
    inputDevice->SetBus(libinput_device_get_id_bustype(deviceOrigin));
    inputDevice->SetVersion(libinput_device_get_id_version(deviceOrigin));
    inputDevice->SetProduct(libinput_device_get_id_product(deviceOrigin));
    inputDevice->SetVendor(libinput_device_get_id_vendor(deviceOrigin));
    const char *phys = libinput_device_get_phys(deviceOrigin);
    inputDevice->SetPhys((phys == nullptr) ? ("null") : (phys));
    const char *uniq = libinput_device_get_uniq(deviceOrigin);
    inputDevice->SetUniq((uniq == nullptr) ? ("null") : (uniq));

    for (const auto &[first, second] : devCapEnumMaps) {
        if (libinput_device_has_capability(deviceOrigin, first)) {
            inputDevice->AddCapability(second);
        }
    }
}

std::vector<int32_t> InputDeviceManager::GetInputDeviceIds() const
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        ids.push_back(item.first);
    }
    for (const auto &item : virtualInputDevices_) {
        ids.push_back(item.first);
    }
    return ids;
}

int32_t InputDeviceManager::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes, std::vector<bool> &keystroke)
{
    CALL_DEBUG_ENTER;
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        return COMMON_PARAMETER_ERROR;
    }
    if (!iter->second.enable) {
        MMI_HILOGE("The current device has been disabled");
        return RET_ERR;
    }
    for (const auto &item : keyCodes) {
        bool ret = false;
        for (const auto &it : KeyMapMgr->InputTransferKeyValue(deviceId, item)) {
            ret |= libinput_device_has_key(iter->second.inputDeviceOrigin, it) == SUPPORT_KEY;
        }
        keystroke.push_back(ret);
    }
    return RET_OK;
}

bool InputDeviceManager::IsMatchKeys(struct libinput_device *device, const std::vector<int32_t> &keyCodes) const
{
    CHKPF(device);
    for (const auto &key : keyCodes) {
        int32_t value = InputTransformationKeyValue(key);
        if (libinput_device_keyboard_has_key(device, value) == SUPPORT_KEY) {
            return true;
        }
    }
    return false;
}

bool InputDeviceManager::GetDeviceConfig(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    if (auto iter = inputDevice_.find(deviceId); iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the deviceId");
        return false;
    }
    auto deviceConfig = KeyRepeat->GetDeviceConfig();
    auto it = deviceConfig.find(deviceId);
    if (it == deviceConfig.end()) {
        MMI_HILOGD("Failed to obtain the keyboard type of the configuration file");
        return false;
    }
    keyboardType = it->second.keyboardType;
    MMI_HILOGD("Get keyboard type results from the configuration file:%{public}d", keyboardType);
    return true;
}

int32_t InputDeviceManager::GetKeyboardBusMode(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr dev = GetInputDevice(deviceId);
    CHKPR(dev, ERROR_NULL_POINTER);
    return dev->GetBus();
}

int32_t InputDeviceManager::GetDeviceSupportKey(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_SHIFT_RIGHT);
    keyCodes.push_back(KeyEvent::KEYCODE_F20);
    std::vector<bool> supportKey;
    int32_t ret = SupportKeys(deviceId, keyCodes, supportKey);
    if (ret != RET_OK) {
        MMI_HILOGE("SupportKey call failed");
        return ret;
    }
    std::map<int32_t, bool> determineKbType;
    for (size_t i = 0; i < keyCodes.size(); i++) {
        determineKbType[keyCodes[i]] = supportKey[i];
    }
    if (determineKbType[KeyEvent::KEYCODE_HOME] && GetKeyboardBusMode(deviceId) == BUS_BLUETOOTH) {
        keyboardType = KEYBOARD_TYPE_REMOTECONTROL;
        MMI_HILOGD("The keyboard type is remote control:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_NUMPAD_1] && !determineKbType[KeyEvent::KEYCODE_Q]) {
        keyboardType = KEYBOARD_TYPE_DIGITALKEYBOARD;
        MMI_HILOGD("The keyboard type is digital keyboard:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_Q]) {
        keyboardType = KEYBOARD_TYPE_ALPHABETICKEYBOARD;
        MMI_HILOGD("The keyboard type is standard:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_CTRL_LEFT] && determineKbType[KeyEvent::KEYCODE_SHIFT_RIGHT] &&
        determineKbType[KeyEvent::KEYCODE_F20]) {
        keyboardType = KEYBOARD_TYPE_HANDWRITINGPEN;
        MMI_HILOGD("The keyboard type is handwriting pen:%{public}d", keyboardType);
    } else {
        keyboardType = KEYBOARD_TYPE_UNKNOWN;
        MMI_HILOGD("Undefined keyboard type");
    }
    MMI_HILOGD("Get keyboard type results by supporting keys:%{public}d", keyboardType);
    return RET_OK;
}

int32_t InputDeviceManager::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    auto item = virtualInputDevices_.find(deviceId);
    if (item != virtualInputDevices_.end()) {
        if (!IsKeyboardDevice(item->second)) {
            MMI_HILOGW("Virtual device with id:%{public}d is not keyboard", deviceId);
            keyboardType = KEYBOARD_TYPE_NONE;
            return RET_OK;
        }
        MMI_HILOGI("Virtual device with id:%{public}d, only KEYBOARD_TYPE_ALPHABETICKEYBOARD supported", deviceId);
        keyboardType = KEYBOARD_TYPE_ALPHABETICKEYBOARD;
        return RET_OK;
    }
    int32_t tempKeyboardType = KEYBOARD_TYPE_NONE;
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        MMI_HILOGD("Failed to search for the deviceID");
        return COMMON_PARAMETER_ERROR;
    }
    if (!iter->second.enable) {
        MMI_HILOGE("The current device has been disabled");
        return RET_ERR;
    }
    if (GetDeviceConfig(deviceId, tempKeyboardType)) {
        keyboardType = tempKeyboardType;
        return RET_OK;
    }
    return GetDeviceSupportKey(deviceId, keyboardType);
}

void InputDeviceManager::SetInputStatusChangeCallback(inputDeviceCallback callback)
{
    CALL_DEBUG_ENTER;
    devCallbacks_ = callback;
}

void InputDeviceManager::AddDevListener(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    InitSessionLostCallback();
    devListeners_.push_back(sess);
}

void InputDeviceManager::RemoveDevListener(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    devListeners_.remove(sess);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputDeviceManager::HasPointerDevice()
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.isPointerDevice) {
            return true;
        }
    }
    return false;
}

bool InputDeviceManager::HasVirtualPointerDevice()
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (auto it = virtualInputDevices_.begin(); it != virtualInputDevices_.end(); ++it) {
        if (IsPointerDevice(it->second)) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
bool InputDeviceManager::HasVirtualKeyboardDevice()
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (auto it = virtualInputDevices_.begin(); it != virtualInputDevices_.end(); ++it) {
        if (IsKeyboardDevice(it->second)) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

bool InputDeviceManager::HasTouchDevice()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.isTouchableDevice) {
            return true;
        }
    }
    return false;
}

std::string InputDeviceManager::GetInputIdentification(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    int32_t deviceVendor = libinput_device_get_id_vendor(inputDevice);
    int32_t deviceProduct = libinput_device_get_id_product(inputDevice);
    struct udev_device *udevDevice = libinput_device_get_udev_device(inputDevice);
    std::string sysPath = udev_device_get_syspath(udevDevice);
    udev_device_unref(udevDevice);
    if ((deviceVendor < 0) || (deviceProduct < 0) || sysPath.empty()) {
        MMI_HILOGE("Get device identification failed");
        return "";
    }
    const size_t bufSize = 10;
    char vid[bufSize] = "";
    char pid[bufSize] = "";
    sprintf_s(vid, sizeof(vid), "%04X", deviceVendor);
    sprintf_s(pid, sizeof(pid), "%04X", deviceProduct);
    std::string strVid(vid);
    std::string strPid(pid);
    std::string vendorProduct = strVid + ":" + strPid;
    std::string deviceIdentification = sysPath.substr(0, sysPath.find(vendorProduct)) + vendorProduct;
    MMI_HILOGI("Device identification is:%{public}s", deviceIdentification.c_str());
    return deviceIdentification;
}

void InputDeviceManager::NotifyDevCallback(int32_t deviceId, struct InputDeviceInfo inDevice)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG
    NotifyDevCallbackExt(deviceId, inDevice.inputDeviceOrigin);
#endif // OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG
    if (!inDevice.isTouchableDevice || (deviceId < 0)) {
        MMI_HILOGI("The device is not touchable device already existent");
        return;
    }
    if (!inDevice.sysUid.empty()) {
        devCallbacks_(deviceId, inDevice.sysUid, "add");
        MMI_HILOGI("Send device info to window manager, device id:%{public}d, system uid:%s, status:add",
            deviceId, inDevice.sysUid.c_str());
    } else {
        MMI_HILOGE("Get device system uid id is empty, deviceId:%{public}d", deviceId);
    }
}

int32_t InputDeviceManager::ParseDeviceId(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    std::regex pattern("^event(\\d+)$");
    std::smatch mr;
    const char *sysName = libinput_device_get_sysname(inputDevice);
    CHKPR(sysName, RET_ERR);
    std::string strName(sysName);
    if (std::regex_match(strName, mr, pattern)) {
        if (mr.ready() && mr.size() == EXPECTED_N_SUBMATCHES) {
            return std::stoi(mr[EXPECTED_SUBMATCH].str());
        }
    }
    std::string errStr = "Parsing strName failed: \'" + strName + "\'";
    MMI_HILOGE("%{public}s", errStr.c_str());
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisyseventDeivce::ReportDeviceFault(DfxHisyseventDeivce::DeviceFaultType::DEVICE_FAULT_TYPE_INNER, errStr);
#endif
    return RET_ERR;
}

void InputDeviceManager::OnInputDeviceAdded(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    if (CheckDuplicateInputDevice(inputDevice)) {
        return;
    }
    // if we have enabled physical/virtual pointer before adding this one.
    bool existEnabledPointerDevice = HasEnabledPhysicalPointerDevice();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    // parse virtual devices for pointer devices.
    if (HasVirtualPointerDevice()) {
        existEnabledPointerDevice = true;
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t deviceId = ParseDeviceId(inputDevice);
    if (deviceId < 0) {
        return;
    }
    struct InputDeviceInfo info;
    MakeDeviceInfo(inputDevice, info);
    AddPhysicalInputDeviceInner(deviceId, info);
    MMI_HILOGI("OnInputDeviceAdded successfully, deviceId:%{public}d, info.sysUid:%{public}s, info.enable:%{public}d",
        deviceId, info.sysUid.c_str(), info.enable);
    if (info.enable) {
        NotifyAddDeviceListeners(deviceId);
    }
    NotifyDevCallback(deviceId, info);
    NotifyAddPointerDevice(info.isPointerDevice, existEnabledPointerDevice);
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisyseventDeivce::ReportDeviceBehavior(deviceId, "Device added successfully");
#endif
}

void InputDeviceManager::MakeDeviceInfo(struct libinput_device *inputDevice, struct InputDeviceInfo &info)
{
    info.inputDeviceOrigin = inputDevice;
    info.isRemote = IsRemote(inputDevice);
    info.enable = info.isRemote ? false : true;
    info.isPointerDevice = IsPointerDevice(inputDevice);
    info.isTouchableDevice = IsTouchDevice(inputDevice);
    info.sysUid = GetInputIdentification(inputDevice);
#ifndef OHOS_BUILD_ENABLE_WATCH
    info.vendorConfig = configManagement_.GetVendorConfig(inputDevice);
#endif // OHOS_BUILD_ENABLE_WATCH
}

void InputDeviceManager::OnInputDeviceRemoved(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    int32_t deviceId = INVALID_DEVICE_ID;
    bool enable = false;
    RemovePhysicalInputDeviceInner(inputDevice, deviceId, enable);
    std::string sysUid = GetInputIdentification(inputDevice);
    if (!sysUid.empty()) {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG
        NotifyDevRemoveCallbackExt(deviceId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD_EXT_FLAG  
        CHKPV(devCallbacks_);
        devCallbacks_(deviceId, sysUid, "remove");
        MMI_HILOGI("Send device info to window manager, device id:%{public}d, system uid:%s, status:remove",
            deviceId, sysUid.c_str());
    }

    NotifyRemovePointerDevice(IsPointerDevice(inputDevice));
    if (enable) {
        NotifyRemoveDeviceListeners(deviceId);
    }
    ScanPointerDevice();
    if (deviceId == INVALID_DEVICE_ID) {
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisyseventDeivce::ReportDeviceFault(DfxHisyseventDeivce::DeviceFaultType::DEVICE_FAULT_TYPE_INNER,
                                               "Device reomved failed becaused of not found");
#endif
    }
}

void InputDeviceManager::ScanPointerDevice()
{
    bool existEnabledPointerDevice = HasEnabledPhysicalPointerDevice();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    // parse virtual devices for pointer devices.
    if (HasVirtualPointerDevice()) {
        existEnabledPointerDevice = true;
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (!existEnabledPointerDevice) {
        NotifyPointerDevice(false, false, true);
        OHOS::system::SetParameter(INPUT_POINTER_DEVICES, "false");
        MMI_HILOGI("Set para input.pointer.device false");
    }
}

bool InputDeviceManager::IsPointerDevice(struct libinput_device *device) const
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_HILOGD("The current device udev tag:%{public}d", static_cast<int32_t>(udevTags));
    std::string name = libinput_device_get_name(device);
    if (name == "hw_fingerprint_mouse") {
        return false;
    }
    if (name.find("TouchPad") == std::string::npos) {
        return (udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK |
            EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD)) != 0;
    }
    return (udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK |
        EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD)) != 0;
}

bool InputDeviceManager::IsKeyboardDevice(struct libinput_device *device) const
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_HILOGD("The current device udev tag:%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & EVDEV_UDEV_TAG_KEYBOARD;
}

bool InputDeviceManager::IsTouchDevice(struct libinput_device *device) const
{
    CHKPF(device);
    return libinput_device_has_capability(device, LIBINPUT_DEVICE_CAP_TOUCH);
}

bool InputDeviceManager::IsTouchPadDevice(struct libinput_device *device) const
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    return udevTags & EVDEV_UDEV_TAG_TOUCHPAD;
}

void InputDeviceManager::Attach(std::shared_ptr<IDeviceObserver> observer)
{
    CALL_DEBUG_ENTER;
    observers_.push_back(observer);
}

void InputDeviceManager::Detach(std::shared_ptr<IDeviceObserver> observer)
{
    CALL_DEBUG_ENTER;
    observers_.remove(observer);
}

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice, bool isVisible, bool isHotPlug)
{
    MMI_HILOGI("The observers_ size:%{public}zu", observers_.size());
    for (auto observer = observers_.begin(); observer != observers_.end(); observer++) {
        (*observer)->UpdatePointerDevice(hasPointerDevice, isVisible, isHotPlug);
    }
}

int32_t InputDeviceManager::FindInputDeviceId(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPR(inputDevice, INVALID_DEVICE_ID);
    for (const auto &item : inputDevice_) {
        if (item.second.inputDeviceOrigin == inputDevice) {
            MMI_HILOGD("Find input device id success");
            return item.first;
        }
    }
    MMI_HILOGE("Find input device id failed");
    return INVALID_DEVICE_ID;
}

struct libinput_device *InputDeviceManager::GetKeyboardDevice() const
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    for (const auto &item : inputDevice_) {
        const auto &device = item.second.inputDeviceOrigin;
        if (IsMatchKeys(device, keyCodes)) {
            MMI_HILOGI("Find keyboard device success");
            return device;
        }
    }
    MMI_HILOGW("No keyboard device is currently available");
    return nullptr;
}

void InputDeviceManager::GetMultiKeyboardDevice(std::vector<struct libinput_device*> &inputDevice)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    for (const auto &item : inputDevice_) {
        const auto &device = item.second.inputDeviceOrigin;
        if (IsMatchKeys(device, keyCodes)) {
            MMI_HILOGI("Find keyboard device success id %{public}d", item.first);
            inputDevice.push_back(device);
        }
    }
}

void InputDeviceManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Device information:\t");
    mprintf(fd, "Input devices: count=%zu", inputDevice_.size());
    mprintf(fd, "Virtual input devices: count=%zu", virtualInputDevices_.size());
    std::vector<int32_t> deviceIds = GetInputDeviceIds();
    for (auto deviceId : deviceIds) {
        std::shared_ptr<InputDevice> inputDevice = GetInputDevice(deviceId, false);
        CHKPV(inputDevice);
        mprintf(fd,
            "deviceId:%d | deviceName:%s | deviceType:%d | bus:%d | version:%d "
            "| product:%d | vendor:%d | phys:%s\t",
            inputDevice->GetId(), inputDevice->GetName().c_str(), inputDevice->GetType(), inputDevice->GetBus(),
            inputDevice->GetVersion(), inputDevice->GetProduct(), inputDevice->GetVendor(),
            inputDevice->GetPhys().c_str());
        std::vector<InputDevice::AxisInfo> axisinfo = inputDevice->GetAxisInfo();
        mprintf(fd, "axis: count=%zu", axisinfo.size());
        for (const auto &axis : axisinfo) {
            auto iter = axisType.find(axis.GetAxisType());
            if (iter == axisType.end()) {
                MMI_HILOGE("The axisType is not found");
                return;
            }
            mprintf(fd, "\t axisType:%s | minimum:%d | maximum:%d | fuzz:%d | flat:%d | resolution:%d\t",
                iter->second.c_str(), axis.GetMinimum(), axis.GetMaximum(), axis.GetFuzz(), axis.GetFlat(),
                axis.GetResolution());
        }
    }
}

void InputDeviceManager::DumpDeviceList(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids = GetInputDeviceIds();
    mprintf(fd, "Total device:%zu, Device list:\t", ids.size());
    for (const auto &item : inputDevice_) {
        std::shared_ptr<InputDevice> inputDevice = GetInputDevice(item.first, false);
        CHKPV(inputDevice);
        int32_t deviceId = inputDevice->GetId();
        mprintf(fd, "deviceId:%d | deviceName:%s | deviceType:%d | bus:%d | version:%d | product:%d | vendor:%d\t",
            deviceId, inputDevice->GetName().c_str(), inputDevice->GetType(), inputDevice->GetBus(),
            inputDevice->GetVersion(), inputDevice->GetProduct(), inputDevice->GetVendor());
    }
}

bool InputDeviceManager::IsRemote(struct libinput_device *inputDevice) const
{
    CHKPF(inputDevice);
    bool isRemote = false;
    const char *name = libinput_device_get_name(inputDevice);
    if (name == nullptr || name[0] == '\0') {
        MMI_HILOGD("Device name is empty");
        return false;
    }
    std::string strName = name;
    std::string::size_type pos = strName.find(INPUT_VIRTUAL_DEVICE_NAME);
    if (pos != std::string::npos) {
        isRemote = true;
    }
    MMI_HILOGD("The isRemote:%{public}s", isRemote ? "true" : "false");
    return isRemote;
}

bool InputDeviceManager::IsRemote(int32_t id) const
{
    bool isRemote = false;
    auto device = inputDevice_.find(id);
    if (device != inputDevice_.end()) {
        isRemote = device->second.isRemote;
    }
    MMI_HILOGD("The isRemote:%{public}s", isRemote ? "true" : "false");
    return isRemote;
}

VendorConfig InputDeviceManager::GetVendorConfig(int32_t deviceId) const
{
    CALL_DEBUG_ENTER;
    auto it = inputDevice_.find(deviceId);
    if (it == inputDevice_.end()) {
        MMI_HILOGE("Device info not find id:%{public}d", deviceId);
        return {};
    }
    return it->second.vendorConfig;
}

int32_t InputDeviceManager::OnEnableInputDevice(bool enable)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Enable input device:%{public}s", enable ? "true" : "false");
    for (auto &item : inputDevice_) {
        if (item.second.isRemote && item.second.enable != enable) {
            int32_t keyboardType = KEYBOARD_TYPE_NONE;
            if (enable) {
                item.second.enable = enable;
                GetKeyboardType(item.first, keyboardType);
            } else {
                GetKeyboardType(item.first, keyboardType);
                item.second.enable = enable;
            }
            if (keyboardType != KEYBOARD_TYPE_ALPHABETICKEYBOARD) {
                continue;
            }
            for (const auto& listener : devListeners_) {
                CHKPC(listener);
                NotifyMessage(listener, item.first, enable ? "add" : "remove");
            }
        }
    }
    for (const auto &item : inputDevice_) {
        if (item.second.isPointerDevice && item.second.enable) {
            NotifyPointerDevice(true, true, false);
            break;
        }
    }
    return RET_OK;
}

int32_t InputDeviceManager::AddVirtualInputDevice(std::shared_ptr<InputDevice> device, int32_t &deviceId)
{
    CALL_INFO_TRACE;
    CHKPR(device, RET_ERR);
    if (CheckDuplicateInputDevice(device)) {
        return RET_ERR;
    }
    // if we have enabled physical/virtual pointer before adding this one.
    bool existEnabledPointerDevice = HasEnabledPhysicalPointerDevice();
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    // parse virtual devices for pointer devices.
    if (HasVirtualPointerDevice()) {
        existEnabledPointerDevice = true;
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (GenerateVirtualDeviceId(deviceId) != RET_OK) {
        MMI_HILOGE("GenerateVirtualDeviceId failed");
        deviceId = INVALID_DEVICE_ID;
        return RET_ERR;
    }
    InputDeviceInfo deviceInfo;
    if (MakeVirtualDeviceInfo(device, deviceInfo) != RET_OK) {
        MMI_HILOGE("MakeVirtualDeviceInfo failed");
        return RET_ERR;
    }
    device->SetId(deviceId);
    AddVirtualInputDeviceInner(deviceId, device);
    MMI_HILOGI("AddVirtualInputDevice successfully, deviceId:%{public}d, deviceName=%{public}s",
        deviceId, device->GetName().c_str());

    // in current structure, virtual devices are always enabled.
    NotifyAddDeviceListeners(deviceId);
    NotifyDevCallback(deviceId, deviceInfo);
    NotifyAddPointerDevice(deviceInfo.isPointerDevice, existEnabledPointerDevice);
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisyseventDeivce::ReportDeviceBehavior(deviceId, "AddVirtualInputDevice successfully");
#endif
    return RET_OK;
}

bool InputDeviceManager::CheckDuplicateInputDevice(struct libinput_device *inputDevice)
{
    CHKPF(inputDevice);
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (const auto &item : inputDevice_) {
        if (item.second.inputDeviceOrigin == inputDevice) {
            MMI_HILOGI("The device is already existent");
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
            DfxHisyseventDeivce::ReportDeviceFault(item.first,
                DfxHisyseventDeivce::DeviceFaultType::DEVICE_FAULT_TYPE_INNER,
                "The device is already existent");
#endif
            return true;
        }
    }
    return false;
}

bool InputDeviceManager::CheckDuplicateInputDevice(std::shared_ptr<InputDevice> inputDevice)
{
    CHKPF(inputDevice);
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (const auto &item: virtualInputDevices_) {
        CHKPC(item.second);
        if (item.second->GetName() == inputDevice->GetName()) {
            MMI_HILOGW("The virtual device already exists: %{public}s", inputDevice->GetName().c_str());
            return true;
        }
    }
    return false;
}

void InputDeviceManager::AddPhysicalInputDeviceInner(int32_t deviceId, const struct InputDeviceInfo& info)
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    inputDevice_[deviceId] = info;
}

void InputDeviceManager::AddVirtualInputDeviceInner(int32_t deviceId, std::shared_ptr<InputDevice> inputDevice)
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    virtualInputDevices_[deviceId] = inputDevice;
}

void InputDeviceManager::RemovePhysicalInputDeviceInner(
    struct libinput_device *inputDevice, int32_t &deviceId, bool &enable)
{
    CHKPV(inputDevice);
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.inputDeviceOrigin == inputDevice) {
            deviceId = it->first;
            enable = it->second.enable;
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
            DfxHisyseventDeivce::ReportDeviceBehavior(deviceId, "Device removed successfully");
#endif
            MMI_HILOGI("Device removed successfully, deviceId:%{public}d, sys uid:%{public}s", deviceId,
                it->second.sysUid.c_str());
            inputDevice_.erase(it);
            break;
        }
    }
}

int32_t InputDeviceManager::RemoveVirtualInputDeviceInner(int32_t deviceId, struct InputDeviceInfo& info)
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    auto iter = virtualInputDevices_.find(deviceId);
    if (iter == virtualInputDevices_.end()) {
        MMI_HILOGE("No virtual deviceId:%{public}d existed", deviceId);
        return RET_ERR;
    }
    if (MakeVirtualDeviceInfo(iter->second, info) != RET_OK) {
        MMI_HILOGE("MakeVirtualDeviceInfo failed");
        virtualInputDevices_.erase(iter);
        return RET_ERR;
    }
    virtualInputDevices_.erase(iter);
    return RET_OK;
}

bool InputDeviceManager::HasEnabledPhysicalPointerDevice()
{
    std::lock_guard<std::mutex> guard(inputDeviceMutex_);
    for (const auto &item : inputDevice_) {
        if ((!item.second.isRemote && item.second.isPointerDevice) ||
            (item.second.isRemote && item.second.isPointerDevice && item.second.enable)) {
            MMI_HILOGI("DeviceId:%{public}d, isRemote:%{public}d, sys uid:%{public}s", item.first,
                item.second.isRemote, item.second.sysUid.c_str());
            return true;
        }
    }
    return false;
}

void InputDeviceManager::NotifyAddDeviceListeners(int32_t deviceId)
{
    for (const auto& item : devListeners_) {
        CHKPC(item);
        NotifyMessage(item, deviceId, "add");
    }
}

void InputDeviceManager::NotifyRemoveDeviceListeners(int32_t deviceId)
{
    for (const auto& item : devListeners_) {
        CHKPV(item);
        NotifyMessage(item, deviceId, "remove");
    }
}

void InputDeviceManager::NotifyAddPointerDevice(bool addNewPointerDevice, bool existEnabledPointerDevice)
{
    MMI_HILOGI("AddNewPointerDevice:%{public}d, existEnabledPointerDevice:%{public}d", addNewPointerDevice,
        existEnabledPointerDevice);
    if (addNewPointerDevice && !existEnabledPointerDevice) {
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
        if (HasTouchDevice()) {
            IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
        }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
        NotifyPointerDevice(true, true, true);
        OHOS::system::SetParameter(INPUT_POINTER_DEVICES, "true");
        MMI_HILOGI("Set para input.pointer.device true");
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (addNewPointerDevice) {
        WIN_MGR->UpdatePointerChangeAreas();
    }
    if (addNewPointerDevice && !existEnabledPointerDevice &&
        IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        WIN_MGR->DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

void InputDeviceManager::NotifyRemovePointerDevice(bool removePointerDevice)
{
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (removePointerDevice && !HasPointerDevice() && !HasVirtualPointerDevice() &&
        IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        WIN_MGR->DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t InputDeviceManager::RemoveVirtualInputDevice(int32_t deviceId)
{
    CALL_INFO_TRACE;
    InputDeviceInfo deviceInfo;
    if (RemoveVirtualInputDeviceInner(deviceId, deviceInfo) == RET_ERR) {
        return RET_ERR;
    }
    NotifyDevRemoveCallback(deviceId, deviceInfo);
    MMI_HILOGI("RemoveVirtualInputDevice successfully, deviceId:%{public}d", deviceId);
    NotifyRemovePointerDevice(deviceInfo.isPointerDevice);
    NotifyRemoveDeviceListeners(deviceId);
    ScanPointerDevice();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisyseventDeivce::ReportDeviceBehavior(deviceId, "RemoveVirtualInputDevice successfully");
#endif
    return RET_OK;
}

int32_t InputDeviceManager::MakeVirtualDeviceInfo(std::shared_ptr<InputDevice> device, InputDeviceInfo &deviceInfo)
{
    CALL_INFO_TRACE;
    CHKPR(device, ERROR_NULL_POINTER);
    deviceInfo = {
        .isRemote = false,
        .isPointerDevice = device->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER),
        .isTouchableDevice = device->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_TOUCH),
        .enable = true,
    };
    return RET_OK;
}

int32_t InputDeviceManager::GenerateVirtualDeviceId(int32_t &deviceId)
{
    CALL_INFO_TRACE;
    static int32_t virtualDeviceId { MIN_VIRTUAL_INPUT_DEVICE_ID };
    if (virtualInputDevices_.size() >= MAX_VIRTUAL_INPUT_DEVICE_NUM) {
        MMI_HILOGE("Virtual device num exceeds limit:%{public}d", MAX_VIRTUAL_INPUT_DEVICE_NUM);
        return RET_ERR;
    }
    if (virtualDeviceId == std::numeric_limits<int32_t>::max()) {
        MMI_HILOGW("Request id exceeds the maximum");
        virtualDeviceId = MIN_VIRTUAL_INPUT_DEVICE_ID;
    }
    deviceId = virtualDeviceId++;
    if (virtualInputDevices_.find(deviceId) != virtualInputDevices_.end()) {
        MMI_HILOGE("Repeated deviceId:%{public}d", deviceId);
        deviceId = INVALID_DEVICE_ID;
        return RET_ERR;
    }
    return RET_OK;
}

void InputDeviceManager::NotifyDevRemoveCallback(int32_t deviceId, const InputDeviceInfo &deviceInfo)
{
    CALL_DEBUG_ENTER;
    if (auto sysUid = deviceInfo.sysUid; !sysUid.empty()) {
        devCallbacks_(deviceId, sysUid, "remove");
        MMI_HILOGI("Send device info to window manager, deivceId:%{public}d, status:remove", deviceId);
    }
}

int32_t InputDeviceManager::NotifyMessage(SessionPtr sess, int32_t id, const std::string &type)
{
    CALL_DEBUG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_LISTENER);
    pkt << type << id;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    if (!sess->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
    }
    return RET_OK;
}

void InputDeviceManager::InitSessionLostCallback()
{
    if (sessionLostCallbackInitialized_) {
        MMI_HILOGD("Init session is failed");
        return;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    udsServerPtr->AddSessionDeletedCallback([this] (SessionPtr session) {
        return this->OnSessionLost(session);
    }
    );
    sessionLostCallbackInitialized_ = true;
    MMI_HILOGI("The callback on session deleted is registered successfully");
}

void InputDeviceManager::OnSessionLost(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    RecoverInputDeviceEnabled(session);
    devListeners_.remove(session);
}

std::vector<int32_t> InputDeviceManager::GetTouchPadIds()
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        auto inputDevice = item.second.inputDeviceOrigin;
        if (inputDevice == nullptr) {
            continue;
        }
        enum evdev_device_udev_tags udevTags = libinput_device_get_tags(inputDevice);
        if ((udevTags & EVDEV_UDEV_TAG_TOUCHPAD) != 0) {
            ids.push_back(item.first);
        }
    }
    return ids;
}

std::vector<libinput_device*> InputDeviceManager::GetTouchPadDeviceOrigins()
{
    CALL_DEBUG_ENTER;
    std::vector<libinput_device*> touchPadDevices;
    for (const auto &item : inputDevice_) {
        auto inputDevice = item.second.inputDeviceOrigin;
        if (inputDevice == nullptr) {
            continue;
        }
        enum evdev_device_udev_tags udevTags = libinput_device_get_tags(inputDevice);
        if ((udevTags & EVDEV_UDEV_TAG_TOUCHPAD) != 0) {
            touchPadDevices.push_back(inputDevice);
            continue;
        }
    }
    return touchPadDevices;
}

bool InputDeviceManager::IsPointerDevice(std::shared_ptr<InputDevice> inputDevice) const
{
    CHKPR(inputDevice, false);
    return inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
}

bool InputDeviceManager::IsTouchableDevice(std::shared_ptr<InputDevice> inputDevice) const
{
    CHKPR(inputDevice, false);
    return inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_TOUCH);
}

bool InputDeviceManager::IsKeyboardDevice(std::shared_ptr<InputDevice> inputDevice) const
{
    CHKPR(inputDevice, false);
    return inputDevice->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
}

int32_t InputDeviceManager::NotifyInputdeviceMessage(SessionPtr session, int32_t index, int32_t result)
{
    CALL_DEBUG_ENTER;
    CHKPR(session, ERROR_NULL_POINTER);
    NetPacket pkt(MmiMessageId::SET_INPUT_DEVICE_ENABLED);
    pkt << index << result;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write data failed");
        return RET_ERR;
    }
    if (!session->SendMsg(pkt)) {
        MMI_HILOGE("Sending failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputDeviceManager::SetInputDeviceEnabled(
    int32_t deviceId, bool enable, int32_t index, int32_t pid, SessionPtr session)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("The deviceId:%{public}d, enable:%{public}d, pid:%{public}d", deviceId, enable, pid);
    auto item = inputDevice_.find(deviceId);
    if (item == inputDevice_.end()) {
        NotifyInputdeviceMessage(session, index, ERROR_DEVICE_NOT_EXIST);
        MMI_HILOGD("Set inputDevice enabled failed, Invalid deviceId");
        return RET_ERR;
    }
    item->second.enable = enable;
    if (!enable) {
        MMI_HILOGD("Disable inputdevice, save calling pid:%{public}d to recoverlist", pid);
        recoverList_.insert(std::pair<int32_t, int32_t>(deviceId, pid));
        InitSessionLostCallback();
    }
    NotifyInputdeviceMessage(session, index, RET_OK);
    return RET_OK;
}

void InputDeviceManager::RecoverInputDeviceEnabled(SessionPtr session)
{
    CALL_DEBUG_ENTER;
    CHKPV(session);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto item = recoverList_.begin(); item != recoverList_.end();) {
        if (session->GetPid() == item->second) {
            auto device = inputDevice_.find(item->first);
            if (device != inputDevice_.end()) {
                MMI_HILOGI("Recover input device:%{public}d", item->first);
                device->second.enable = true;
            }
            item = recoverList_.erase(item);
        } else {
            item++;
        }
    }
}

bool InputDeviceManager::IsInputDeviceEnable(int32_t deviceId)
{
    bool enable = false;
    CALL_DEBUG_ENTER;
    auto item = inputDevice_.find(deviceId);
    if (item == inputDevice_.end()) {
        MMI_HILOGD("Get inputDevice enabled failed, Invalid deviceId.");
        return enable;
    }
    enable = item->second.enable;
    return enable;
}

bool InputDeviceManager::IsLocalDevice(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    return (keyEvent->GetDeviceId() >= 0 && keyEvent->GetDeviceId() < MIN_VIRTUAL_INPUT_DEVICE_ID);
}
} // namespace MMI
} // namespace OHOS
