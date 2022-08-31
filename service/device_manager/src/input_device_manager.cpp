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

#include <parameters.h>
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include <openssl/sha.h>
#include <regex>
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include <unordered_map>
#include "dfx_hisysevent.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_cooperate_sm.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "input_windows_manager.h"
#include "key_event_value_transformation.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "softbus_bus_center.h"
#include "util.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "util_ex.h"

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
constexpr int32_t BUS_BLUETOOTH = 0X5;
const std::string UNKNOWN_SCREEN_ID = "";
#ifdef OHOS_BUILD_ENABLE_COOPERATE
const char *SPLIT_SYMBOL = "|";
const std::string BUNDLE_NAME = "DBinderBus_" + std::to_string(getpid());
const std::string DH_ID_PREFIX = "Input_";
#endif // OHOS_BUILD_ENABLE_COOPERATE

std::unordered_map<int32_t, std::string> axisType = {
    {ABS_MT_TOUCH_MAJOR, "TOUCH_MAJOR"},
    {ABS_MT_TOUCH_MINOR, "TOUCH_MINOR"},
    {ABS_MT_ORIENTATION, "ORIENTATION"},
    {ABS_MT_POSITION_X, "POSITION_X"},
    {ABS_MT_POSITION_Y, "POSITION_Y"},
    {ABS_MT_PRESSURE, "PRESSURE"},
    {ABS_MT_WIDTH_MAJOR, "WIDTH_MAJOR"},
    {ABS_MT_WIDTH_MINOR, "WIDTH_MINOR"}
};
} // namespace

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t id) const
{
    CALL_DEBUG_ENTER;
    auto iter = inputDevice_.find(id);
    if (iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the device");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    CHKPP(inputDevice);
    inputDevice->SetId(iter->first);
    struct libinput_device *inputDeviceOrigin = iter->second.inputDeviceOrigin_;
    inputDevice->SetType(static_cast<int32_t>(libinput_device_get_tags(inputDeviceOrigin)));
    const char* name = libinput_device_get_name(inputDeviceOrigin);
    inputDevice->SetName((name == nullptr) ? ("null") : (name));
    inputDevice->SetBus(libinput_device_get_id_bustype(inputDeviceOrigin));
    inputDevice->SetVersion(libinput_device_get_id_version(inputDeviceOrigin));
    inputDevice->SetProduct(libinput_device_get_id_product(inputDeviceOrigin));
    inputDevice->SetVendor(libinput_device_get_id_vendor(inputDeviceOrigin));
    const char* phys = libinput_device_get_phys(inputDeviceOrigin);
    inputDevice->SetPhys((phys == nullptr) ? ("null") : (phys));
    const char* uniq = libinput_device_get_uniq(inputDeviceOrigin);
    inputDevice->SetUniq((uniq == nullptr) ? ("null") : (uniq));

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

std::vector<int32_t> InputDeviceManager::GetInputDeviceIds() const
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        ids.push_back(item.first);
    }
    return ids;
}

std::vector<bool> InputDeviceManager::SupportKeys(int32_t deviceId, std::vector<int32_t> &keyCodes)
{
    CALL_DEBUG_ENTER;
    std::vector<bool> keystrokeAbility;
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        keystrokeAbility.insert(keystrokeAbility.end(), keyCodes.size(), false);
        return keystrokeAbility;
    }
    for (const auto &item : keyCodes) {
        bool ret = false;
        for (const auto &it : KeyMapMgr->InputTransferKeyValue(deviceId, item)) {
            ret |= libinput_device_has_key(iter->second.inputDeviceOrigin_, it) == SUPPORT_KEY;
        }
        keystrokeAbility.push_back(ret);
    }
    return keystrokeAbility;
}

bool InputDeviceManager::IsMatchKeys(struct libinput_device* device, const std::vector<int32_t> &keyCodes) const
{
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
        MMI_HILOGE("Failed to search for the deviceID");
        return false;
    }
    auto deviceConfig = KeyRepeat->GetDeviceConfig();
    auto it = deviceConfig.find(deviceId);
    if (it == deviceConfig.end()) {
        MMI_HILOGE("Failed to obtain the keyboard type of the configuration file");
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

int32_t InputDeviceManager::GetDeviceSupportKey(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::vector <int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    keyCodes.push_back(KeyEvent::KEYCODE_HOME);
    keyCodes.push_back(KeyEvent::KEYCODE_CTRL_LEFT);
    keyCodes.push_back(KeyEvent::KEYCODE_SHIFT_RIGHT);
    keyCodes.push_back(KeyEvent::KEYCODE_F20);
    std::vector<bool> supportKey = SupportKeys(deviceId, keyCodes);
    std::map<int32_t, bool> determineKbType;
    for (size_t i = 0; i < keyCodes.size(); i++) {
        determineKbType[keyCodes[i]] = supportKey[i];
    }
    int32_t keyboardType = 0;
    if (determineKbType[KeyEvent::KEYCODE_HOME] && GetKeyboardBusMode(deviceId) == BUS_BLUETOOTH) {
        keyboardType = KEYBOARD_TYPE_REMOTECONTROL;
        MMI_HILOGD("The keyboard type is remote control:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_NUMPAD_1] && !determineKbType[KeyEvent::KEYCODE_Q]) {
        keyboardType = KEYBOARD_TYPE_DIGITALKEYBOARD;
        MMI_HILOGD("The keyboard type is digital keyboard:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_Q]) {
        keyboardType = KEYBOARD_TYPE_ALPHABETICKEYBOARD;
        MMI_HILOGD("The keyboard type is standard:%{public}d", keyboardType);
    } else if (determineKbType[KeyEvent::KEYCODE_CTRL_LEFT] && determineKbType[KeyEvent::KEYCODE_SHIFT_RIGHT]
        && determineKbType[KeyEvent::KEYCODE_F20]) {
        keyboardType = KEYBOARD_TYPE_HANDWRITINGPEN;
        MMI_HILOGD("The keyboard type is handwriting pen:%{public}d", keyboardType);
    } else {
        keyboardType = KEYBOARD_TYPE_UNKNOWN;
        MMI_HILOGW("Undefined keyboard type");
    }
    MMI_HILOGD("Get keyboard type results by supporting keys:%{public}d", keyboardType);
    return keyboardType;
}

int32_t InputDeviceManager::GetKeyboardType(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t keyboardType = KEYBOARD_TYPE_NONE;
    if (auto iter = inputDevice_.find(deviceId); iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the deviceID");
        return keyboardType;
    }
    if (GetDeviceConfig(deviceId, keyboardType)) {
        return keyboardType;
    }
    keyboardType = GetDeviceSupportKey(deviceId);
    return keyboardType;
}

void InputDeviceManager::AddDevListener(SessionPtr sess, std::function<void(int32_t, const std::string&)> callback)
{
    CALL_DEBUG_ENTER;
    auto ret = devListener_.insert({ sess, callback });
    if (!ret.second) {
        MMI_HILOGE("Session is duplicated");
        return;
    }
}

void InputDeviceManager::RemoveDevListener(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    auto iter = devListener_.find(sess);
    if (iter == devListener_.end()) {
        MMI_HILOGE("Session does not exist");
        return;
    }
    devListener_.erase(iter);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
bool InputDeviceManager::HasPointerDevice()
{
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (IsPointerDevice(it->second.inputDeviceOrigin_)) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

void InputDeviceManager::OnInputDeviceAdded(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    bool hasLocalPointer = false;
    for (const auto &item : inputDevice_) {
        if (item.second.inputDeviceOrigin_ == inputDevice) {
            MMI_HILOGI("The device is already existent");
            DfxHisysevent::OnDeviceConnect(item.first, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
            return;
        }
        if (!item.second.isRemote_ && IsPointerDevice(item.second.inputDeviceOrigin_)) {
            hasLocalPointer = true;
        }
    }
    if (nextId_ == INT32_MAX) {
        MMI_HILOGE("The nextId_ exceeded the upper limit");
        DfxHisysevent::OnDeviceConnect(INT32_MAX, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
        return;
    }
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (IsPointerDevice(inputDevice) && !HasPointerDevice()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        WinMgr->DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
#endif // OHOS_BUILD_ENABLE_POINTER
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    struct InputDeviceInfo info;
    MakeDeviceInfo(inputDevice, info);
    inputDevice_[nextId_] = info;
    for (const auto &item : devListener_) {
        CHKPC(item.first);
        item.second(nextId_, "add");
    }
    ++nextId_;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (IsKeyboardDevice(inputDevice)) {
        InputDevCooSM->OnKeyboardOnline(info.dhid_);
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    if (IsPointerDevice(inputDevice)) {
        bool visible = !info.isRemote_ || hasLocalPointer;
        NotifyPointerDevice(true, visible);
        OHOS::system::SetParameter(INPUT_POINTER_DEVICE, "true");
        MMI_HILOGI("Set para input.pointer.device true");
    }
    DfxHisysevent::OnDeviceConnect(nextId_ - 1, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
}

void InputDeviceManager::MakeDeviceInfo(struct libinput_device *inputDevice, struct InputDeviceInfo& info)
{
    info.inputDeviceOrigin_ = inputDevice;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    info.isRemote_ = IsRemote(inputDevice);
    if (info.isRemote_) {
        info.networkIdOrigin_ = MakeNetworkId(libinput_device_get_phys(inputDevice));
    }
    info.dhid_ = GenerateDescriptor(inputDevice, info.isRemote_);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

void InputDeviceManager::OnInputDeviceRemoved(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    int32_t deviceId = INVALID_DEVICE_ID;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    OnDInputDeviceRemove(inputDevice);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.inputDeviceOrigin_ == inputDevice) {
            deviceId = it->first;
            DfxHisysevent::OnDeviceDisconnect(deviceId, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
            inputDevice_.erase(it);
            break;
        }
    }
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    if (IsPointerDevice(inputDevice) && !HasPointerDevice()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        WinMgr->DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
#endif // OHOS_BUILD_ENABLE_POINTER
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    for (const auto &item : devListener_) {
        CHKPC(item.first);
        item.second(deviceId, "remove");
    }
    ScanPointerDevice();
    if (deviceId == INVALID_DEVICE_ID) {
        DfxHisysevent::OnDeviceDisconnect(INVALID_DEVICE_ID, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    }
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
void InputDeviceManager::OnDInputDeviceRemove(struct libinput_device *inputDevice)
{
    if (!IsPointerDevice(inputDevice)) {
        return;
    }
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.inputDeviceOrigin_ == inputDevice) {
            std::vector<std::string> dhids =  GetPointerKeyboardDhids(it->first);
            InputDevCooSM->OnPointerOffline(it->second.dhid_, it->second.networkIdOrigin_, dhids);
            break;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_COOPERATE

void InputDeviceManager::ScanPointerDevice()
{
    bool hasPointerDevice = false;
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (IsPointerDevice(it->second.inputDeviceOrigin_)) {
            hasPointerDevice = true;
            break;
        }
    }
    if (!hasPointerDevice) {
        NotifyPointerDevice(false, false);
        OHOS::system::SetParameter(INPUT_POINTER_DEVICE, "false");
        MMI_HILOGI("Set para input.pointer.device false");
    }
}

bool InputDeviceManager::IsPointerDevice(struct libinput_device* device) const
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_HILOGD("The current device udev tag:%{public}d", static_cast<int32_t>(udevTags));
    return (udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK |
    EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD)) != 0;
}

bool InputDeviceManager::IsKeyboardDevice(struct libinput_device* device) const
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_HILOGD("The current device udev tag:%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & EVDEV_UDEV_TAG_KEYBOARD;
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

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice, bool isVisible)
{
    MMI_HILOGI("observers_ size:%{public}zu", observers_.size());
    for (auto observer = observers_.begin(); observer != observers_.end(); observer++) {
        (*observer)->UpdatePointerDevice(hasPointerDevice, isVisible);
    }
}

int32_t InputDeviceManager::FindInputDeviceId(struct libinput_device* inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPR(inputDevice, INVALID_DEVICE_ID);
    for (const auto &item : inputDevice_) {
        if (item.second.inputDeviceOrigin_ == inputDevice) {
            MMI_HILOGI("Find input device id success");
            return item.first;
        }
    }
    MMI_HILOGE("Find input device id failed");
    return INVALID_DEVICE_ID;
}

struct libinput_device* InputDeviceManager::GetKeyboardDevice() const
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> keyCodes;
    keyCodes.push_back(KeyEvent::KEYCODE_Q);
    keyCodes.push_back(KeyEvent::KEYCODE_NUMPAD_1);
    for (const auto &item : inputDevice_) {
        const auto &device = item.second.inputDeviceOrigin_;
        if (IsMatchKeys(device, keyCodes)) {
            MMI_HILOGI("Find keyboard device success");
            return device;
        }
    }
    MMI_HILOGW("No keyboard device is currently available");
    return nullptr;
}

void InputDeviceManager::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Device information:\t");
    mprintf(fd, "Input devices: count=%d", inputDevice_.size());
    for (const auto &item : inputDevice_) {
        std::shared_ptr<InputDevice> inputDevice = GetInputDevice(item.first);
        CHKPV(inputDevice);
        mprintf(fd,
                "deviceId:%d | deviceName:%s | deviceType:%d | bus:%d | version:%d "
                "| product:%d | vendor:%d | phys:%s\t",
                inputDevice->GetId(), inputDevice->GetName().c_str(), inputDevice->GetType(),
                inputDevice->GetBus(), inputDevice->GetVersion(), inputDevice->GetProduct(),
                inputDevice->GetVendor(), inputDevice->GetPhys().c_str());
        std::vector<InputDevice::AxisInfo> axisinfo = inputDevice->GetAxisInfo();
        mprintf(fd, "axis: count=%d", axisinfo.size());
        for (const auto &axis : axisinfo) {
            auto iter = axisType.find(axis.GetAxisType());
            if (iter == axisType.end()) {
                MMI_HILOGE("The axisType is not found");
                return;
            }
            mprintf(fd,
                    "\t axisType:%s | minimum:%d | maximum:%d | fuzz:%d | flat:%d | resolution:%d\t",
                    iter->second.c_str(), axis.GetMinimum(), axis.GetMaximum(), axis.GetFuzz(),
                    axis.GetFlat(), axis.GetResolution());
        }
    }
}

void InputDeviceManager::DumpDeviceList(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> ids = GetInputDeviceIds();
    mprintf(fd, "Total device:%d, Device list:\t", int32_t { ids.size() });
    for (const auto &item : inputDevice_) {
        std::shared_ptr<InputDevice> inputDevice = GetInputDevice(item.first);
        CHKPV(inputDevice);
        int32_t deviceId = inputDevice->GetId();
        mprintf(fd,
                "deviceId:%d | deviceName:%s | deviceType:%d | bus:%d | version:%d | product:%d | vendor:%d\t",
                deviceId, inputDevice->GetName().c_str(), inputDevice->GetType(), inputDevice->GetBus(),
                inputDevice->GetVersion(), inputDevice->GetProduct(), inputDevice->GetVendor());
    }
}

#ifdef OHOS_BUILD_ENABLE_COOPERATE
std::vector<std::string> InputDeviceManager::GetPointerKeyboardDhids(int32_t pointerId)
{
    std::vector<std::string> dhids;
    auto iter = inputDevice_.find(pointerId);
    if (iter == inputDevice_.end()) {
        MMI_HILOGI("Find pointer id failed");
        return dhids;
    }
    if (!IsPointerDevice(iter->second.inputDeviceOrigin_)) {
        MMI_HILOGI("Not pointer device");
        return dhids;
    }
    dhids.push_back(iter->second.dhid_);
    MMI_HILOGI("unq: %{public}s, type:%{public}s", dhids.back().c_str(), "pointer");
    auto pointerNetworkId = iter->second.networkIdOrigin_;
    std::string localNetworkId;
    GetLocalDeviceId(localNetworkId);
    pointerNetworkId = iter->second.isRemote_ ? iter->second.networkIdOrigin_ : localNetworkId;
    for (const auto &item : inputDevice_) {
        auto networkId = item.second.isRemote_ ? item.second.networkIdOrigin_ : localNetworkId;
        if (networkId != pointerNetworkId) {
            continue;
        }
        if (GetDeviceSupportKey(item.first) == KEYBOARD_TYPE_ALPHABETICKEYBOARD) {
            dhids.push_back(item.second.dhid_);
            MMI_HILOGI("unq: %{public}s, type:%{public}s", dhids.back().c_str(), "supportkey");
        }
    }
    return dhids;
}

std::vector<std::string> InputDeviceManager::GetPointerKeyboardDhids(const std::string &dhid)
{
    int32_t pointerId = -1;
    for (const auto &iter : inputDevice_) {
        if (iter.second.dhid_ == dhid) {
            pointerId = iter.first;
            break;
        }
    }
    return GetPointerKeyboardDhids(pointerId);
}

std::string InputDeviceManager::GetOriginNetworkId(int32_t id)
{
    auto iter = inputDevice_.find(id);
    if (iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the device: id %{public}d", id);
        return "";
    }
    auto networkId = iter->second.networkIdOrigin_;
    if (networkId.empty()) {
        GetLocalDeviceId(networkId);
    }
    return networkId;
}

std::string InputDeviceManager::GetOriginNetworkId(const std::string &dhid)
{
    if (dhid.empty()) {
        return "";
    }
    std::string networkId;
    for (const auto &iter : inputDevice_) {
        if (iter.second.dhid_ == dhid) {
            networkId = iter.second.networkIdOrigin_;
            if (networkId.empty()) {
                GetLocalDeviceId(networkId);
                break;
            }
        }
    }
    return networkId;
}

void InputDeviceManager::GetLocalDeviceId(std::string &local)
{
    local = "";
    auto localNode = std::make_unique<NodeBasicInfo>();
    CHKPV(localNode);
    int32_t errCode = GetLocalNodeDeviceInfo(BUNDLE_NAME.c_str(), localNode.get());
    if (errCode != RET_OK) {
        MMI_HILOGE("GetLocalNodeDeviceInfo errCode: %{public}d", errCode);
        return;
    }
    local = localNode->networkId;
}

std::string InputDeviceManager::GetDhid(int32_t deviceId) const
{
    auto dev = inputDevice_.find(deviceId);
    if (dev != inputDevice_.end()) {
        return dev->second.dhid_;
    }
    return "";
}

bool InputDeviceManager::HasLocalPointerDevice() const
{
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (!it->second.isRemote_ && IsPointerDevice(it->second.inputDeviceOrigin_)) {
            return true;
        }
    }
    return false;
}

bool InputDeviceManager::IsRemote(struct libinput_device *inputDevice) const
{
    CHKPR(inputDevice, false);
    bool isRemote = false;
    const char* name = libinput_device_get_name(inputDevice);
    if (name == nullptr || name[0] == '\0') {
        return false;
    }
    std::string strName = name;
    std::string::size_type pos = strName.find(VIRTUAL_DEVICE_NAME);
    if (pos != std::string::npos) {
        isRemote = true;
    }
    MMI_HILOGD("isRemote: %{public}s", isRemote == true ? "true" : "false");
    return isRemote;
}

bool InputDeviceManager::IsRemote(int32_t id) const
{
    bool isRemote = false;
    auto device = inputDevice_.find(id);
    if (device != inputDevice_.end()) {
        isRemote = device->second.isRemote_;
    }
    MMI_HILOGD("isRemote: %{public}s", isRemote == true ? "true" : "false");
    return isRemote;
}

std::string InputDeviceManager::MakeNetworkId(const char *phys) const
{
    std::string networkId;
    if (phys == nullptr || phys[0] == '\0') {
        return networkId;
    }
    std::string strPhys = phys;
    std::vector<std::string> strList;
    StringSplit(strPhys, SPLIT_SYMBOL, strList);
    if (strList.size() == 3) {
        networkId = strList[1];
    }
    return networkId;
}

std::string InputDeviceManager::Sha256(const std::string &in) const
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, reinterpret_cast<const u_char *>(in.c_str()), in.size());
    u_char digest[SHA_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);

    std::string out;
    for (size_t i = 0; i < SHA_DIGEST_LENGTH; i++) {
        out += StringPrintf("%02x", digest[i]);
    }
    return out;
}

std::string InputDeviceManager::GenerateDescriptor(struct libinput_device *inputDevice, bool isRemote) const
{
    const char* location = libinput_device_get_phys(inputDevice);
    std::string descriptor;
    if (isRemote && location != nullptr) {
        MMI_HILOGI("location:%{public}s", location);
        std::vector<std::string> strList;
        StringSplit(location, SPLIT_SYMBOL, strList);
        if (strList.size() == 3) {
            descriptor = strList[2];
        }
        return descriptor;
    }

    uint16_t vendor = libinput_device_get_id_vendor(inputDevice);
    const char* name = libinput_device_get_name(inputDevice);
    const char* uniqueId = libinput_device_get_uniq(inputDevice);
    uint16_t product = libinput_device_get_id_product(inputDevice);
    std::string rawDescriptor;
    rawDescriptor += StringPrintf(":%04x:%04x:", vendor, product);
    // add handling for USB devices to not uniqueify kbs that show up twice
    if (uniqueId != nullptr && uniqueId[0] != '\0') {
        rawDescriptor += "uniqueId:" + std::string(uniqueId);
    } else if (location != nullptr) {
        rawDescriptor += "location:" + std::string(location);
    }
    if (name != nullptr && name[0] != '\0') {
        rawDescriptor += "name:" + regex_replace(name, std::regex(" "), "");
    }
    descriptor = DH_ID_PREFIX + Sha256(rawDescriptor);
    MMI_HILOGI("Created descriptor raw: %{public}s", rawDescriptor.c_str());
    return descriptor;
}
#endif // OHOS_BUILD_ENABLE_COOPERATE
int32_t InputDeviceManager::SetInputDevice(const std::string& dhid, const std::string& screenId)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (dhid.empty()) {
        MMI_HILOGE("hdid is empty");
        return RET_ERR;
    }
    if (screenId.empty()) {
        MMI_HILOGE("screenId is empty");
        return RET_ERR;
    }
    inputDeviceScreens_[dhid] = screenId;
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return RET_OK;
}

const std::string& InputDeviceManager::GetScreenId(int32_t deviceId) const
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    auto item = inputDevice_.find(deviceId);
    if (item != inputDevice_.end()) {
        auto iter = inputDeviceScreens_.find(item->second.dhid_);
        if (iter != inputDeviceScreens_.end()) {
            return iter->second;
        }
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    MMI_HILOGE("Find input device screen id failed");
    return UNKNOWN_SCREEN_ID;
}
} // namespace MMI
} // namespace OHOS
