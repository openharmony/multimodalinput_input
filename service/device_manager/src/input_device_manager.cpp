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

#include <linux/input.h>
#include <parameters.h>
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include <openssl/sha.h>
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include <regex>
#include <unordered_map>

#include "dfx_hisysevent.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "input_device_cooperate_sm.h"
#include "input_device_cooperate_util.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "input_windows_manager.h"
#include "key_event_value_transformation.h"
#ifdef OHOS_BUILD_ENABLE_COOPERATE
#include "util.h"
#endif // OHOS_BUILD_ENABLE_COOPERATE
#include "util_ex.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceManager"};
constexpr int32_t INVALID_DEVICE_ID = -1;
constexpr int32_t SUPPORT_KEY = 1;

const std::string UNKNOWN_SCREEN_ID = "";
#ifdef OHOS_BUILD_ENABLE_COOPERATE
const char *SPLIT_SYMBOL = "|";
const std::string DH_ID_PREFIX = "Input_";
#endif // OHOS_BUILD_ENABLE_COOPERATE
const std::string INPUT_VIRTUAL_DEVICE_NAME = "Hos Distributed Virtual Device ";
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

constexpr size_t EXPECTED_N_SUBMATCHES { 2 };
constexpr size_t EXPECTED_SUBMATCH { 1 };
} // namespace

InputDeviceManager::InputDeviceManager() {}
InputDeviceManager::~InputDeviceManager() {}

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
    struct libinput_device *inputDeviceOrigin = iter->second.inputDeviceOrigin;
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
#ifdef OHOS_BUILD_ENABLE_COOPERATE
        if (IsRemote(item.second.inputDeviceOrigin) &&
            InputDevCooSM->GetCurrentCooperateState() == CooperateState::STATE_FREE) {
            MMI_HILOGW("Current device is remote and in STATUS_STATE");
            continue;
        }
#endif // OHOS_BUILD_ENABLE_COOPERATE
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
    for (const auto &item : keyCodes) {
        bool ret = false;
        for (const auto &it : KeyMapMgr->InputTransferKeyValue(deviceId, item)) {
            ret |= libinput_device_has_key(iter->second.inputDeviceOrigin, it) == SUPPORT_KEY;
        }
        keystroke.push_back(ret);
    }
    return RET_OK;
}

bool InputDeviceManager::IsMatchKeys(struct libinput_device* device, const std::vector<int32_t> &keyCodes) const
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

int32_t InputDeviceManager::GetDeviceSupportKey(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    std::vector <int32_t> keyCodes;
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
    } else if (determineKbType[KeyEvent::KEYCODE_CTRL_LEFT] && determineKbType[KeyEvent::KEYCODE_SHIFT_RIGHT]
        && determineKbType[KeyEvent::KEYCODE_F20]) {
        keyboardType = KEYBOARD_TYPE_HANDWRITINGPEN;
        MMI_HILOGD("The keyboard type is handwriting pen:%{public}d", keyboardType);
    } else {
        keyboardType = KEYBOARD_TYPE_UNKNOWN;
        MMI_HILOGW("Undefined keyboard type");
    }
    MMI_HILOGD("Get keyboard type results by supporting keys:%{public}d", keyboardType);
    return RET_OK;
}

int32_t InputDeviceManager::GetKeyboardType(int32_t deviceId, int32_t &keyboardType)
{
    CALL_DEBUG_ENTER;
    int32_t tempKeyboardType = KEYBOARD_TYPE_NONE;
    if (auto iter = inputDevice_.find(deviceId); iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the deviceID");
        return COMMON_PARAMETER_ERROR;
    }
    if (GetDeviceConfig(deviceId, tempKeyboardType)) {
        keyboardType = tempKeyboardType;
        return RET_OK;
    }
    return GetDeviceSupportKey(deviceId, keyboardType);
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
        if (it->second.isPointerDevice) {
            return true;
        }
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

bool InputDeviceManager::HasTouchDevice()
{
    CALL_DEBUG_ENTER;
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.isTouchableDevice) {
            return true;
        }
    }
    return false;
}

int32_t InputDeviceManager::ParseDeviceId(const std::string &sysName)
{
    CALL_DEBUG_ENTER;
    std::regex pattern("^event(\\d+)$");
    std::smatch mr;

    if (std::regex_match(sysName, mr, pattern)) {
        if (mr.ready() && mr.size() == EXPECTED_N_SUBMATCHES) {
            return std::stoi(mr[EXPECTED_SUBMATCH].str());
        }
    }
    return -1;
}

void InputDeviceManager::OnInputDeviceAdded(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    bool hasLocalPointer = false;
    bool hasPointer = false;
    for (const auto &item : inputDevice_) {
        if (item.second.inputDeviceOrigin == inputDevice) {
            MMI_HILOGI("The device is already existent");
            DfxHisysevent::OnDeviceConnect(item.first, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
            return;
        }
        if (item.second.isPointerDevice) {
            hasPointer = true;
            if (!item.second.isRemote) {
                hasLocalPointer = true;
            }
        }
    }

    const char *sysName = libinput_device_get_sysname(inputDevice);
    CHKPV(sysName);
    int32_t deviceId = ParseDeviceId(std::string(sysName));
    if (deviceId < 0) {
        MMI_HILOGE("Parsing sysname failed: \'%{public}s\'", sysName);
        return;
    }

    struct InputDeviceInfo info;
    MakeDeviceInfo(inputDevice, info);
    inputDevice_[deviceId] = info;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (!IsRemote(inputDevice) || InputDevCooSM->GetCurrentCooperateState() != CooperateState::STATE_FREE) {
        for (const auto &item : devListener_) {
            CHKPC(item.first);
            item.second(deviceId, "add");
        }
    }
#else
    for (const auto &item : devListener_) {
        CHKPC(item.first);
        item.second(deviceId, "add");
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE

#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (IsKeyboardDevice(inputDevice)) {
        if (IsRemote(inputDevice)) {
            InputDevCooSM->SetVirtualKeyBoardDevId(deviceId);
        }
        InputDevCooSM->OnKeyboardOnline(info.dhid);
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (!hasPointer && info.isPointerDevice) {
        bool visible = !info.isRemote || hasLocalPointer;
        if (HasTouchDevice()) {
            IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
        }
        NotifyPointerDevice(true, visible);
        OHOS::system::SetParameter(INPUT_POINTER_DEVICE, "true");
        MMI_HILOGI("Set para input.pointer.device true");
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (info.isPointerDevice && !HasPointerDevice() &&
        IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        WinMgr->DispatchPointer(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
#endif // OHOS_BUILD_ENABLE_POINTER
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    DfxHisysevent::OnDeviceConnect(deviceId, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
}

void InputDeviceManager::MakeDeviceInfo(struct libinput_device *inputDevice, struct InputDeviceInfo& info)
{
    info.inputDeviceOrigin = inputDevice;
    info.isRemote = IsRemote(inputDevice);
    info.isPointerDevice = IsPointerDevice(inputDevice);
    info.isTouchableDevice = IsTouchDevice(inputDevice);
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (info.isRemote) {
        info.networkIdOrigin = MakeNetworkId(libinput_device_get_phys(inputDevice));
    }
    info.dhid = GenerateDescriptor(inputDevice, info.isRemote);
#endif // OHOS_BUILD_ENABLE_COOPERATE
}

void InputDeviceManager::OnInputDeviceRemoved(struct libinput_device *inputDevice)
{
    CALL_DEBUG_ENTER;
    CHKPV(inputDevice);
    int32_t deviceId = INVALID_DEVICE_ID;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    struct InputDeviceInfo removedInfo;
    std::vector<std::string> dhids;
#endif // OHOS_BUILD_ENABLE_COOPERATE
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.inputDeviceOrigin == inputDevice) {
            deviceId = it->first;
#ifdef OHOS_BUILD_ENABLE_COOPERATE
            removedInfo = it->second;
            dhids = GetCooperateDhids(deviceId);
#endif // OHOS_BUILD_ENABLE_COOPERATE
            DfxHisysevent::OnDeviceDisconnect(deviceId, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
            inputDevice_.erase(it);
            break;
        }
    }
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (IsPointerDevice(inputDevice) && !HasPointerDevice() &&
        IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
#ifdef OHOS_BUILD_ENABLE_POINTER
        WinMgr->DispatchPointer(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
#endif // OHOS_BUILD_ENABLE_POINTER
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (!IsRemote(inputDevice) || InputDevCooSM->GetCurrentCooperateState() != CooperateState::STATE_FREE) {
        for (const auto &item : devListener_) {
            CHKPC(item.first);
            item.second(deviceId, "remove");
        }
    }
#else
    for (const auto &item : devListener_) {
        CHKPC(item.first);
        item.second(deviceId, "remove");
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    ScanPointerDevice();
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    if (IsPointerDevice(inputDevice)) {
        InputDevCooSM->OnPointerOffline(removedInfo.dhid, removedInfo.networkIdOrigin, dhids);
    }
#endif // OHOS_BUILD_ENABLE_COOPERATE
    if (deviceId == INVALID_DEVICE_ID) {
        DfxHisysevent::OnDeviceDisconnect(INVALID_DEVICE_ID, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    }
}

void InputDeviceManager::ScanPointerDevice()
{
    bool hasPointerDevice = false;
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second.isPointerDevice) {
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
    return libinput_device_has_capability(device, LIBINPUT_DEVICE_CAP_POINTER);
}

bool InputDeviceManager::IsKeyboardDevice(struct libinput_device* device) const
{
    CHKPF(device);
    return libinput_device_has_capability(device, LIBINPUT_DEVICE_CAP_KEYBOARD);
}

bool InputDeviceManager::IsTouchDevice(struct libinput_device* device) const
{
    CHKPF(device);
    return libinput_device_has_capability(device, LIBINPUT_DEVICE_CAP_TOUCH);
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
        if (item.second.inputDeviceOrigin == inputDevice) {
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
        const auto &device = item.second.inputDeviceOrigin;
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

bool InputDeviceManager::IsRemote(struct libinput_device *inputDevice) const
{
    CHKPF(inputDevice);
    bool isRemote = false;
    const char* name = libinput_device_get_name(inputDevice);
    if (name == nullptr || name[0] == '\0') {
        MMI_HILOGD("Device name is empty");
        return false;
    }
    std::string strName = name;
    std::string::size_type pos = strName.find(INPUT_VIRTUAL_DEVICE_NAME);
    if (pos != std::string::npos) {
        isRemote = true;
    }
    MMI_HILOGD("isRemote:%{public}s", isRemote ? "true" : "false");
    return isRemote;
}

bool InputDeviceManager::IsRemote(int32_t id) const
{
    bool isRemote = false;
    auto device = inputDevice_.find(id);
    if (device != inputDevice_.end()) {
        isRemote = device->second.isRemote;
    }
    MMI_HILOGD("isRemote: %{public}s", isRemote == true ? "true" : "false");
    return isRemote;
}
#ifdef OHOS_BUILD_ENABLE_COOPERATE
std::vector<std::string> InputDeviceManager::GetCooperateDhids(int32_t deviceId)
{
    std::vector<std::string> dhids;
    auto iter = inputDevice_.find(deviceId);
    if (iter == inputDevice_.end()) {
        MMI_HILOGI("Find pointer id failed");
        return dhids;
    }
    if (!iter->second.isPointerDevice) {
        MMI_HILOGI("Not pointer device");
        return dhids;
    }
    dhids.push_back(iter->second.dhid);
    MMI_HILOGI("unq: %{public}s, type:%{public}s", dhids.back().c_str(), "pointer");
    auto pointerNetworkId = iter->second.networkIdOrigin;
    std::string localNetworkId = GetLocalDeviceId();
    pointerNetworkId = iter->second.isRemote ? iter->second.networkIdOrigin : localNetworkId;
    for (const auto &item : inputDevice_) {
        auto networkId = item.second.isRemote ? item.second.networkIdOrigin : localNetworkId;
        if (networkId != pointerNetworkId) {
            continue;
        }
        int32_t keyboardType = KEYBOARD_TYPE_NONE;
        if (GetDeviceSupportKey(item.first, keyboardType) != RET_OK) {
            MMI_HILOGI("Get device support key failed");
            return dhids;
        }
        if (keyboardType == KEYBOARD_TYPE_ALPHABETICKEYBOARD) {
            dhids.push_back(item.second.dhid);
            MMI_HILOGI("unq: %{public}s, type:%{public}s", dhids.back().c_str(), "supportkey");
        }
    }
    return dhids;
}

std::vector<std::string> InputDeviceManager::GetCooperateDhids(const std::string &dhid)
{
    int32_t inputDeviceId = INVALID_DEVICE_ID;
    for (const auto &iter : inputDevice_) {
        if (iter.second.dhid == dhid) {
            inputDeviceId = iter.first;
            break;
        }
    }
    return GetCooperateDhids(inputDeviceId);
}

std::string InputDeviceManager::GetOriginNetworkId(int32_t id)
{
    auto iter = inputDevice_.find(id);
    if (iter == inputDevice_.end()) {
        MMI_HILOGE("Failed to search for the device: id %{public}d", id);
        return "";
    }
    auto networkId = iter->second.networkIdOrigin;
    if (networkId.empty()) {
        networkId = GetLocalDeviceId();
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
        if (iter.second.isRemote && iter.second.dhid == dhid) {
            networkId = iter.second.networkIdOrigin;
            break;
        }
    }
    return networkId;
}

std::string InputDeviceManager::GetDhid(int32_t deviceId) const
{
    auto dev = inputDevice_.find(deviceId);
    if (dev != inputDevice_.end()) {
        return dev->second.dhid;
    }
    return "";
}

bool InputDeviceManager::HasLocalPointerDevice() const
{
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (!it->second.isRemote && it->second.isPointerDevice) {
            return true;
        }
    }
    return false;
}

void InputDeviceManager::NotifyVirtualKeyBoardStatus(int32_t deviceId, bool isAvailable) const
{
    MMI_HILOGI("virtual keyboard device %{public}s", isAvailable ? "online" : "offline");
    if (deviceId == -1) {
        MMI_HILOGE("no virtual keyboard device for this device!");
        return;
    }

    for (const auto &item : devListener_) {
        CHKPC(item.first);
        item.second(deviceId, isAvailable ? "add" : "remove");
    }
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
    unsigned char out[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in.data(), in.size());
    SHA256_Final(&out[SHA256_DIGEST_LENGTH], &ctx);
    // here we translate sha256 hash to hexadecimal. each 8-bit char will be presented by two characters([0-9a-f])
    constexpr int32_t WIDTH = 4;
    constexpr unsigned char MASK = 0x0F;
    const char* hexCode = "0123456789abcdef";
    constexpr int32_t DOUBLE_TIMES = 2;
    for (int32_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        unsigned char value = out[SHA256_DIGEST_LENGTH + i];
        // uint8_t is 2 digits in hexadecimal.
        out[i * DOUBLE_TIMES] = hexCode[(value >> WIDTH) & MASK];
        out[i * DOUBLE_TIMES + 1] = hexCode[value & MASK];
    }
    out[SHA256_DIGEST_LENGTH * DOUBLE_TIMES] = 0;
    return reinterpret_cast<char*>(out);
}

std::string InputDeviceManager::GenerateDescriptor(struct libinput_device *inputDevice, bool isRemote) const
{
    const char* physicalPath = libinput_device_get_phys(inputDevice);
    std::string descriptor;
    if (isRemote && physicalPath != nullptr) {
        MMI_HILOGI("physicalPath:%{public}s", physicalPath);
        std::vector<std::string> strList;
        StringSplit(physicalPath, SPLIT_SYMBOL, strList);
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
    }
    if (physicalPath != nullptr) {
        rawDescriptor += "physicalPath:" + std::string(physicalPath);
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
        auto iter = inputDeviceScreens_.find(item->second.dhid);
        if (iter != inputDeviceScreens_.end()) {
            return iter->second;
        }
    }
    MMI_HILOGE("Find input device screen id failed");
#endif // OHOS_BUILD_ENABLE_COOPERATE
    return UNKNOWN_SCREEN_ID;
}
} // namespace MMI
} // namespace OHOS
