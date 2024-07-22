/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "device.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <cstring>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>

#include <openssl/sha.h>
#include <securec.h>

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "fi_log.h"
#include "if_stream_wrap.h"
#include "napi_constants.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "Device"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct Range {
    size_t start { 0 };
    size_t end { 0 };
};

namespace {
constexpr int32_t COMMENT_SUBSCRIPT { 0 };
constexpr ssize_t MAX_FILE_SIZE_ALLOWED { 0x5000 };

const struct Range KEY_BLOCKS[] {
    { KEY_ESC, BTN_MISC },
    { KEY_OK, BTN_DPAD_UP },
    { KEY_ALS_TOGGLE, BTN_TRIGGER_HAPPY }
};
} // namespace

Device::Device(int32_t deviceId)
    : deviceId_(deviceId)
{}

Device::~Device()
{
    Close();
}

int32_t Device::Open()
{
    CALL_DEBUG_ENTER;
    char buf[PATH_MAX] {};
    if (realpath(devPath_.c_str(), buf) == nullptr) {
        FI_HILOGE("Not real path:%{public}s", devPath_.c_str());
        return RET_ERR;
    }

    int32_t nRetries { 6 };
    for (;;) {
        Utility::ShowUserAndGroup();
        Utility::ShowFileAttributes(buf);

        fd_ = open(buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd_ < 0) {
            FI_HILOGE("Open device \'%{public}s\':%{public}s failed", buf, strerror(errno));
            if (nRetries-- > 0) {
                static constexpr int32_t DEFAULT_WAIT_TIME { 500 };
                std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_WAIT_TIME));
                FI_HILOGI("Retry opening the device \'%{public}s\'", buf);
            } else {
                return RET_ERR;
            }
        } else {
            FI_HILOGD("Successful opening \'%{public}s\'", buf);
            break;
        }
    }
    QueryDeviceInfo();
    QuerySupportedEvents();
    UpdateCapability();
    LoadDeviceConfig();
    return RET_OK;
}

void Device::Close()
{
    CALL_DEBUG_ENTER;
    if (fd_ >= 0) {
        if (close(fd_) < 0) {
            FI_HILOGE("Close fd failed, error:%{public}s, fd_:%{public}d", strerror(errno), fd_);
        }
        fd_ = -1;
    }
}

void Device::Dispatch(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        FI_HILOGD("Input data received");
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup, errno:%{public}s", strerror(errno));
    }
}

void Device::QueryDeviceInfo()
{
    CALL_DEBUG_ENTER;
    char buffer[PATH_MAX] = { 0 };
    int32_t rc = ioctl(fd_, EVIOCGNAME(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Could not get device name, errno:%{public}s", strerror(errno));
    } else {
        name_.assign(buffer);
    }

    struct input_id inputId;
    rc = ioctl(fd_, EVIOCGID, &inputId);
    if (rc < 0) {
        FI_HILOGE("Could not get device input id, errno:%{public}s", strerror(errno));
    } else {
        bus_ = inputId.bustype;
        product_ = inputId.product;
        vendor_ = inputId.vendor;
        version_ = inputId.version;
    }

    errno_t ret = memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    if (ret != EOK) {
        FI_HILOGE("Call memset_s failed");
        return;
    }
    rc = ioctl(fd_, EVIOCGPHYS(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Could not get location:%{public}s", strerror(errno));
    } else {
        phys_.assign(buffer);
    }
    ret = memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    if (ret != EOK) {
        FI_HILOGE("Call memset_s failed");
        return;
    }
    rc = ioctl(fd_, EVIOCGUNIQ(sizeof(buffer) - 1), &buffer);
    if (rc < 0) {
        FI_HILOGE("Could not get uniq, errno:%{public}s", strerror(errno));
    } else {
        uniq_.assign(buffer);
    }
}

void Device::GetEventMask(const std::string &eventName, uint32_t type,
    std::size_t arrayLength, uint8_t *whichBitMask) const
{
    int32_t rc = ioctl(fd_, EVIOCGBIT(type, arrayLength), whichBitMask);
    if (rc < 0) {
        FI_HILOGE("Could not get %{public}s events mask:%{public}s", eventName.c_str(), strerror(errno));
    }
}

void Device::GetPropMask(const std::string &eventName, std::size_t arrayLength, uint8_t *whichBitMask) const
{
    int32_t rc = ioctl(fd_, EVIOCGPROP(arrayLength), whichBitMask);
    if (rc < 0) {
        FI_HILOGE("Could not get %{public}s mask:%{public}s", eventName.c_str(), strerror(errno));
    }
}

void Device::QuerySupportedEvents()
{
    CALL_DEBUG_ENTER;
    GetEventMask("", 0, sizeof(evBitmask_), evBitmask_);
    GetEventMask("key", EV_KEY, sizeof(keyBitmask_), keyBitmask_);
    GetEventMask("abs", EV_ABS, sizeof(absBitmask_), absBitmask_);
    GetEventMask("rel", EV_REL, sizeof(relBitmask_), relBitmask_);
    GetPropMask("properties", sizeof(propBitmask_), propBitmask_);
}

void Device::UpdateCapability()
{
    CALL_DEBUG_ENTER;
    CheckPointers();
    CheckPencilMouse();
    CheckKeys();
}

bool Device::HasAxesOrButton(size_t start, size_t end, const uint8_t* whichBitMask) const
{
    for (size_t type = start; type < end; ++type) {
        if (TestBit(type, whichBitMask)) {
            return true;
        }
    }
    return false;
}

bool Device::HasJoystickAxesOrButtons() const
{
    if (!TestBit(BTN_JOYSTICK - 1, keyBitmask_)) {
        if (HasAxesOrButton(BTN_JOYSTICK, BTN_DIGI, keyBitmask_) ||
            // BTN_TRIGGER_HAPPY40 + 1 : loop boundary
            HasAxesOrButton(BTN_TRIGGER_HAPPY1, BTN_TRIGGER_HAPPY40 + 1, keyBitmask_) ||
            HasAxesOrButton(BTN_DPAD_UP, BTN_DPAD_RIGHT + 1, keyBitmask_)) { // BTN_DPAD_RIGHT + 1 : loop boundary
            return true;
        }
    }
    return HasAxesOrButton(ABS_RX, ABS_PRESSURE, absBitmask_);
}

bool Device::HasAbsCoord() const
{
    return (HasAbs(ABS_X) && HasAbs(ABS_Y));
}

bool Device::HasMtCoord() const
{
    return (HasAbs(ABS_MT_POSITION_X) && HasAbs(ABS_MT_POSITION_Y));
}

bool Device::HasRelCoord() const
{
    return (HasRel(REL_X) && HasRel(REL_Y));
}

void Device::PrintCapsDevice() const
{
    const std::map<std::size_t, std::string> deviceComparisonTable {
        { DEVICE_CAP_KEYBOARD, "keyboard" },
        { DEVICE_CAP_TOUCH, "touch device" },
        { DEVICE_CAP_POINTER, "pointer" },
        { DEVICE_CAP_TABLET_TOOL, "tablet tool" },
        { DEVICE_CAP_TABLET_PAD, "pad" },
        { DEVICE_CAP_GESTURE, "gesture" },
        { DEVICE_CAP_SWITCH, "switch" },
        { DEVICE_CAP_JOYSTICK, "joystick" }
    };
    for (const auto &[cap, name]: deviceComparisonTable) {
        if (caps_.test(cap)) {
            FI_HILOGD("This is %{public}s", name.c_str());
        }
    }
}

void Device::CheckPointers()
{
    CALL_DEBUG_ENTER;
    if (HasAbsCoord()) {
        CheckAbs();
    } else {
        CheckJoystick();
    }
    if (HasMtCoord()) {
        CheckMt();
    }
    CheckAdditional();
    PrintCapsDevice();
}

void Device::CheckAbs()
{
    CALL_DEBUG_ENTER;
    if (HasKey(BTN_STYLUS) || HasKey(BTN_TOOL_PEN)) {
        caps_.set(DEVICE_CAP_TABLET_TOOL);
    } else if (HasKey(BTN_TOOL_FINGER) && !HasKey(BTN_TOOL_PEN) && !HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasAxesOrButton(BTN_MOUSE, BTN_JOYSTICK, keyBitmask_)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasKey(BTN_TOUCH) || HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_TOUCH);
    } else if (HasJoystickAxesOrButtons()) {
        caps_.set(DEVICE_CAP_JOYSTICK);
    }
}

void Device::CheckJoystick()
{
    CALL_DEBUG_ENTER;
    if (HasJoystickAxesOrButtons()) {
        caps_.set(DEVICE_CAP_JOYSTICK);
    }
}

void Device::CheckMt()
{
    CALL_DEBUG_ENTER;
    if (HasKey(BTN_STYLUS) || HasKey(BTN_TOOL_PEN)) {
        caps_.set(DEVICE_CAP_TABLET_TOOL);
    } else if (HasKey(BTN_TOOL_FINGER) && !HasKey(BTN_TOOL_PEN) && !HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_POINTER);
    } else if (HasKey(BTN_TOUCH) || HasProperty(INPUT_PROP_DIRECT)) {
        caps_.set(DEVICE_CAP_TOUCH);
    }
}

void Device::CheckAdditional()
{
    CALL_DEBUG_ENTER;
    if (!HasCapability(DEVICE_CAP_TABLET_TOOL) &&
        !HasCapability(DEVICE_CAP_POINTER) &&
        !HasCapability(DEVICE_CAP_JOYSTICK) &&
        HasAxesOrButton(BTN_MOUSE, BTN_JOYSTICK, keyBitmask_) &&
        (HasRelCoord() || !HasAbsCoord())) {
        caps_.set(DEVICE_CAP_POINTER);
    }
}

void Device::CheckPencilMouse()
{
    CALL_DEBUG_ENTER;
    if (name_ == "M-Pencil Mouse") {
        caps_.set(DEVICE_CAP_POINTER, 0);
    }
}

void Device::CheckKeys()
{
    CALL_DEBUG_ENTER;
    if (!TestBit(EV_KEY, evBitmask_)) {
        FI_HILOGD("No EV_KEY capability");
        return;
    }
    size_t length = sizeof(KEY_BLOCKS) / sizeof(struct Range);
    for (size_t block { 0U }; block < length; ++block) {
        for (size_t key = KEY_BLOCKS[block].start; key < KEY_BLOCKS[block].end; ++key) {
            if (TestBit(key, keyBitmask_)) {
                FI_HILOGD("Found key:%{public}zx", key);
                caps_.set(DEVICE_CAP_KEYBOARD);
                return;
            }
        }
    }
}

std::string Device::MakeConfigFileName() const
{
    std::ostringstream ss;
    ss << GetVendor() << "_" << GetProduct() << "_" << GetVersion() << "_" << GetName();
    std::string fname { ss.str() };
    Utility::RemoveSpace(fname);

    std::ostringstream sp;
    sp << "/vendor/etc/keymap/" << fname << ".TOML";
    return sp.str();
}

int32_t Device::ReadConfigFile(const std::string &filePath)
{
    CALL_DEBUG_ENTER;
    char realPath[PATH_MAX] = { 0 };
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        FI_HILOGE("Path is error, path is %{pubilc}s", filePath.c_str());
        return RET_ERR;
    }
    IfStreamWrap cfgFile;
    cfgFile.ifStream = std::ifstream(filePath);
    if (!cfgFile.IsOpen()) {
        FI_HILOGE("Failed to open config file");
        return FILE_OPEN_FAIL;
    }
    std::string tmp;
    while (std::getline(cfgFile.ifStream, tmp)) {
        Utility::RemoveSpace(tmp);
        size_t pos = tmp.find('#');
        if ((pos != tmp.npos) && (pos != COMMENT_SUBSCRIPT)) {
            FI_HILOGE("File format is error");
            return RET_ERR;
        }
        if (tmp.empty() || (tmp.front() == '#')) {
            continue;
        }
        pos = tmp.find('=');
        if (tmp.size() == 0) {
            FI_HILOGE("Invalid size, pos will overflow");
            return RET_ERR;
        } else if ((pos == (tmp.size() - 1)) || (pos == tmp.npos)) {
            FI_HILOGE("Find config item error");
            return RET_ERR;
        }
        std::string configItem = tmp.substr(0, pos);
        std::string value = tmp.substr(pos + 1);
        if (ConfigItemSwitch(configItem, value) == RET_ERR) {
            FI_HILOGE("Configuration item error");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t Device::ConfigItemSwitch(const std::string &configItem, const std::string &value)
{
    CALL_DEBUG_ENTER;
    const std::string CONFIG_ITEM_KEYBOARD_TYPE { "Key.keyboard.type" };
    if (configItem.empty() || value.empty() || !Utility::IsInteger(value)) {
        FI_HILOGE("Invalid configuration encountered");
        return RET_ERR;
    }
    if (configItem == CONFIG_ITEM_KEYBOARD_TYPE) {
        keyboardType_ = static_cast<IDevice::KeyboardType>(stoi(value));
    }
    return RET_OK;
}

int32_t Device::ReadTomlFile(const std::string &filePath)
{
    CALL_DEBUG_ENTER;
    char temp[PATH_MAX] {};
    if (realpath(filePath.c_str(), temp) == nullptr) {
        FI_HILOGE("Not real path (\'%{public}s\'):%{public}s", filePath.c_str(), strerror(errno));
        return RET_ERR;
    }
    FI_HILOGD("Config file path:%{public}s", temp);

    if (!Utility::DoesFileExist(temp)) {
        FI_HILOGE("File does not exist:%{public}s", temp);
        return RET_ERR;
    }
    if (Utility::GetFileSize(temp) > MAX_FILE_SIZE_ALLOWED) {
        FI_HILOGE("File size is out of range");
        return RET_ERR;
    }
    if (ReadConfigFile(std::string(temp)) != RET_OK) {
        FI_HILOGE("ReadConfigFile failed");
        return RET_ERR;
    }
    return RET_OK;
}

void Device::JudgeKeyboardType()
{
    CALL_DEBUG_ENTER;
    if (TestBit(KEY_Q, keyBitmask_)) {
        keyboardType_ = IDevice::KEYBOARD_TYPE_ALPHABETICKEYBOARD;
        FI_HILOGD("The keyboard type is standard");
    } else if (TestBit(KEY_HOME, keyBitmask_) && (GetBus() == BUS_BLUETOOTH)) {
        keyboardType_ = IDevice::KEYBOARD_TYPE_REMOTECONTROL;
        FI_HILOGD("The keyboard type is remote control");
    } else if (TestBit(KEY_KP1, keyBitmask_)) {
        keyboardType_ = IDevice::KEYBOARD_TYPE_DIGITALKEYBOARD;
        FI_HILOGD("The keyboard type is digital keyboard");
    } else if (TestBit(KEY_LEFTCTRL, keyBitmask_) &&
               TestBit(KEY_RIGHTCTRL, keyBitmask_) &&
               TestBit(KEY_F20, keyBitmask_)) {
        keyboardType_ = IDevice::KEYBOARD_TYPE_HANDWRITINGPEN;
        FI_HILOGD("The keyboard type is handwriting pen");
    } else {
        keyboardType_ = IDevice::KEYBOARD_TYPE_UNKNOWN;
        FI_HILOGD("Undefined keyboard type");
    }
}

void Device::LoadDeviceConfig()
{
    CALL_DEBUG_ENTER;
    if (ReadTomlFile(MakeConfigFileName()) != RET_OK) {
        FI_HILOGE("ReadTomlFile failed");
        keyboardType_ = IDevice::KEYBOARD_TYPE_NONE;
    }
    if (IsKeyboard()) {
        if ((keyboardType_ <= IDevice::KEYBOARD_TYPE_NONE) ||
            (keyboardType_ >= IDevice::KEYBOARD_TYPE_MAX)) {
            JudgeKeyboardType();
        }
    } else {
        keyboardType_ = IDevice::KEYBOARD_TYPE_NONE;
    }
    FI_HILOGD("keyboard type:%{public}d", keyboardType_);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
