/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h>

#include <libudev.h>
#include <linux/input.h>

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MmiLibudev"

using namespace std::literals;
namespace {
constexpr int UTIL_PATH_SIZE { 1024 };
constexpr int UTIL_LINE_SIZE { 16384 };

bool StartsWith(std::string_view str, std::string_view prefix)
{
    return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

bool ChopTail(std::string_view &str, char sep)
{
    auto pos = str.rfind(sep);
    if (pos == std::string_view::npos) {
        return false;
    }
    str.remove_suffix(str.size() - pos);
    return true;
}

std::string ResolveSymLink(const std::string &syspath)
{
    constexpr auto backStr = "../"sv;
    char linkTarget[UTIL_PATH_SIZE];

    ssize_t len = readlink(syspath.c_str(), linkTarget, sizeof(linkTarget));
    if (len <= 0 || len == static_cast<ssize_t>(sizeof(linkTarget))) {
        return syspath;
    }

    std::string_view tail{ linkTarget, len };
    int32_t back = 0;
    for (; StartsWith(tail, backStr); back++) {
        tail.remove_prefix(backStr.size());
    }

    std::string_view base = syspath;
    for (int32_t i = 0; i <= back; i++) {
        if (!ChopTail(base, '/')) {
            return syspath;
        }
    }

    return std::string{ base }.append("/").append(tail);
}

std::optional<std::string> GetLinkValue(const std::string &slink, const std::string &syspath)
{
    auto path = syspath + "/" + slink;

    char target[UTIL_PATH_SIZE];
    ssize_t len = readlink(path.c_str(), target, sizeof(target));
    if (len <= 0 || len == static_cast<ssize_t>(sizeof(target))) {
        MMI_HILOGE("Failed to read link");
        return std::nullopt;
    }

    std::string_view result{ target, len };
    auto pos = result.rfind('/');
    if (pos == std::string_view::npos) {
        MMI_HILOGE("Failed to get link value");
        return std::nullopt;
    }
    return std::string{ result.substr(pos + 1) };
}

class BitVector {
public:
    // This type depends on kernel definition
    using val_t = unsigned long;

    // Input string is hexadecimal 64-bit numbers separated by spaces with high bit number first
    explicit BitVector(const std::string &str)
    {
        std::istringstream ss{ str };
        ss >> std::hex;
        std::copy(std::istream_iterator<val_t>(ss), std::istream_iterator<val_t>(), std::back_inserter(bits_));
        // Since numbers in string starts with high number we need to reverse vector to count numbers from low to high
        std::reverse(bits_.begin(), bits_.end());
    }

    [[nodiscard]] bool CheckBit(size_t idx) const
    {
        auto vidx = idx / (sizeof(val_t) * CHAR_BIT);
        auto bidx = idx % (sizeof(val_t) * CHAR_BIT);
        if (vidx >= bits_.size()) {
            return false;
        }
        return (bits_[vidx] & (1ULL << bidx)) != 0;
    }

private:
    std::vector<val_t> bits_;
};
} // namespace

struct udev {};

struct udev_device {
public:
    // Not copyable and not movable
    udev_device(udev_device &) = delete;
    udev_device(udev_device &&) = delete;
    udev_device &operator = (udev_device &) = delete;
    udev_device &operator = (udev_device &&) = delete;

    static udev_device *NewFromSyspath(const std::string &syspathParam)
    {
        // path starts in sys
        if (!StartsWith(syspathParam, "/sys/") || syspathParam.back() == '/') {
            errno = EINVAL;
            return nullptr;
        }

        // resolve possible symlink to real path
        std::string path = ResolveSymLink(syspathParam);
        if (StartsWith(path, "/sys/devices/")) {
            // all "devices" require a "uevent" file
            struct stat statbuf;
            std::string filename = path + "/uevent";
            if (stat(filename.c_str(), &statbuf) != 0) {
                return nullptr;
            }
        } else {
            return nullptr;
        }

        auto *inst = new udev_device;
        inst->SetSyspath(std::move(path));

        return inst;
    }

    static udev_device *NewFromDevnum(char type, dev_t devnum)
    {
        const char *typeStr = nullptr;

        if (type == 'b') {
            typeStr = "block";
        } else if (type == 'c') {
            typeStr = "char";
        } else {
            MMI_HILOGE("Param invalid");
            errno = EINVAL;
            return nullptr;
        }

        // use /sys/dev/{block,char}/<maj>:<min> link
        auto majStr = std::to_string(major(devnum));
        auto minStr = std::to_string(minor(devnum));
        return NewFromSyspath("/sys/dev/"s + typeStr + "/" + majStr + ":" + minStr);
    }

    void Ref()
    {
        refcount++;
    }

    void Unref()
    {
        if (--refcount <= 0) {
            delete this;
        }
    }

    udev_device *GetParent()
    {
        if (!parentDevice_.has_value()) {
            parentDevice_ = NewFromChild(this);
        }
        return *parentDevice_;
    }

    const std::string &GetSyspath() const
    {
        return syspath;
    }

    const std::string &GetSysname() const
    {
        return sysname;
    }

    const std::string &GetDevnode()
    {
        return GetProperty("DEVNAME");
    }

    bool IsInitialized()
    {
        if (!ueventLoaded) {
            ReadUeventFile();
        }
        return ueventLoaded;
    }

    udev_device *GetParentWithSubsystem(const std::string &subsystem)
    {
        udev_device *parent = GetParent();
        while (parent != nullptr) {
            auto parentSubsystem = parent->GetSubsystem();
            if (parentSubsystem.has_value() && parentSubsystem.value() == subsystem) {
                break;
            }
            parent = parent->GetParent();
        }

        if (parent == nullptr) {
            errno = ENOENT;
        }
        return parent;
    }

    bool HasProperty(const std::string &key)
    {
        if (!ueventLoaded) {
            ReadUeventFile();
        }
        return property_.find(key) != property_.end();
    }

    const std::string &GetProperty(const std::string &key)
    {
        if (!ueventLoaded) {
            ReadUeventFile();
        }
        return property_[key];
    }

private:
    udev_device() = default;

    ~udev_device()
    {
        if (parentDevice_.has_value() && parentDevice_.value() != nullptr) {
            parentDevice_.value()->Unref();
        }
    }

    static udev_device *NewFromChild(udev_device *child)
    {
        std::string_view path = child->GetSyspath();

        while (true) {
            if (!ChopTail(path, '/')) {
                break;
            }
            udev_device *parent = NewFromSyspath(std::string{ path });
            if (parent != nullptr) {
                return parent;
            }
        }

        return nullptr;
    }

    void SetSyspath(std::string newSyspath)
    {
        syspath = std::move(newSyspath);

        AddProperty("DEVPATH", syspath.substr(0, "/sys"sv.size()));

        auto pos = syspath.rfind('/');
        if (pos == std::string::npos) {
            return;
        }
        sysname = syspath.substr(pos + 1);

        // some devices have '!' in their name, change that to '/'
        for (char &c : sysname) {
            if (c == '!') {
                c = '/';
            }
        }
    }

    void AddPropertyFromString(const std::string &line)
    {
        auto pos = line.find('=');
        if (pos == std::string::npos) {
            return;
        }
        std::string key = line.substr(0, pos);
        if (key == "DEVNAME") {
            SetDevnode(line.substr(pos + 1));
            return;
        }
        AddProperty(std::move(key), line.substr(pos + 1));
    }

    void ReadUeventFile()
    {
        if (ueventLoaded) {
            return;
        }

        auto filename = syspath + "/uevent";
        char realPath[PATH_MAX] = {};
        CHKPV(realpath(filename.c_str(), realPath));
        std::ifstream f(realPath, std::ios_base::in);
        if (!f.is_open()) {
            MMI_HILOGE("ReadUeventFile(): path:%{public}s, error:%{public}s", realPath, std::strerror(errno));
            return;
        }
        ueventLoaded = true;

        char line[UTIL_LINE_SIZE];
        while (f.getline(line, sizeof(line))) {
            AddPropertyFromString(line);
        }

        CheckInputProperties();
    }

    bool CheckAccel(const BitVector &ev, const BitVector &abs, const BitVector &prop)
    {
        bool hasKeys = ev.CheckBit(EV_KEY);
        bool has3dCoordinates = abs.CheckBit(ABS_X) && abs.CheckBit(ABS_Y) && abs.CheckBit(ABS_Z);
        bool isAccelerometer = prop.CheckBit(INPUT_PROP_ACCELEROMETER);

        if (!hasKeys && has3dCoordinates) {
            isAccelerometer = true;
        }

        if (isAccelerometer) {
            SetInputProperty("ID_INPUT_ACCELEROMETER");
        }
        return isAccelerometer;
    }

    bool HasJoystickAxesOrButtons(const BitVector &abs, const BitVector &key)
    {
        bool hasJoystickAxesOrButtons = false;
        // Some mouses have so much buttons that they overflow in joystick range, ignore them
        if (!key.CheckBit(BTN_JOYSTICK - 1)) {
            for (int32_t button = BTN_JOYSTICK; button < BTN_DIGI && !hasJoystickAxesOrButtons; button++) {
                hasJoystickAxesOrButtons = key.CheckBit(button);
            }
            for (int32_t button = BTN_TRIGGER_HAPPY1; button <= BTN_TRIGGER_HAPPY40 && !hasJoystickAxesOrButtons;
                button++) {
                hasJoystickAxesOrButtons = key.CheckBit(button);
            }
            for (int32_t button = BTN_DPAD_UP; button <= BTN_DPAD_RIGHT && !hasJoystickAxesOrButtons; button++) {
                hasJoystickAxesOrButtons = key.CheckBit(button);
            }
        }
        for (int32_t axis = ABS_RX; axis < ABS_PRESSURE && !hasJoystickAxesOrButtons; axis++) {
            hasJoystickAxesOrButtons = abs.CheckBit(axis);
        }
        return hasJoystickAxesOrButtons;
    }

    bool CheckPointingStick(const BitVector &prop)
    {
        if (prop.CheckBit(INPUT_PROP_POINTING_STICK)) {
            SetInputProperty("ID_INPUT_POINTINGSTICK");
            return true;
        }
        return false;
    }

    void CheckAndSetProp(std::string prop, const bool &flag)
    {
        if (flag) {
            SetInputProperty(prop);
            MMI_HILOGD("device has prop with %{public}s", prop.c_str());
        }
    }

    void CheckMouseButton(const BitVector &key, bool &flag)
    {
        for (int32_t button = BTN_MOUSE; button < BTN_JOYSTICK && !flag; button++) {
            flag = key.CheckBit(button);
        }
    }

    void UpdateProByKey(const BitVector &key, const bool &isDirect, bool &probablyTablet, bool &probablyTouchpad,
        bool &probablyTouchscreen)
    {
        probablyTablet = key.CheckBit(BTN_STYLUS) || key.CheckBit(BTN_TOOL_PEN);
        probablyTouchpad = key.CheckBit(BTN_TOOL_FINGER) && !key.CheckBit(BTN_TOOL_PEN) && !isDirect;
        probablyTouchscreen = key.CheckBit(BTN_TOUCH) && isDirect;
    }

    bool CheckMtCoordinates(const BitVector &abs)
    {
        bool hasMtCoordinates = abs.CheckBit(ABS_MT_POSITION_X) && abs.CheckBit(ABS_MT_POSITION_Y);
        /* unset hasMtCoordinates if devices claims to have all abs axis */
        if (hasMtCoordinates && abs.CheckBit(ABS_MT_SLOT) && abs.CheckBit(ABS_MT_SLOT - 1)) {
            hasMtCoordinates = false;
        }
        return hasMtCoordinates;
    }

    void UpdateProByStatus(const bool &isMouse, const bool &isTouchpad, const bool &isTouchscreen,
        const bool &isJoystick, const bool &isTablet)
    {
        CheckAndSetProp("ID_INPUT_MOUSE", isMouse);
        CheckAndSetProp("ID_INPUT_TOUCHPAD", isTouchpad);
        CheckAndSetProp("ID_INPUT_TOUCHSCREEN", isTouchscreen);
        CheckAndSetProp("ID_INPUT_JOYSTICK", isJoystick);
        CheckAndSetProp("ID_INPUT_TABLET", isTablet);
    }

    bool CheckPointers(const BitVector &ev, const BitVector &abs, const BitVector &key, const BitVector &rel,
        const BitVector &prop)
    {
        bool isDirect = prop.CheckBit(INPUT_PROP_DIRECT);
        bool hasAbsCoordinates = abs.CheckBit(ABS_X) && abs.CheckBit(ABS_Y);
        bool hasRelCoordinates = ev.CheckBit(EV_REL) && rel.CheckBit(REL_X) && rel.CheckBit(REL_Y);
        bool hasMtCoordinates = CheckMtCoordinates(abs);

        bool hasMouseButton = false;
        CheckMouseButton(key, hasMouseButton);

        bool probablyTablet;
        bool probablyTouchpad;
        bool probablyTouchscreen;
        UpdateProByKey(key, isDirect, probablyTablet, probablyTouchpad, probablyTouchscreen);
        bool probablyJoystick = HasJoystickAxesOrButtons(abs, key);

        bool isTablet = false;
        bool isMouse = false;
        bool isTouchpad = false;
        bool isTouchscreen = false;
        bool isJoystick = false;
        if (hasAbsCoordinates) {
            if (probablyTablet) {
                isTablet = true;
            } else if (probablyTouchpad) {
                isTouchpad = true;
            } else if (hasMouseButton) {
                /* This path is taken by VMware's USB mouse, which has
                 * absolute axes, but no touch/pressure button. */
                isMouse = true;
            } else if (probablyTouchscreen) {
                isTouchscreen = true;
            } else {
                isJoystick = probablyJoystick;
            }
        } else {
            isJoystick = probablyJoystick;
        }

        if (hasMtCoordinates) {
            if (probablyTablet) {
                isTablet = true;
            } else if (probablyTouchpad) {
                isTouchpad = true;
            } else if (probablyTouchscreen) {
                isTouchscreen = true;
            }
        }

        /* mouse buttons and no axis */
        if (!isTablet && !isTouchpad && !isJoystick && hasMouseButton && (hasRelCoordinates || !hasAbsCoordinates)) {
            isMouse = true;
        }

        UpdateProByStatus(isMouse, isTouchpad, isTouchscreen, isJoystick, isTablet);

        return isTablet || isMouse || isTouchpad || isTouchscreen || isJoystick || CheckPointingStick(prop);
    }

    bool CheckKeys(const BitVector &ev, const BitVector &key)
    {
        if (!ev.CheckBit(EV_KEY)) {
            return false;
        }

        /* only consider KEY_* here, not BTN_* */
        bool found = false;
        for (int32_t i = 0; i < BTN_MISC && !found; ++i) {
            found = key.CheckBit(i);
        }
        /* If there are no keys in the lower block, check the higher blocks */
        for (int32_t i = KEY_OK; i < BTN_DPAD_UP && !found; ++i) {
            found = key.CheckBit(i);
        }
        for (int32_t i = KEY_ALS_TOGGLE; i < BTN_TRIGGER_HAPPY && !found; ++i) {
            found = key.CheckBit(i);
        }

        if (found) {
            SetInputProperty("ID_INPUT_KEY");
        }

        /* the first 32 bits are ESC, numbers, and Q to D; if we have all of
         * those, consider it a full keyboard; do not test KEY_RESERVED, though */
        bool isKeyboard = true;
        for (int32_t i = KEY_ESC; i < KEY_D && isKeyboard; i++) {
            isKeyboard = key.CheckBit(i);
        }
        if (isKeyboard) {
            SetInputProperty("ID_INPUT_KEYBOARD");
        }

        return found || isKeyboard;
    }

    void SetInputProperty(std::string prop)
    {
        AddProperty("ID_INPUT", "1");
        AddProperty(std::move(prop), "1");
    }

    void CheckInputProperties()
    {
        BitVector ev{ GetProperty("EV") };
        BitVector abs{ GetProperty("ABS") };
        BitVector key{ GetProperty("KEY") };
        BitVector rel{ GetProperty("REL") };
        BitVector prop{ GetProperty("PROP") };

        bool isPointer = CheckAccel(ev, abs, prop) || CheckPointers(ev, abs, key, rel, prop);
        bool isKey = CheckKeys(ev, key);
        /* Some evdev nodes have only a scrollwheel */
        if (!isPointer && !isKey && ev.CheckBit(EV_REL) && (rel.CheckBit(REL_WHEEL) || rel.CheckBit(REL_HWHEEL))) {
            SetInputProperty("ID_INPUT_KEY");
        }
        if (ev.CheckBit(EV_SW)) {
            SetInputProperty("ID_INPUT_SWITCH");
        }
    }

    void SetDevnode(std::string newDevnode)
    {
        if (newDevnode[0] != '/') {
            newDevnode = "/dev/" + newDevnode;
        }
        AddProperty("DEVNAME", std::move(newDevnode));
    }

    void AddProperty(std::string key, std::string value)
    {
        property_[std::move(key)] = std::move(value);
    }

    std::optional<std::string> GetSubsystem()
    {
        if (!subsystem_.has_value()) {
            auto res = GetLinkValue("subsystem", syspath);
            // read "subsystem" link
            if (res.has_value()) {
                SetSubsystem(std::move(*res));
                return subsystem_;
            }
            subsystem_ = "";
        }
        return subsystem_;
    }

    void SetSubsystem(std::string newSubsystem)
    {
        subsystem_ = newSubsystem;
        AddProperty("SUBSYSTEM", std::move(newSubsystem));
    }

private:
    int refcount = 1;
    std::string syspath;
    std::string sysname;

    std::optional<udev_device *> parentDevice_;
    std::optional<std::string> subsystem_;

    bool ueventLoaded = false;
    std::unordered_map<std::string, std::string> property_;
};

// C-style interface

udev *udev_new(void)
{
    static udev instance{};
    return &instance;
}

udev *udev_unref([[maybe_unused]] udev *udev)
{
    return nullptr;
}

udev_device *udev_device_ref(udev_device *device)
{
    CHKPP(device);
    device->Ref();
    return device;
}

udev_device *udev_device_unref(udev_device *device)
{
    CHKPP(device);
    device->Unref();
    return nullptr;
}

udev *udev_device_get_udev(udev_device *device)
{
    CHKPP(device);
    return udev_new();
}

udev_device *udev_device_new_from_syspath(udev *udev, const char *syspath)
{
    if (udev == nullptr || syspath == nullptr) {
        errno = EINVAL;
        return nullptr;
    }
    return udev_device::NewFromSyspath(syspath);
}

udev_device *udev_device_new_from_devnum(udev *udev, char type, dev_t devnum)
{
    if (udev == nullptr) {
        errno = EINVAL;
        return nullptr;
    }
    return udev_device::NewFromDevnum(type, devnum);
}

udev_device *udev_device_get_parent(udev_device *device)
{
    if (device == nullptr) {
        errno = EINVAL;
        return nullptr;
    }
    return device->GetParent();
}

udev_device *udev_device_get_parent_with_subsystem_devtype(udev_device *device, const char *subsystem,
    const char *devtype)
{
    CHKPP(device);
    if (subsystem == nullptr) {
        errno = EINVAL;
        return nullptr;
    }
    // Searching with specific devtype is not supported, since not used by libinput
    CHKPP(devtype);
    return device->GetParentWithSubsystem(subsystem);
}

const char *udev_device_get_syspath(udev_device *device)
{
    CHKPP(device);
    return device->GetSyspath().c_str();
}

const char *udev_device_get_sysname(udev_device *device)
{
    CHKPP(device);
    return device->GetSysname().c_str();
}

const char *udev_device_get_devnode(udev_device *device)
{
    CHKPP(device);
    return device->GetDevnode().c_str();
}

int udev_device_get_is_initialized(udev_device *device)
{
    return (device != nullptr) ? static_cast<int>(device->IsInitialized()) : -1;
}

const char *udev_device_get_property_value(udev_device *device, const char *key)
{
    CHKPP(device);
    CHKPP(key);
    std::string skey{ key };
    if (!device->HasProperty(key)) {
        return nullptr;
    }
    return device->GetProperty(key).c_str();
}
