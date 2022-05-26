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

#include "virtual_device.h"
#include "virtual_finger.h"
#include "virtual_gamepad.h"
#include "virtual_joystick.h"
#include "virtual_keyboard.h"
#include "virtual_keyboard_sys_ctrl.h"
#include "virtual_keyboard_consumer_ctrl.h"
#include "virtual_keyboard_ext.h"
#include "virtual_knob.h"
#include "virtual_knob_sys_ctrl.h"
#include "virtual_knob_consumer_ctrl.h"
#include "virtual_knob_mouse.h"
#include "virtual_mouse.h"
#include "virtual_pen.h"
#include "virtual_pen_mouse.h"
#include "virtual_pen_keyboard.h"
#include "virtual_remote_control.h"
#include "virtual_single_finger.h"
#include "virtual_single_touchscreen.h"
#include "virtual_stylus.h"
#include "virtual_trackball.h"
#include "virtual_trackpad.h"
#include "virtual_trackpad_sys_ctrl.h"
#include "virtual_touchpad.h"
#include "virtual_touchscreen.h"
#include "virtual_trackpad_mouse.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABSRANGE = 200;
constexpr int32_t FINGERABSRANGE = 40;
const std::string VIRTUAL_DEVICE_NAME = "mmi-virtual-device";
#define SETRESOLUTION(codeTmp, value) do { \
    g_absTemp_.code = codeTmp; \
    g_absTemp_.absinfo.resolution = value; \
    absInit_.push_back(g_absTemp_); \
} while (0)

bool CheckFileName(const std::string& fileName)
{
    std::string::size_type pos = fileName.find("_");
    if (pos ==  std::string::npos) {
        printf("Failed to create file");
        return false;
    }
    if (!IsNum(fileName.substr(0, pos))) {
        printf("file name check error");
        return false;
    }
    std::vector<std::string> validFileNames = {
        "mouse", "keyboard", "joystick", "trackball", "remotecontrol",
        "trackpad", "knob", "gamepad", "touchpad", "touchscreen",
        "pen", "all"
    };
    std::string deviceName = fileName.substr(pos + 1);
    bool result = std::any_of(validFileNames.begin(), validFileNames.end(), [deviceName](const std::string& str) {
        return str == deviceName;
    });
    if (!result) {
        printf("file name check divece file name error : %s", fileName.c_str());
    }
    return result;
}

void RemoveDir(const std::string& filePath)
{
    if (filePath.empty()) {
        printf("file path is empty");
        return;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        printf("Failed to open folder");
        return;
    }
    dirent* ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        std::string tmpDirName(ptr->d_name);
        if ((tmpDirName == ".") || (tmpDirName == "..")) {
            continue;
        }
        if (ptr->d_type == DT_REG) {
            std::string rmFile = filePath + ptr->d_name;
            if (std::remove(rmFile.c_str()) != 0) {
                printf("remove file: %s failed", rmFile.c_str());
            }
        } else if (ptr->d_type == DT_DIR) {
            RemoveDir((filePath + ptr->d_name + "/"));
        } else {
            printf("file name:%s, type is error", ptr->d_name);
        }
    }
    if (closedir(dir) != 0) {
        printf("close dir: %s failed", filePath.c_str());
    }
    if (std::remove(filePath.c_str()) != 0) {
        printf("remove dir: %s failed", filePath.c_str());
    }
    return;
}

void StartMouse()
{
    static VirtualMouse virtualMouse;
    virtualMouse.SetUp();
}

void StartKeyboard()
{
    static VirtualKeyboard virtualKey;
    virtualKey.SetUp();
    static VirtualKeyboardSysCtrl virtualKeyboardSysCtrl;
    virtualKeyboardSysCtrl.SetUp();
    static VirtualKeyboardConsumerCtrl virtualKeyboardConsumerCtrl;
    virtualKeyboardConsumerCtrl.SetUp();
    static VirtualKeyboardExt virtualKeyext;
    virtualKeyext.SetUp();
}

void StartJoystick()
{
    static VirtualJoystick virtualJoystick;
    virtualJoystick.SetUp();
}

void StartTrackball()
{
    static VirtualTrackball virtualTrackball;
    virtualTrackball.SetUp();
}

void StartRemoteControl()
{
    static VirtualRemoteControl virtualRemoteControl;
    virtualRemoteControl.SetUp();
}


void StartTrackpad()
{
    static VirtualTrackpad virtualTrackpad;
    virtualTrackpad.SetUp();
    static VirtualTrackpadMouse virtualMousepadMouse;
    virtualMousepadMouse.SetUp();
    static VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
    virtualTrackpadSysCtrl.SetUp();
}

void StartKnob()
{
    static VirtualKnob virtualKnob;
    virtualKnob.SetUp();
    static VirtualKnobConsumerCtrl virtualKnobConsumerCtrl;
    virtualKnobConsumerCtrl.SetUp();
    static VirtualKnobMouse virtualKnobMouse;
    virtualKnobMouse.SetUp();
    static VirtualKnobSysCtrl virtualKnobSysCtrl;
    virtualKnobSysCtrl.SetUp();
}

void StartGamePad()
{
    static VirtualGamePad virtualGamePad;
    virtualGamePad.SetUp();
}

void StartTouchPad()
{
    static VirtualStylus virtualStylus;
    virtualStylus.SetUp();
    static VirtualTouchpad virtualTouchpad;
    virtualTouchpad.SetUp();
    static VirtualFinger virtualFinger;
    virtualFinger.SetUp();
    static VirtualSingleFinger virtualSingleFinger;
    virtualSingleFinger.SetUp();
}

void StartTouchScreen()
{
    static VirtualTouchScreen virtualTouchScreen;
    virtualTouchScreen.SetUp();
    static VirtualSingleTouchScreen virtualSingleTouchScreen;
    virtualSingleTouchScreen.SetUp();
}

void StartPen()
{
    static VirtualPen virtualPen;
    virtualPen.SetUp();
    static VirtualPenMouse virtualPenMouse;
    virtualPenMouse.SetUp();
    static VirtualPenKeyboard virtualPenKeyboard;
    virtualPenKeyboard.SetUp();
}

using virtualFun = void (*)();
std::map<std::string, virtualFun> mapFun = {
    {"mouse", &StartMouse},
    {"keyboard", &StartKeyboard},
    {"joystick", &StartJoystick},
    {"trackball", &StartTrackball},
    {"remotecontrol", &StartRemoteControl},
    {"trackpad", &StartTrackpad},
    {"knob", &StartKnob},
    {"gamepad", &StartGamePad},
    {"touchpad", &StartTouchPad},
    {"touchscreen", &StartTouchScreen},
    {"pen", &StartPen}
};

void StartAllDevices()
{
    if (mapFun.empty()) {
        printf("mapFun is empty");
        return;
    }
    for (const auto &item : mapFun) {
        (*item.second)();
    }
}
} // namespace

bool VirtualDevice::DoIoctl(int32_t fd, int32_t request, const uint32_t value)
{
    int32_t rc = ioctl(fd, request, value);
    if (rc < 0) {
        printf("%s ioctl failed", __func__);
        return false;
    }
    return true;
}

VirtualDevice::VirtualDevice(const std::string &device_name, uint16_t busType,
    uint16_t vendorId, uint16_t product_id)
    : deviceName_(device_name),
      busTtype_(busType),
      vendorId_(vendorId),
      productId_(product_id),
      version_(1) {}

VirtualDevice::~VirtualDevice()
{
    Close();
}

std::vector<std::string> VirtualDevice::BrowseDirectory(const std::string& filePath)
{
    std::vector<std::string> fileList;
    fileList.clear();
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        printf("Failed to open folder");
        return fileList;
    }
    dirent* ptr = nullptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_type == DT_REG) {
            if (ClearFileResidues(ptr->d_name)) {
                fileList.push_back(ptr->d_name);
            }
        }
    }
    if (closedir(dir) != 0) {
        printf("close dir: %s failed", filePath.c_str());
    }
    return fileList;
}

bool VirtualDevice::ClearFileResidues(const std::string& fileName)
{
    DIR *dir = nullptr;
    const std::string::size_type pos = fileName.find("_");
    const std::string procressPath = "/proc/" + fileName.substr(0, pos) + "/";
    const std::string filePath = procressPath + "cmdline";
    std::string temp;
    std::string processName;
    if (!CheckFileName(fileName)) {
        printf("file name check error");
        goto RELEASE_RES;
    }
    if (pos == std::string::npos) {
        printf("Failed to create file");
        goto RELEASE_RES;
    }
    dir = opendir(procressPath.c_str());
    if (dir == nullptr) {
        printf("open dir:%s failed", procressPath.c_str());
        goto RELEASE_RES;
    }
    temp = ReadUinputToolFile(filePath);
    if (temp.empty()) {
        printf("temp is empty");
        goto RELEASE_RES;
    }
    processName.append(temp);
    if (processName.find(VIRTUAL_DEVICE_NAME.c_str()) != std::string::npos) {
        if (closedir(dir) != 0) {
            printf("close dir: %s failed", procressPath.c_str());
        }
        return true;
    }
    RELEASE_RES:
    if (dir != nullptr) {
        if (closedir(dir) != 0) {
            printf("close dir failed");
        }
    }
    if (std::remove((g_folderpath + fileName).c_str()) != 0) {
        printf("remove file failed");
    }
    return false;
}

bool VirtualDevice::CreateKey()
{
    auto fun = [&](int32_t uiSet, const std::vector<uint32_t>& list) ->bool {
        for (const auto &item : list) {
            if (!DoIoctl(fd_, uiSet, item)) {
                printf("%s Error setting event type: %u", __func__, item);
                return false;
            }
        }
        return true;
    };
    std::map<int32_t, std::vector<uint32_t>> evt_type;
    evt_type[UI_SET_EVBIT] = GetEventTypes();
    evt_type[UI_SET_KEYBIT] = GetKeys();
    evt_type[UI_SET_PROPBIT] = GetProperties();
    evt_type[UI_SET_ABSBIT] = GetAbs();
    evt_type[UI_SET_RELBIT] = GetRelBits();
    evt_type[UI_SET_MSCBIT] = GetMiscellaneous();
    evt_type[UI_SET_LEDBIT] = GetLeds();
    evt_type[UI_SET_SWBIT] = GetSwitchs();
    evt_type[UI_SET_PHYS] = GetRepeats();
    for (auto &item : evt_type) {
        fun(item.first, item.second);
    }
    return true;
}

bool VirtualDevice::SetAbsResolution(const std::string& deviceName)
{
    if (deviceName == "Virtual Stylus" || deviceName == "Virtual Touchpad") {
        SETRESOLUTION(ABS_X, ABSRANGE);
        SETRESOLUTION(ABS_Y, ABSRANGE);
    } else if (deviceName == "Virtual Finger") {
        SETRESOLUTION(ABS_X, FINGERABSRANGE);
        SETRESOLUTION(ABS_Y, FINGERABSRANGE);
        SETRESOLUTION(ABS_MT_POSITION_X, FINGERABSRANGE);
        SETRESOLUTION(ABS_MT_POSITION_Y, FINGERABSRANGE);
        SETRESOLUTION(ABS_MT_TOOL_X, FINGERABSRANGE);
        SETRESOLUTION(ABS_MT_TOOL_Y, FINGERABSRANGE);
    } else if (deviceName == "V-Pencil") {
        SETRESOLUTION(ABS_X, ABSRANGE);
        SETRESOLUTION(ABS_Y, ABSRANGE);
    } else {
        printf("Not devide:deviceName:%s", deviceName.c_str());
        return false;
    }
    for (const auto &item : absInit_) {
        ioctl(fd_, UI_ABS_SETUP, &item);
    }
    return true;
}

bool VirtualDevice::SetPhys(const std::string& deviceName)
{
    std::string phys;
    std::map<std::string, std::string> typeDevice = {
        {"Virtual Mouse",                "mouse"},
        {"Virtual keyboard",             "keyboard"},
        {"Virtual KeyboardConsumerCtrl", "keyboard"},
        {"Virtual keyboardExt",          "keyboard"},
        {"Virtual KeyboardSysCtrl",      "keyboard"},
        {"Virtual Knob",                 "knob"},
        {"Virtual KnobConsumerCtrl",     "knob"},
        {"Virtual KnobMouse",            "knob"},
        {"Virtual KnobSysCtrl",          "knob"},
        {"Virtual Trackpad",             "trackpad"},
        {"Virtual TrackPadMouse",        "trackpad"},
        {"Virtual TrackpadSysCtrl",      "trackpad"},
        {"Virtual Finger",               "touchpad"},
        {"Virtual SingleFinger",         "touchpad"},
        {"Virtual Stylus",               "touchpad"},
        {"Virtual Touchpad",             "touchpad"},
        {"Virtual RemoteControl",        "remotecontrol"},
        {"Virtual Joystick",             "joystick"},
        {"Virtual GamePad",              "gamepad"},
        {"Virtual Trackball",            "trackball"},
        {"Virtual TouchScreen",          "touchscreen"},
        {"Virtual SingleTouchScreen",    "touchscreen"},
        {"V-Pencil",                     "pen"},
        {"V-Pencil-mouse",               "pen"},
        {"V-Pencil-keyboard",            "pen"},
    };
    std::string deviceType = typeDevice.find(deviceName)->second;
    phys.append(deviceType).append(g_pid).append("/").append(g_pid);

    if (ioctl(fd_, UI_SET_PHYS, phys.c_str()) < 0) {
        printf("Failed to UI_SET_PHYS %s", __func__);
        return false;
    }
    return true;
}

bool VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        printf("Failed to open uinput %s, fd:%d", __func__, fd_);
        return false;
    }

    if (strncpy_s(dev_.name, sizeof(dev_.name), deviceName_.c_str(), deviceName_.size()) != 0) {
        printf("Failed to device name copy %s", dev_.name);
        return false;
    };
    dev_.id.bustype = busTtype_;
    dev_.id.vendor = vendorId_;
    dev_.id.product = productId_;
    dev_.id.version = version_;

    SetAbsResolution(deviceName_);
    if (!SetPhys(deviceName_)) {
        printf("Failed to set PHYS! %s", __func__);
        return false;
    }

    if (!CreateKey()) {
        printf("Failed to create KeyValue %s", __func__);
        return false;
    }

    if (write(fd_, &dev_, sizeof(dev_)) < 0) {
        printf("Unable to set input device info: %s", __func__);
        return false;
    }
    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        printf("fd:%d, Unable to create input device:%s", fd_, __func__);
        return false;
    }
    return true;
}

void VirtualDevice::Close()
{
    if (fd_ >= 0) {
        ioctl(fd_, UI_DEV_DESTROY);
        close(fd_);
        fd_ = -1;
    }
}

bool VirtualDevice::CreateHandle(const std::string& deviceArgv)
{
    if (deviceArgv == "all") {
        StartAllDevices();
        return true;
    }
    if (mapFun.find(deviceArgv) == mapFun.end()) {
        printf("Please enter the device type correctly");
        return false;
    }
    (*mapFun[deviceArgv])();
    return true;
}

bool VirtualDevice::AddDevice(const std::string& startDeviceName)
{
    if (startDeviceName.empty()) {
        printf("startDeviceName is empty");
        return false;
    }
    if (!CreateHandle(startDeviceName)) {
        printf("Device %s start faild", startDeviceName.c_str());
        return false;
    }
    std::string symbolFile;
    symbolFile.append(g_folderpath).append(g_pid).append("_").append(startDeviceName);
    std::ofstream flagFile;
    flagFile.open(symbolFile.c_str());
    if (!flagFile.is_open()) {
        printf("Failed to create file");
        return false;
    }
    return true;
}

bool VirtualDevice::CloseDevice(const std::string& closeDeviceName, const std::vector<std::string>& deviceList)
{
    if (BrowseDirectory(g_folderpath).size() == 0) {
        printf("no device to off");
        return false;
    }
    if (deviceList.empty()) {
        RemoveDir(g_folderpath);
        printf("no start device");
        return false;
    }
    if (closeDeviceName == "all") {
        for (auto it : deviceList) {
            kill(atoi(it.c_str()), SIGKILL);
        }
        RemoveDir(g_folderpath);
        return true;
    }
    for (auto it : deviceList) {
        if (it.find(closeDeviceName) == 0) {
            kill(atoi(it.c_str()), SIGKILL);
            if (BrowseDirectory(g_folderpath).size() == 0) {
                RemoveDir(g_folderpath);
            }
            return true;
        }
    }
    printf("Device shutdown failed! The PID format is incorrect");
    return false;
}

bool VirtualDevice::CommandBranch(std::vector<std::string>& argvList)
{
    std::vector<std::string> deviceList = BrowseDirectory(g_folderpath);
    if (argvList[1] == "start") {
        if (argvList.size() != PARAMETERS_NUMBER) {
            printf("Invaild Input Para, Plase Check the validity of the para");
            return false;
        }
        if (!AddDevice(argvList.back())) {
            printf("Failed to create device");
            return false;
        }
        return true;
    } else if (argvList[1] == "list") {
        if (argvList.size() != PARAMETERS_QUERY_NUMBER) {
            printf("Invaild Input Para, Plase Check the validity of the para");
            return false;
        }
        std::string::size_type pos;
        printf("PID\tDEVICE\n");
        for (const auto &item : deviceList) {
            pos = item.find("_");
            printf("%s\t%s\n", item.substr(0, pos).c_str(), item.substr(pos + 1, item.size() - pos - 1).c_str());
        }
        return false;
    } else if (argvList[1] == "close") {
        if (argvList.size() != PARAMETERS_NUMBER) {
            printf("Invaild Input Para, Plase Check the validity of the para");
            return false;
        }
        if (!CloseDevice(argvList.back(), deviceList)) {
            return false;
        } else {
            printf("device closed successfully");
            return false;
        }
    } else {
        printf("The command line format is incorrect");
        return false;
    }
}

const std::vector<uint32_t>& VirtualDevice::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
    };
    return evt_types;
}

const std::vector<uint32_t>& VirtualDevice::GetKeys() const
{
    static const std::vector<uint32_t> keys {
    };
    return keys;
}

const std::vector<uint32_t>& VirtualDevice::GetProperties() const
{
    static const std::vector<uint32_t> properties {
    };
    return properties;
}

const std::vector<uint32_t>& VirtualDevice::GetAbs() const
{
    static const std::vector<uint32_t> abs {
    };
    return abs;
}

const std::vector<uint32_t>& VirtualDevice::GetRelBits() const
{
    static const std::vector<uint32_t> relBits {
    };
    return relBits;
}

const std::vector<uint32_t>& VirtualDevice::GetLeds() const
{
    static const std::vector<uint32_t> leds {
    };
    return leds;
}

const std::vector<uint32_t>& VirtualDevice::GetRepeats() const
{
    static const std::vector<uint32_t> repeats {
    };
    return repeats;
}

const std::vector<uint32_t>& VirtualDevice::GetMiscellaneous() const
{
    static const std::vector<uint32_t> miscellaneous {
    };
    return miscellaneous;
}

const std::vector<uint32_t>& VirtualDevice::GetSwitchs() const
{
    static const std::vector<uint32_t> switchs {
    };
    return switchs;
}
} // namespace MMI
} // namespace OHOS
