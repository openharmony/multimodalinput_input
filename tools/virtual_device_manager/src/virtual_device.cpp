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
bool IsNum(const std::string& str)
{
    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isdigit(c) != 0;
    });
}

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

void RemoveDir()
{
    DIR* dir = opendir(g_folderpath.c_str());
    if (dir == nullptr) {
        printf("Failed to open folder");
        return;
    }
    dirent* ptr = nullptr;
    int32_t fileNnm = 0;
    while ((ptr = readdir(dir)) != nullptr) {
        std::string tmpDirName(ptr->d_name);
        if ((tmpDirName == ".") || (tmpDirName == "..")) {
            continue;
        }
        fileNnm++;
    }
    closedir(dir);
    if (fileNnm == 0) {
        if (remove(g_folderpath.c_str()) != 0) {
            printf("remove %s fail, errno: %d.", g_folderpath.c_str(), errno);
        }
    }
    return;
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

std::vector<std::string> VirtualDevice::ViewDirectory(const std::string& filePath, bool compliant)
{
    std::vector<std::string> fileList;
    fileList.clear();
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        printf("Failed to open folder");
        return fileList;
    }
    dirent* ptr = nullptr;
    int32_t fileNum = 0;
    while ((ptr = readdir(dir)) != nullptr) {
        std::string tmpDirName(ptr->d_name);
        if ((tmpDirName == ".") || (tmpDirName == "..")) {
            continue;
        }
        fileNum++;
        if (ptr->d_type == DT_REG) {
            if (CheckFileName(ptr->d_name) && compliant) {
                fileList.push_back(ptr->d_name);
            } else {
                std::string removeFile = filePath + ptr->d_name;
                if (std::remove(removeFile.c_str()) != 0) {
                    printf("delete file: %s failed", removeFile.c_str());
                }
                fileNum--;
            }
        } else if (ptr->d_type == DT_DIR) {
            std::string path = filePath + ptr->d_name + "/";
            printf("filePath : %s is error", path.c_str());
            ViewDirectory(path, false);
        } else {
            printf("file name:%s, type is error", ptr->d_name);
            fileNum--;
        }
    }
    closedir(dir);
    if (fileNum == 0 && !compliant) {
        if (std::remove(filePath.c_str()) != 0) {
            printf("delete file: %s failed", filePath.c_str());
        }
    }
    return fileList;
}

bool VirtualDevice::ClearFileResidues(const std::string& procressPath, const std::string& fileName)
{
    DIR* dir = opendir(procressPath.c_str());
    if (dir == nullptr) {
        std::string removeFile = "/data/symbol/" + fileName;
        if (!IsFileExists(removeFile)) {
            printf("/data/symbol/%s path is error", removeFile.c_str());
            return false;
        }
        if (std::remove(removeFile.c_str()) != 0) {
            printf("delete file: %s failed", removeFile.c_str());
        }
        return true;
    }
    closedir(dir);
    return false;
}

void VirtualDevice::SyncSymbolFile()
{
    std::vector<std::string> tempList = ViewDirectory(g_folderpath);
    if (tempList.size() <= 0) {
        printf("Failed to find file ");
        return;
    }
    for (const auto &item : tempList) {
        if (!CheckFileName(item)) {
            printf("file name check error");
            return;
        }
        std::string::size_type pos = item.find("_");
        std::string procressPath = "/proc/" + item.substr(0, pos) + "/";
        if (!ClearFileResidues(procressPath, item)) {
            std::string filePath = "/proc/" + item.substr(0, pos) + "/cmdline";
            const std::string temp = ReadFile(filePath, 1);
            if (temp.empty()) {
                printf("%s is null", filePath.c_str());
                return;
            }
            std::string processName;
            processName.append(temp);
            if (processName.find("mmi-virtual-device") == processName.npos) {
                std::string removeFile = "/data/symbol/" + item;
                if (!IsFileExists(removeFile)) {
                    printf("/data/symbol/%s path is error", removeFile.c_str());
                    return;
                }
                if (std::remove(removeFile.c_str()) != 0) {
                    printf("delete file: %s failed", removeFile.c_str());
                }
            }
        }
    }
    return;
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
    evt_type[UI_SET_MSCBIT] = GetMscs();
    evt_type[UI_SET_LEDBIT] = GetLeds();
    evt_type[UI_SET_SWBIT] = GetSws();
    evt_type[UI_SET_PHYS] = GetReps();
    for (auto &item : evt_type) {
        fun(item.first, item.second);
    }
    return true;
}

bool VirtualDevice::SetAbsResolution(const std::string deviceName)
{
    constexpr int32_t ABSRANGE = 200;
    constexpr int32_t FINGERABSRANGE = 40;
    if (deviceName == "Virtual Stylus" || deviceName == "Virtual Touchpad") {
        g_absTemp_.code = 0x00;
        g_absTemp_.absinfo.resolution = ABSRANGE;
        absInit_.push_back(g_absTemp_);
        g_absTemp_.code = 0x01;
        g_absTemp_.absinfo.resolution = ABSRANGE;
        absInit_.push_back(g_absTemp_);
    } else if (deviceName == "Virtual Finger") {
        g_absTemp_.code = 0x00;
        g_absTemp_.absinfo.resolution = FINGERABSRANGE;
        absInit_.push_back(g_absTemp_);
        g_absTemp_.code = 0x01;
        g_absTemp_.absinfo.resolution = FINGERABSRANGE;
        absInit_.push_back(g_absTemp_);
    } else if (deviceName == "V-Pencil") {
        g_absTemp_.code = 0x00;
        g_absTemp_.absinfo.resolution = ABSRANGE;
        absInit_.push_back(g_absTemp_);
        g_absTemp_.code = 0x01;
        g_absTemp_.absinfo.resolution = ABSRANGE;
        absInit_.push_back(g_absTemp_);
    } else {
        printf("Not devide:deviceName:%s", deviceName.c_str());
        return false;
    }
    for (const auto &item : absInit_) {
        ioctl(fd_, UI_ABS_SETUP, &item);
    }
    return true;
}

bool VirtualDevice::SetPhys(const std::string deviceName)
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
        {"Virtual Stylus",               "touchpad"},
        {"Virtual Touchpad",             "touchpad"},
        {"Virtual RemoteControl",        "remotecontrol"},
        {"Virtual Joystick",             "joystick"},
        {"Virtual GamePad",              "gamepad"},
        {"Virtual Trackball",            "trackball"},
        {"Virtual TouchScreen",          "touchscreen"},
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

void VirtualDevice::CloseAllDevice(const std::vector<std::string>& fileList)
{
    for (auto it : fileList) {
        kill(atoi(it.c_str()), SIGKILL);
        it.insert(0, g_folderpath.c_str());
        if (std::remove(it.c_str()) != 0) {
            printf("delete file: %s failed", it.c_str());
        }
    }
}

void VirtualDevice::StartAllDevices()
{
    static VirtualMouse virtualMouse;
    virtualMouse.SetUp();
    static VirtualKeyboard virtualKey;
    virtualKey.SetUp();
    static VirtualKeyboardSysCtrl virtualKeyboardSysCtrl;
    virtualKeyboardSysCtrl.SetUp();
    static VirtualKeyboardConsumerCtrl virtualKeyboardConsumerCtrl;
    virtualKeyboardConsumerCtrl.SetUp();
    static VirtualKeyboardExt virtualKeyext;
    virtualKeyext.SetUp();
    static VirtualJoystick virtualJoystick;
    virtualJoystick.SetUp();
    static VirtualTrackball virtualTrackball;
    virtualTrackball.SetUp();
    static VirtualRemoteControl virtualRemoteControl;
    virtualRemoteControl.SetUp();
    static VirtualTrackpad virtualTrackpad;
    virtualTrackpad.SetUp();
    static VirtualTrackpadMouse virtualMousepadMouse;
    virtualMousepadMouse.SetUp();
    static VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
    virtualTrackpadSysCtrl.SetUp();
    static VirtualKnob virtualKnob;
    virtualKnob.SetUp();
    static VirtualKnobConsumerCtrl virtualKnobConsumerCtrl;
    virtualKnobConsumerCtrl.SetUp();
    static VirtualKnobMouse virtualKnobMouse;
    virtualKnobMouse.SetUp();
    static VirtualKnobSysCtrl virtualKnobSysCtrl;
    virtualKnobSysCtrl.SetUp();
    static VirtualGamePad virtualGamePad;
    virtualGamePad.SetUp();
    static VirtualStylus virtualStylus;
    virtualStylus.SetUp();
    static VirtualTouchpad virtualTouchpad;
    virtualTouchpad.SetUp();
    static VirtualFinger virtualFinger;
    virtualFinger.SetUp();
    static VirtualTouchScreen virtualTouchScreen;
    virtualTouchScreen.SetUp();
    static VirtualPen virtualPen;
    virtualPen.SetUp();
    static VirtualPenMouse virtualPenMouse;
    virtualPenMouse.SetUp();
    static VirtualPenKeyboard virtualPenKeyboard;
    virtualPenKeyboard.SetUp();
}

bool VirtualDevice::SelectDevice(std::vector<std::string> &fileList)
{
    if (fileList.size() == MAXPARAMETER) {
        printf("Invaild Input Para, Plase Check the validity of the para");
        return false;
    }
    fileList = ViewDirectory(g_folderpath);
    if (fileList.size() == 0) {
        printf("No device is currently on");
        return false;
    }
    return true;
}

bool VirtualDevice::CreateHandle(const std::string deviceArgv)
{
    if (deviceArgv == "mouse") {
        static VirtualMouse virtualMouse;
        virtualMouse.SetUp();
    } else if (deviceArgv == "keyboard") {
        static VirtualKeyboard virtualKey;
        virtualKey.SetUp();
        static VirtualKeyboardSysCtrl virtualKeyboardSysCtrl;
        virtualKeyboardSysCtrl.SetUp();
        static VirtualKeyboardConsumerCtrl virtualKeyboardConsumerCtrl;
        virtualKeyboardConsumerCtrl.SetUp();
        static VirtualKeyboardExt virtualKeyext;
        virtualKeyext.SetUp();
    } else if (deviceArgv == "joystick") {
        static VirtualJoystick virtualJoystick;
        virtualJoystick.SetUp();
    } else if (deviceArgv == "trackball") {
        static VirtualTrackball virtualTrackball;
        virtualTrackball.SetUp();
    } else if (deviceArgv == "remotecontrol") {
        static VirtualRemoteControl virtualRemoteControl;
        virtualRemoteControl.SetUp();
    } else if (deviceArgv == "trackpad") {
        static VirtualTrackpad virtualTrackpad;
        virtualTrackpad.SetUp();
        static VirtualTrackpadMouse virtualMousepadMouse;
        virtualMousepadMouse.SetUp();
        static VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
        virtualTrackpadSysCtrl.SetUp();
    } else if (deviceArgv == "knob") {
        static VirtualKnob virtualKnob;
        virtualKnob.SetUp();
        static VirtualKnobConsumerCtrl virtualKnobConsumerCtrl;
        virtualKnobConsumerCtrl.SetUp();
        static VirtualKnobMouse virtualKnobMouse;
        virtualKnobMouse.SetUp();
        static VirtualKnobSysCtrl virtualKnobSysCtrl;
        virtualKnobSysCtrl.SetUp();
    } else if (deviceArgv == "gamepad") {
        static VirtualGamePad virtualGamePad;
        virtualGamePad.SetUp();
    } else if (deviceArgv == "touchpad") {
        static VirtualStylus virtualStylus;
        virtualStylus.SetUp();
        static VirtualTouchpad virtualTouchpad;
        virtualTouchpad.SetUp();
        static VirtualFinger virtualFinger;
        virtualFinger.SetUp();
    } else if (deviceArgv == "touchscreen") {
        static VirtualTouchScreen virtualTouchScreen;
        virtualTouchScreen.SetUp();
    } else if (deviceArgv == "pen") {
        static VirtualPen virtualPen;
        virtualPen.SetUp();
        static VirtualPenMouse virtualPenMouse;
        virtualPenMouse.SetUp();
        static VirtualPenKeyboard virtualPenKeyboard;
        virtualPenKeyboard.SetUp();
    } else if (deviceArgv == "all") {
        StartAllDevices();
    } else {
        printf("Please enter the device type correctly");
        return false;
    }
    return true;
}

bool VirtualDevice::AddDevice(const std::vector<std::string>& fileList)
{
    if (fileList.size() == MAXDELPARAMETER) {
        printf("Invaild Input Para, Plase Check the validity of the para");
        return false;
    }
    std::string deviceArgv = fileList.back();
    if (!CreateHandle(deviceArgv)) {
        return false;
    }

    std::string symbolFile;
    symbolFile.append(g_folderpath).append(g_pid).append("_").append(deviceArgv);
    std::ofstream flagFile;
    flagFile.open(symbolFile.c_str());
    if (!flagFile.is_open()) {
        printf("Failed to create file");
        return false;
    }
    return true;
}

bool VirtualDevice::CloseDevice(const std::vector<std::string>& fileList)
{
    if (fileList.size() == MAXDELPARAMETER) {
        printf("Invaild Input Para, Plase Check the validity of the para");
        return false;
    }
    std::vector<std::string> alldevice = {};
    std::string closePid = fileList.back();
    closePid.append("_");
    bool result = SelectDevice(alldevice);
    if (!result) {
        RemoveDir();
        return false;
    }
    if (closePid.compare("all_") == 0) {
        CloseAllDevice(alldevice);
        RemoveDir();
        return true;
    }
    for (auto it : alldevice) {
        if (it.find(closePid) == 0) {
            kill(atoi(it.c_str()), SIGKILL);
            it.insert(0, g_folderpath.c_str());
            if (std::remove(it.c_str()) != 0) {
                printf("delete file: %s failed", it.c_str());
            }
            RemoveDir();
            return true;
        }
    }
    printf("Device shutdown failed! The PID format is incorrect");
    return false;
}

bool VirtualDevice::FindDevice(std::vector<std::string> argvList)
{
    SyncSymbolFile();
    if (argvList[1] == "start") {
        if (!AddDevice(argvList)) {
            printf("Failed to create device");
            return false;
        }
        return true;
    } else if (argvList[1] == "list") {
        if (!SelectDevice(argvList)) {
            return false;
        } else {
            std::string::size_type pos;
            printf("PID\tDEVICE\n");

            for (const auto &item : argvList) {
                pos = item.find("_");
                printf("%s\t%s\n", item.substr(0, pos).c_str(), item.substr(pos + 1, item.size() - pos - 1).c_str());
            }
            return false;
        }
    } else if (argvList[1] == "close") {
        if (!CloseDevice(argvList)) {
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

const std::vector<uint32_t>& VirtualDevice::GetReps() const
{
    static const std::vector<uint32_t> reps {
    };
    return reps;
}

const std::vector<uint32_t>& VirtualDevice::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
    };
    return mscs;
}

const std::vector<uint32_t>& VirtualDevice::GetSws() const
{
    static const std::vector<uint32_t> sws {
    };
    return sws;
}
} // namespace MMI
} // namespace OHOS
