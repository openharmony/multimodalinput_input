/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "virtual_keyboard.h"
#include "virtual_mouse.h"
#include "virtual_gamepad.h"
#include "virtual_joystick.h"
#include "virtual_knob.h"
#include "virtual_trackball.h"
#include "virtual_trackpad.h"
#include "virtual_trackpad_sys_ctrl.h"
#include "virtual_knob_sys_ctrl.h"
#include "virtual_knob_consumer_ctrl.h"
#include "virtual_knob_mouse.h"
#include "virtual_finger.h"
#include "virtual_touchpad.h"
#include "virtual_stylus.h"
#include "virtual_trackpad_mouse.h"
#include "virtual_keyboard_sys_ctrl.h"
#include "virtual_keyboard_consumer_ctrl.h"
#include "virtual_keyboard_ext.h"
#include "virtual_remote_control.h"
#include "virtual_touchscreen.h"

bool OHOS::MMI::VirtualDevice::DoIoctl(int32_t fd, int32_t request, const uint32_t value)
{
    int32_t rc = ioctl(fd, request, value);
    if (rc < 0) {
        printf("%s ioctl failed", __func__);
        return false;
    }
    return true;
}

OHOS::MMI::VirtualDevice::VirtualDevice(const String &device_name, uint16_t busType,
                                        uint16_t vendorId, uint16_t product_id)
    : deviceName_(device_name),
      busTtype_(busType),
      vendorId_(vendorId),
      productId_(product_id),
      version_(1) {}  // The version number is one.

OHOS::MMI::VirtualDevice::~VirtualDevice()
{
    if (fd_ >= 0) {
        ioctl(fd_, UI_DEV_DESTROY);
        close(fd_);
        fd_ = -1;
    }
}

bool OHOS::MMI::VirtualDevice::CatFload(StringList& fileList)
{
    struct dirent* ptr = nullptr;
    DIR* dir = opendir(OHOS::MMI::g_folderpath.c_str());
    if (dir == nullptr) {
        printf("Failed to open folder!\n");
        return false;
    }

    fileList.clear();
    while ((ptr = readdir(dir)) != nullptr) {
        if (ptr->d_type == IS_FILE_JUDGE) {
            fileList.push_back(ptr->d_name);
        } else {
            continue;
        }
    }
    closedir(dir);
    return true;
}

bool OHOS::MMI::VirtualDevice::SyncSymbolFile()
{
    StringList tempList;
    StringList res;

    if (!CatFload(tempList)) {
        return false;
    }
    for (auto it : tempList) {
        Size_type pos = it.find("_");
        res.push_back(it.substr(0, pos));
    }

    for (auto it : res) {
        char temp[32] = { 0 };
        String processName;
        String procressPath = "/proc/" + it + "/";
        DIR* dir = opendir(procressPath.c_str());
        if (dir == nullptr) {
            String removeFile = "find /data/symbol/ -name " + it + "* | xargs rm";
            system(removeFile.c_str());
        } else {
            String catName = "cat /proc/" + it + "/cmdline";
            FILE* cmdName = popen(catName.c_str(), "r");
            if (cmdName == nullptr) {
                printf("popen Execution failed!\n");
                closedir(dir);
                return false;
            }
            fgets(temp, sizeof(temp), cmdName);
            pclose(cmdName);
            processName.append(temp);
            if (processName.find("hosmmi-virtual-device") == processName.npos) {
                String removeFile = "find /data/symbol/ -name " + it + "* | xargs rm";
                system(removeFile.c_str());
            }
        }
    }
    return true;
}

bool OHOS::MMI::VirtualDevice::CreateKey()
{
    auto fun = [&](int32_t uiSet, const std::vector<uint32_t>& list) ->bool {
        for (uint32_t evt_type : list) {
            if (!DoIoctl(fd_, uiSet, evt_type)) {
                printf("%s Error setting event type: %u", __func__, evt_type);
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
    for (auto &it : evt_type) {
        fun(it.first, it.second);
    }

    return true;
}

bool OHOS::MMI::VirtualDevice::SetAbsResolution(const String deviceName)
{
    const int ABS_RESOLUTION = 200;
    const int ABS_RESOLUTION_FINGER = 40;
    if (deviceName == "Virtual Stylus" || deviceName == "Virtual Touchpad") {
        absTemp_.code = 0x00;
        absTemp_.absinfo.resolution = ABS_RESOLUTION;
        absInit_.push_back(absTemp_);
        absTemp_.code = 0x01;
        absTemp_.absinfo.resolution = ABS_RESOLUTION;
        absInit_.push_back(absTemp_);
    } else if (deviceName == "Virtual Finger") {
        absTemp_.code = 0x00;
        absTemp_.absinfo.resolution = ABS_RESOLUTION_FINGER;
        absInit_.push_back(absTemp_);
        absTemp_.code = 0x01;
        absTemp_.absinfo.resolution = ABS_RESOLUTION_FINGER;
        absInit_.push_back(absTemp_);
    } else {
        return false;
    }
    for (auto it : absInit_) {
        ioctl(fd_, UI_ABS_SETUP, &it);
    }
    return true;
}

bool OHOS::MMI::VirtualDevice::SetPhys(const String deviceName)
{
    String phys;
    std::map<String, String> typeDevice = {
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
    };
    String deviceType = typeDevice.find(deviceName)->second;
    phys.append(deviceType).append(OHOS::MMI::g_pid).append("/").append(OHOS::MMI::g_pid);

    if (ioctl(fd_, UI_SET_PHYS, phys.c_str()) < 0) {
        return false;
    }
    return true;
}

bool OHOS::MMI::VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        printf("Failed to open uinput %s", __func__);
        return false;
    }

    if (strncpy_s(dev_.name, sizeof(dev_.name), deviceName_.c_str(), deviceName_.size()) != 0) {
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
        printf("fd = %d,ioctl(fd_, UI_DEV_CREATE) = %d", fd_, ioctl(fd_, UI_DEV_CREATE));
        printf("Unable to create input device : %s", __func__);
        return false;
    }
    return true;
}

void OHOS::MMI::VirtualDevice::CloseAllDevice(const StringList& fileList)
{
    for (auto it : fileList) {
        kill(atoi(it.c_str()), SIGKILL);
        it.insert(0, OHOS::MMI::g_folderpath.c_str());
        const int ret = remove(it.c_str());
        if (ret == -1) {
            const int errnoSaved = errno;
            printf("remove file fail. file name: %s, errno: %d, error message: %s\n",
                it.c_str(), errnoSaved, strerror(errnoSaved));
        }
    }
}

void OHOS::MMI::VirtualDevice::StartAllDevices()
{
    static OHOS::MMI::VirtualMouse virtualMouse;
    virtualMouse.SetUp();
    static OHOS::MMI::VirtualKeyboard virtualKey;
    virtualKey.SetUp();
    static OHOS::MMI::VirtualKeyboardSysCtrl virtualKeyboardSysCtrl;
    virtualKeyboardSysCtrl.SetUp();
    static OHOS::MMI::VirtualKeyboardConsumerCtrl virtualKeyboardConsumerCtrl;
    virtualKeyboardConsumerCtrl.SetUp();
    static OHOS::MMI::VirtualKeyboardExt virtualKeyext;
    virtualKeyext.SetUp();
    static OHOS::MMI::VirtualJoystick virtualJoystick;
    virtualJoystick.SetUp();
    static OHOS::MMI::VirtualTrackball virtualTrackball;
    virtualTrackball.SetUp();
    static OHOS::MMI::VirtualRemoteControl virtualRemoteControl;
    virtualRemoteControl.SetUp();
    static OHOS::MMI::VirtualTrackpad virtualTrackpad;
    virtualTrackpad.SetUp();
    static OHOS::MMI::VirtualTrackpadMouse virtualMousepadMouse;
    virtualMousepadMouse.SetUp();
    static OHOS::MMI::VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
    virtualTrackpadSysCtrl.SetUp();
    static OHOS::MMI::VirtualKnob virtualKnob;
    virtualKnob.SetUp();
    static OHOS::MMI::VirtualKnobConsumerCtrl virtualKnobConsumerCtrl;
    virtualKnobConsumerCtrl.SetUp();
    static OHOS::MMI::VirtualKnobMouse virtualKnobMouse;
    virtualKnobMouse.SetUp();
    static OHOS::MMI::VirtualKnobSysCtrl virtualKnobSysCtrl;
    virtualKnobSysCtrl.SetUp();
    static OHOS::MMI::VirtualGamePad virtualGamePad;
    virtualGamePad.SetUp();
    static OHOS::MMI::VirtualStylus virtualStylus;
    virtualStylus.SetUp();
    static OHOS::MMI::VirtualTouchpad virtualTouchpad;
    virtualTouchpad.SetUp();
    static OHOS::MMI::VirtualFinger virtualFinger;
    virtualFinger.SetUp();
    static OHOS::MMI::VirtualTouchScreen virtualTouchScreen;
    virtualTouchScreen.SetUp();
}

void OHOS::MMI::VirtualDevice::MakeFolder(const String &filePath)
{
    DIR* dir = opendir(filePath.c_str());
    bool flag = false;
    if (dir == nullptr) {
        mkdir(filePath.c_str(), SYMBOL_FOLDER_PERMISSIONS);
        flag = true;
    }
    if (!flag) {
        closedir(dir);
    }
}

bool OHOS::MMI::VirtualDevice::SelectDevice(StringList &fileList)
{
    if (fileList.size() == MAX_PARAMETER_NUMBER) {
        printf("Invaild Input Para, Plase Check the validity of the para!\n");
        return false;
    }

    if (!CatFload(fileList)) {
        return false;
    }

    if (fileList.size()) {
        return true;
    } else {
        printf("No device is currently on!\n");
        return false;
    }
}

bool OHOS::MMI::VirtualDevice::CreateHandle(const String deviceArgv)
{
    if (deviceArgv == "mouse") {
        static OHOS::MMI::VirtualMouse virtualMouse;
        virtualMouse.SetUp();
    } else if (deviceArgv == "keyboard") {
        static OHOS::MMI::VirtualKeyboard virtualKey;
        virtualKey.SetUp();
        static OHOS::MMI::VirtualKeyboardSysCtrl virtualKeyboardSysCtrl;
        virtualKeyboardSysCtrl.SetUp();
        static OHOS::MMI::VirtualKeyboardConsumerCtrl virtualKeyboardConsumerCtrl;
        virtualKeyboardConsumerCtrl.SetUp();
        static OHOS::MMI::VirtualKeyboardExt virtualKeyext;
        virtualKeyext.SetUp();
    } else if (deviceArgv == "joystick") {
        static OHOS::MMI::VirtualJoystick virtualJoystick;
        virtualJoystick.SetUp();
    } else if (deviceArgv == "trackball") {
        static OHOS::MMI::VirtualTrackball virtualTrackball;
        virtualTrackball.SetUp();
    } else if (deviceArgv == "remotecontrol") {
        static OHOS::MMI::VirtualRemoteControl virtualRemoteControl;
        virtualRemoteControl.SetUp();
    } else if (deviceArgv == "trackpad") {
        static OHOS::MMI::VirtualTrackpad virtualTrackpad;
        virtualTrackpad.SetUp();
        static OHOS::MMI::VirtualTrackpadMouse virtualMousepadMouse;
        virtualMousepadMouse.SetUp();
        static OHOS::MMI::VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
        virtualTrackpadSysCtrl.SetUp();
    } else if (deviceArgv == "knob") {
        static OHOS::MMI::VirtualKnob virtualKnob;
        virtualKnob.SetUp();
        static OHOS::MMI::VirtualKnobConsumerCtrl virtualKnobConsumerCtrl;
        virtualKnobConsumerCtrl.SetUp();
        static OHOS::MMI::VirtualKnobMouse virtualKnobMouse;
        virtualKnobMouse.SetUp();
        static OHOS::MMI::VirtualKnobSysCtrl virtualKnobSysCtrl;
        virtualKnobSysCtrl.SetUp();
    } else if (deviceArgv == "gamepad") {
        static OHOS::MMI::VirtualGamePad virtualGamePad;
        virtualGamePad.SetUp();
    } else if (deviceArgv == "touchpad") {
        static OHOS::MMI::VirtualStylus virtualStylus;
        virtualStylus.SetUp();
        static OHOS::MMI::VirtualTouchpad virtualTouchpad;
        virtualTouchpad.SetUp();
        static OHOS::MMI::VirtualFinger virtualFinger;
        virtualFinger.SetUp();
    } else if (deviceArgv == "touchscreen") {
        static OHOS::MMI::VirtualTouchScreen virtualTouchScreen;
        virtualTouchScreen.SetUp();
    } else if (deviceArgv == "all") {
        StartAllDevices();
    } else {
        printf("Please enter the device type correctly!\n");
        return false;
    }
    return true;
}

bool OHOS::MMI::VirtualDevice::AddDevice(const StringList& fileList)
{
    if (fileList.size() == MAX_PARAMETER_NUMBER_FOR_ADD_DEL) {
        printf("Invaild Input Para, Plase Check the validity of the para!\n");
        return false;
    }
    String deviceArgv = fileList.back();
    if (!CreateHandle(deviceArgv)) {
        return false;
    }

    String symbolFile;
    symbolFile.append(OHOS::MMI::g_folderpath).append(OHOS::MMI::g_pid).append("_").append(deviceArgv);
    std::ofstream flagFile;
    flagFile.open(symbolFile.c_str());
    if (!flagFile.is_open()) {
        printf("Failed to create file!\n");
        return false;
    } else {
        return true;
    }
}

bool OHOS::MMI::VirtualDevice::CloseDevice(const StringList& fileList)
{
    if (fileList.size() == MAX_PARAMETER_NUMBER_FOR_ADD_DEL) {
        printf("Invaild Input Para, Plase Check the validity of the para!\n");
        return false;
    }
    StringList alldevice = {};
    String closePid = fileList.back();
    closePid.append("_");
    bool result = SelectDevice(alldevice);
    if (!result) {
        return false;
    } else {
        if (closePid.find("all") == 0) {
            CloseAllDevice(alldevice);
            return true;
        }
        for (auto it : alldevice) {
            if (it.find(closePid) == 0) {
                kill(atoi(it.c_str()), SIGKILL);
                it.insert(0, OHOS::MMI::g_folderpath.c_str());
                const int ret = remove(it.c_str());
                if (ret == -1) {
                    const int errnoSaved = errno;
                    printf("remove file fail. file name: %s, errno: %d, error message: %s\n",
                        it.c_str(), errnoSaved, strerror(errnoSaved));
                }
                return true;
            } else {
                continue;
            }
        }
        printf("Device shutdown failed! The PID format is incorrect!\n");
        return false;
    }
}

bool OHOS::MMI::VirtualDevice::FunctionalShunt(const String firstArgv, StringList argvList)
{
    SyncSymbolFile();
    if (firstArgv == "start") {
        bool result = AddDevice(argvList);
        if (!result) {
            return false;
        } else {
            return true;
        }
    } else if (firstArgv == "list") {
        bool result = SelectDevice(argvList);
        if (!result) {
            return false;
        } else {
            Size_type pos;
            printf("PID\tDEVICE\n");

            for (auto it : argvList) {
                pos = it.find("_");
                printf("%s\t%s\n", it.substr(0, pos).c_str(), it.substr(pos + 1, it.size() - pos - 1).c_str());
            }
            return false;
        }
    } else if (firstArgv == "close") {
        bool result = CloseDevice(argvList);
        if (!result) {
            return false;
        } else {
            printf("device closed successfully!\n");
            return false;
        }
    } else {
        printf("The command line format is incorrect!\n");
        return false;
    }
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetKeys() const
{
    static const std::vector<uint32_t> keys {
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetProperties() const
{
    static const std::vector<uint32_t> properties {
    };
    return properties;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetAbs() const
{
    static const std::vector<uint32_t> abs {
    };
    return abs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetRelBits() const
{
    static const std::vector<uint32_t> relBits {
    };
    return relBits;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetLeds() const
{
    static const std::vector<uint32_t> leds {
    };
    return leds;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetReps() const
{
    static const std::vector<uint32_t> reps {
    };
    return reps;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
    };
    return mscs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualDevice::GetSws() const
{
    static const std::vector<uint32_t> sws {
    };
    return sws;
}
