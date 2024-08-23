/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "virtual_device.h"

#include <getopt.h>
#include <sys/stat.h>

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
#include "virtual_pc_switch.h"
#include "virtual_pc_touchpad.h"
#include "virtual_touchscreen.h"
#include "virtual_trackpad_mouse.h"
#include "virtual_fingerprint_key.h"
#include "virtual_fingerprint_mouse.h"
#include "virtual_crown.h"
#include "virtual_uwb_remote_control.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FILE_SIZE_MAX = 0x5000;
constexpr int32_t INVALID_FILE_SIZE = -1;
constexpr int32_t FILE_POWER = 0777;
constexpr int32_t SLEEP_TIME = 1500000;
const std::string PROC_PATH = "/proc";
const std::string VIRTUAL_DEVICE_NAME = "vuinput";
const std::string g_pid = std::to_string(getpid());

static inline bool IsNum(const std::string& str)
{
    std::istringstream sin(str);
    double num;
    return (sin >> num) && sin.eof();
}

static inline bool IsValidPath(const std::string& rootDir, const std::string& filePath)
{
    return (filePath.compare(0, rootDir.size(), rootDir) == 0);
}

static inline bool IsValidUinputPath(const std::string& filePath)
{
    return IsValidPath(PROC_PATH, filePath);
}

static inline bool IsFileExists(const std::string& fileName)
{
    return (access(fileName.c_str(), F_OK) == 0);
}

static bool CheckFileName(const std::string& fileName)
{
    std::string::size_type pos = fileName.find("_");
    if (pos == std::string::npos) {
        std::cout << "Failed to create file" << std::endl;
        return false;
    }
    if (!IsNum(fileName.substr(0, pos))) {
        std::cout << "File name check error" << std::endl;
        return false;
    }
    std::vector<std::string> validFileNames = {
        "mouse", "keyboard", "joystick", "trackball", "remotecontrol",
        "trackpad", "knob", "gamepad", "touchpad", "touchscreen",
        "pen", "pc", "all"
    };
    std::string deviceName = fileName.substr(pos + 1);
    bool result = std::any_of(validFileNames.begin(), validFileNames.end(), [deviceName](const std::string& str) {
        return str == deviceName;
        });
    if (!result) {
        std::cout << "Check device file name:" << fileName << std::endl;
    }
    return result;
}

static void RemoveDir(const std::string& filePath)
{
    if (filePath.empty()) {
        std::cout << "File path is empty" << std::endl;
        return;
    }
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        std::cout << "Failed to open folder:" << filePath << std::endl;
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
            if (remove(rmFile.c_str()) != 0) {
                std::cout << "Remove file:" << rmFile << " failed" << std::endl;
            }
        } else if (ptr->d_type == DT_DIR) {
            RemoveDir((filePath + ptr->d_name + "/"));
        } else {
            std::cout << "File name:" << ptr << " type is error" << std::endl;
        }
    }
    if (closedir(dir) != 0) {
        std::cout << "Close dir:" << filePath << " failed" << std::endl;
    }
    if (std::remove(filePath.c_str()) != 0) {
        std::cout << "Remove dir:" << filePath <<" failed" << std::endl;
    }
}

static void StartMouse()
{
    static VirtualMouse virtualMouse;
    virtualMouse.SetUp();
}

static void StartKeyboard()
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

static void StartJoystick()
{
    static VirtualJoystick virtualJoystick;
    virtualJoystick.SetUp();
}

static void StartTrackball()
{
    static VirtualTrackball virtualTrackball;
    virtualTrackball.SetUp();
}

static void StartRemoteControl()
{
    static VirtualRemoteControl virtualRemoteControl;
    virtualRemoteControl.SetUp();
}

static void StartTrackpad()
{
    static VirtualTrackpad virtualTrackpad;
    virtualTrackpad.SetUp();
    static VirtualTrackpadMouse virtualMousepadMouse;
    virtualMousepadMouse.SetUp();
    static VirtualTrackpadSysCtrl virtualTrackpadSysCtrl;
    virtualTrackpadSysCtrl.SetUp();
}

static void StartPc()
{
    static VirtualPcTouchpad virtualPcTouchpad;
    virtualPcTouchpad.SetUp();
    static VirtualPcSwitch virtualPcSwitch;
    virtualPcSwitch.SetUp();
}

static void StartKnob()
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

static void StartGamePad()
{
    static VirtualGamePad virtualGamePad;
    virtualGamePad.SetUp();
}

static void StartTouchPad()
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

static void StartTouchScreen()
{
    static VirtualTouchScreen virtualTouchScreen;
    virtualTouchScreen.SetUp();
    static VirtualSingleTouchScreen virtualSingleTouchScreen;
    virtualSingleTouchScreen.SetUp();
}

static void StartPen()
{
    static VirtualPen virtualPen;
    virtualPen.SetUp();
    static VirtualPenMouse virtualPenMouse;
    virtualPenMouse.SetUp();
    static VirtualPenKeyboard virtualPenKeyboard;
    virtualPenKeyboard.SetUp();
}

static void StartFingerprint()
{
    static VirtualFingerprintKey fingerprintKey;
    fingerprintKey.SetUp();
    static VirtualFingerprintMouse fingerprintMouse;
    fingerprintMouse.SetUp();
}

static void StartCrown()
{
    static VirtualCrown virtualCrown;
    virtualCrown.SetUp();
}

static void StartUwbRemoteControl()
{
    static VirtualUwbRemoteControl virtualUwbRemoteControl;
    virtualUwbRemoteControl.SetUp();
}

using VirtualFun = void (*)();
std::map<std::string, VirtualFun> mapFun = {
    {"mouse", &StartMouse},
    {"keyboard", &StartKeyboard},
    {"joystick", &StartJoystick},
    {"trackball", &StartTrackball},
    {"remotecontrol", &StartRemoteControl},
    {"trackpad", &StartTrackpad},
    {"knob", &StartKnob},
    {"gamepad", &StartGamePad},
    {"touchpad", &StartTouchPad},
    {"pc", &StartPc},
    {"touchscreen", &StartTouchScreen},
    {"pen", &StartPen},
    {"fingerprint", &StartFingerprint},
    {"crown", &StartCrown},
    {"uwbremotecontrol", &StartUwbRemoteControl}
};

static void StartAllDevices()
{
    if (mapFun.empty()) {
        std::cout << "mapFun is empty" << std::endl;
        return;
    }
    for (const auto &item : mapFun) {
        (*item.second)();
    }
}
} // namespace

VirtualDevice::VirtualDevice(const std::string& deviceName, uint16_t busType,
    uint16_t vendorId, uint16_t productId)
    : deviceName_(deviceName),
      busTtype_(busType),
      vendorId_(vendorId),
      productId_(productId),
      version_(1) {}

VirtualDevice::~VirtualDevice()
{
    Close();
}

std::vector<std::string> VirtualDevice::BrowseDirectory(const std::string& filePath)
{
    std::vector<std::string> fileList;
    DIR* dir = opendir(filePath.c_str());
    if (dir == nullptr) {
        std::cout << "Failed to open folder" << std::endl;
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
        std::cout << "Close dir:" << filePath << " failed" << std::endl;
    }
    return fileList;
}

bool VirtualDevice::ClearFileResidues(const std::string& fileName)
{
    const std::string::size_type pos = fileName.find("_");
    const std::string processPath = "/proc/" + fileName.substr(0, pos) + "/";
    const std::string filePath = processPath + "cmdline";
    std::string temp;
    std::string processName;
    DIR *dir = nullptr;
    if (!CheckFileName(fileName)) {
        std::cout << "File name check error" << std::endl;
        goto RELEASE_RES1;
    }
    if (pos == std::string::npos) {
        std::cout << "Failed to create file" << std::endl;
        goto RELEASE_RES1;
    }
    if (!IsFileExists(processPath)) {
        std::cout <<  processPath << " folder does not exist" << std::endl;
        goto RELEASE_RES1;
    }
    dir = opendir(processPath.c_str());
    if (dir == nullptr) {
        std::cout << "Useless flag file:" << processPath << std::endl;
        goto RELEASE_RES1;
    }
    temp = ReadUinputToolFile(filePath);
    if (temp.empty()) {
        std::cout << "Temp is empty" << std::endl;
        goto RELEASE_RES2;
    }
    processName.append(temp);
    if (processName.find(VIRTUAL_DEVICE_NAME.c_str()) == std::string::npos) {
        std::cout << "Process name is wrong" << std::endl;
        goto RELEASE_RES2;
    }
    return true;
    RELEASE_RES1:
    if (remove((g_folderPath + fileName).c_str()) != 0) {
        std::cout << "Remove file failed" << std::endl;
    }
    return false;
    RELEASE_RES2:
    if (closedir(dir) != 0) {
        std::cout << "Close dir failed" << std::endl;
    }
    if (remove((g_folderPath + fileName).c_str()) != 0) {
        std::cout << "Remove file failed" << std::endl;
    }
    return false;
}

bool VirtualDevice::CreateKey()
{
    auto fun = [&](int32_t uiSet, const std::vector<uint32_t>& list) ->bool {
        for (const auto &item : list) {
            if (ioctl(fd_, uiSet, item) < 0) {
                std::cout << __func__ << " not setting event type:" << item
                    << ", deviceName:" << deviceName_ << std::endl;
                return false;
            }
        }
        return true;
    };
    std::map<int32_t, std::vector<uint32_t>> uinputTypes;
    uinputTypes[UI_SET_EVBIT] = GetEventTypes();
    uinputTypes[UI_SET_KEYBIT] = GetKeys();
    uinputTypes[UI_SET_PROPBIT] = GetProperties();
    uinputTypes[UI_SET_ABSBIT] = GetAbs();
    uinputTypes[UI_SET_RELBIT] = GetRelBits();
    uinputTypes[UI_SET_MSCBIT] = GetMiscellaneous();
    uinputTypes[UI_SET_LEDBIT] = GetLeds();
    uinputTypes[UI_SET_SWBIT] = GetSwitches();
    uinputTypes[UI_SET_FFBIT] = GetRepeats();

    for (const auto &item : uinputTypes) {
        if (!fun(item.first, item.second)) {
            return false;
        }
    }
    return true;
}

bool VirtualDevice::SetAbsResolution()
{
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
        {"Virtual Crown",                "mouse"},
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
        {"Virtual PcSwitch",             "pc"},
        {"Virtual PcTouchPad",           "pc"},
        {"Virtual RemoteControl",        "remotecontrol"},
        {"Virtual Joystick",             "joystick"},
        {"Virtual GamePad",              "gamepad"},
        {"Virtual Trackball",            "trackball"},
        {"Virtual TouchScreen",          "touchscreen"},
        {"Virtual SingleTouchScreen",    "touchscreen"},
        {"V-Pencil",                     "pen"},
        {"V-Pencil-mouse",               "pen"},
        {"V-Pencil-keyboard",            "pen"},
        {"Virtual UWB RemoteControl",    "uwbremotecontrol"}
    };
    std::string deviceType = typeDevice.find(deviceName)->second;
    phys.append(deviceType).append(g_pid).append("/").append(g_pid);

    if (ioctl(fd_, UI_SET_PHYS, phys.c_str()) < 0) {
        std::cout << "Failed to set uinput phys" << std::endl;
        return false;
    }
    return true;
}

bool VirtualDevice::DoIoctl(int32_t fd, int32_t request, const uint32_t value)
{
    int32_t rc = ioctl(fd, request, value);
    if (rc < 0) {
        std::cout << "Failed to ioctl" << std::endl;
        return false;
    }
    return true;
}

void VirtualDevice::SetDeviceId()
{
    uinputDev_.id.bustype = busTtype_;
    uinputDev_.id.vendor = vendorId_;
    uinputDev_.id.product = productId_;
    uinputDev_.id.version = version_;
}

bool VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        std::cout << "Failed to open uinput: " << fd_ << std::endl;
        return false;
    }

    if (strncpy_s(uinputDev_.name, sizeof(uinputDev_.name), deviceName_.c_str(), deviceName_.size()) != 0) {
        std::cout << "Failed to copied device name: " << uinputDev_.name << std::endl;
        return false;
    };
    SetDeviceId();
    if (!SetAbsResolution()) {
        std::cout << "Failed to set uinput abs resolution" << std::endl;
        return false;
    }
    if (!SetPhys(deviceName_)) {
        std::cout << "Failed to set uinput phys" << std::endl;
        return false;
    }
    if (!CreateKey()) {
        std::cout << "Failed to create uinput KeyValue" << std::endl;
        return false;
    }
    if (write(fd_, &uinputDev_, sizeof(uinputDev_)) < 0) {
        std::cout << "Unable to write device info to target" << std::endl;
        return false;
    }
    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        std::cout << "Try to create uinput device filed in fd: " << fd_ << std::endl;
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

std::string VirtualDevice::ReadFile(const std::string& filePath)
{
    FILE* fp = fopen(filePath.c_str(), "r");
    if (fp == nullptr) {
        std::cout << "Failed to open file: " << filePath << std::endl;
        return "";
    }
    std::string dataStr;
    char buf[256] = {};
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        dataStr += buf;
    }
    if (fclose(fp) != 0) {
        std::cout << "Failed to close file" << std::endl;
    }
    return dataStr;
}

int32_t VirtualDevice::GetFileSize(const std::string& filePath)
{
    struct stat statbuf = { 0 };
    if (stat(filePath.c_str(), &statbuf) != 0) {
        std::cout << "Get file size error" << std::endl;
        return INVALID_FILE_SIZE;
    }
    return statbuf.st_size;
}

std::string VirtualDevice::ReadUinputToolFile(const std::string& filePath)
{
    if (filePath.empty()) {
        std::cout << "FilePath is empty" << std::endl;
        return "";
    }
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        std::cout << "Path is error" << std::endl;
        return "";
    }
    if (!IsValidUinputPath(realPath)) {
        std::cout << "File path is error" << std::endl;
        return "";
    }
    if (!IsFileExists(realPath)) {
        std::cout << "File not exist" << std::endl;
        return "";
    }
    int32_t fileSize = GetFileSize(realPath);
    if ((fileSize < 0) || (fileSize > FILE_SIZE_MAX)) {
        std::cout << "File size out of read range" << std::endl;
        return "";
    }
    return ReadFile(filePath);
}

bool VirtualDevice::CreateHandle(const std::string& deviceArgv)
{
    if (deviceArgv == "all") {
        StartAllDevices();
        return true;
    }
    if (mapFun.find(deviceArgv) == mapFun.end()) {
        std::cout << "Please enter the device type correctly" << std::endl;
        return false;
    }
    (*mapFun[deviceArgv])();
    return true;
}

bool VirtualDevice::AddDevice(const std::string& startDeviceName)
{
    if (startDeviceName.empty()) {
        std::cout << "StartDeviceName is empty" << std::endl;
        return false;
    }
    if (!CreateHandle(startDeviceName)) {
        std::cout << "Failed to start device: " << startDeviceName <<std::endl;
        return false;
    }
    std::string symbolFile;
    symbolFile.append(g_folderPath).append(g_pid).append("_").append(startDeviceName);
    std::ofstream flagFile;
    flagFile.open(symbolFile.c_str());
    if (!flagFile.is_open()) {
        std::cout << "Failed to create file" <<std::endl;
        return false;
    }
    flagFile.close();
    return true;
}

bool VirtualDevice::CloseDevice(const std::string& closeDeviceName, const std::vector<std::string>& deviceList)
{
    if (deviceList.empty()) {
        RemoveDir(g_folderPath);
        std::cout << "No start device" <<std::endl;
        return false;
    }
    if (closeDeviceName == "all") {
        for (const auto &it : deviceList) {
            kill(std::stoi(it), SIGKILL);
        }
        RemoveDir(g_folderPath);
        return true;
    }
    for (const auto &it : deviceList) {
        if (it.find(closeDeviceName) == 0) {
            kill(std::stoi(it), SIGKILL);
            remove((g_folderPath + it).c_str());
            if (BrowseDirectory(g_folderPath).empty()) {
                    RemoveDir(g_folderPath);
            }
            return true;
        }
    }
    std::cout << "Device shutdown failed! The PID format is incorrect" <<std::endl;
    return false;
}

bool VirtualDevice::CheckCommand(int32_t argc, char **argv)
{
    int32_t c = -1;
    if (!SelectOptions(argc, argv, c)) {
        std::cout << "Select option failed" << std::endl;
        return false;
    }
    if (!IsFileExists(g_folderPath)) {
        mkdir(g_folderPath.c_str(), FILE_POWER);
    }
    switch (c) {
        case 'L': {
            if (!ListOption(argc, argv)) {
                std::cout << "Device query failed" << std::endl;
                return false;
            }
            break;
        }
        case 'S': {
            if (!StartOption(argc, argv)) {
                std::cout << "Device start failed" << std::endl;
                return false;
            }
            break;
        }
        case 'C': {
            if (!CloseOption(argc, argv)) {
                std::cout << "Device close failed" << std::endl;
                return false;
            }
            break;
        }
        case '?': {
            if (!HelpOption(argc, argv)) {
                std::cout << "Failed to ask for help" << std::endl;
                return false;
            }
            break;
        }
        default: {
            std::cout << "The command line format is incorrect" << std::endl;
            return false;
        }
    }
    return true;
}

bool VirtualDevice::SelectOptions(int32_t argc, char **argv, int32_t &opt)
{
    if (argc < PARAMETERS_QUERY_NUMBER) {
        std::cout << "Please enter options or parameters" << std::endl;
        return false;
    }
    struct option longOptions[] = {
        {"list", no_argument, nullptr, 'L'},
        {"start", no_argument, nullptr, 'S'},
        {"close", no_argument, nullptr, 'C'},
        {"help", no_argument, nullptr, '?'},
        {nullptr, 0, nullptr, 0}
    };
    std::string inputOptions = argv[optind];
    if (inputOptions.find('-') == inputOptions.npos) {
        for (uint32_t i = 0; i < sizeof(longOptions) / sizeof(struct option) - 1; ++i) {
            if (longOptions[i].name == inputOptions) {
                opt = longOptions[i].val;
                optind++;
                break;
            }
        }
    } else if ((inputOptions.length() != PARAMETERS_QUERY_NUMBER) &&
               (inputOptions[inputOptions.find('-') + 1] != '-')) {
        std::cout << "More than one short option is not supported" << std::endl;
        return false;
    } else {
        int32_t optionIndex = 0;
        opt = getopt_long(argc, argv, "LSC?", longOptions, &optionIndex);
    }
    if (opt == -1) {
        std::cout << "Nonstandard input parameters" << std::endl;
        return false;
    }
    return true;
}

bool VirtualDevice::ListOption(int32_t argc, char **argv)
{
    if (argc != PARAMETERS_QUERY_NUMBER) {
        std::cout << "Invalid Input Param, Please Check the validity of the para" << std::endl;
        return false;
    }
    std::vector<std::string> deviceList = BrowseDirectory(g_folderPath);
    if (deviceList.empty()) {
        std::cout << "No device information to query" << std::endl;
        return true;
    }
    std::string::size_type pos;
    std::cout << "PID\tDEVICE" << std::endl;
    for (const auto &item : deviceList) {
        pos = item.find("_");
        if (pos != std::string::npos) {
            std::cout << item.substr(0, pos) << "\t" << item.substr(pos + 1, item.size() - pos - 1) << std::endl;
        }
    }
    return true;
}

bool VirtualDevice::StartOption(int32_t argc, char **argv)
{
    if (argc != PARAMETERS_NUMBER) {
        std::cout << "Invalid Input Param, Please Check the validity of the para" << std::endl;
        return false;
    }
    if (!AddDevice(argv[optind])) {
        std::cout << "Failed to create device" << std::endl;
        return false;
    }
    while (true) {
        usleep(SLEEP_TIME);
    }
    return true;
}

bool VirtualDevice::CloseOption(int32_t argc, char **argv)
{
    std::vector<std::string> deviceList = BrowseDirectory(g_folderPath);
    if (argc != PARAMETERS_NUMBER) {
        std::cout << "Invalid Input Param, Please Check the validity of the para" << std::endl;
        return false;
    }
    if (!CloseDevice(argv[optind], deviceList)) {
        std::cout << "Failed to closed device" << std::endl;
        return false;
    }
    std::cout << "device closed successfully" << std::endl;
    return true;
}

bool VirtualDevice::HelpOption(int32_t argc, char **argv)
{
    if (argc != PARAMETERS_QUERY_NUMBER) {
        std::cout << "Invalid Input Param, Please Check the validity of the para" << std::endl;
        return false;
    }
    ShowUsage();
    return true;
}

void VirtualDevice::SetResolution(const ResolutionInfo& resolutionInfo)
{
    uinputAbs_.code = resolutionInfo.axisCode;
    uinputAbs_.absinfo.resolution = resolutionInfo.absResolution;
    absInit_.push_back(uinputAbs_);
}

void VirtualDevice::SetAbsValue(const AbsInfo& absInfo)
{
    uinputDev_.absmin[absInfo.code] = absInfo.minValue;
    uinputDev_.absmax[absInfo.code] = absInfo.maxValue;
    uinputDev_.absfuzz[absInfo.code] = absInfo.fuzz;
    uinputDev_.absflat[absInfo.code] = absInfo.flat;
}

const std::vector<uint32_t>& VirtualDevice::GetEventTypes() const
{
    return eventTypes_;
}

const std::vector<uint32_t>& VirtualDevice::GetKeys() const
{
    return keys_;
}

const std::vector<uint32_t>& VirtualDevice::GetProperties() const
{
    return properties_;
}

const std::vector<uint32_t>& VirtualDevice::GetAbs() const
{
    return abs_;
}

const std::vector<uint32_t>& VirtualDevice::GetRelBits() const
{
    return relBits_;
}

const std::vector<uint32_t>& VirtualDevice::GetLeds() const
{
    return leds_;
}

const std::vector<uint32_t>& VirtualDevice::GetRepeats() const
{
    return repeats_;
}

const std::vector<uint32_t>& VirtualDevice::GetMiscellaneous() const
{
    return miscellaneous_;
}

const std::vector<uint32_t>& VirtualDevice::GetSwitches() const
{
    return switches_;
}

void VirtualDevice::ShowUsage()
{
    std::cout << "Usage: vuinput <option> <command> <arg>..."      << std::endl;
    std::cout << "The option are:                                " << std::endl;
    std::cout << "commands for list:                             " << std::endl;
    std::cout << "-L      --list        list    -display virtual devices and pid information" << std::endl;
    std::cout << "commands for start:                            " << std::endl;
    std::cout << "-S <device> &   --start <device> &    start <device> &     -start a device" << std::endl;
    std::cout << " -start supported <device>-" << std::endl;
    std::cout << "  mouse"         << std::endl;
    std::cout << "  keyboard"      << std::endl;
    std::cout << "  joystick"      << std::endl;
    std::cout << "  trackball"     << std::endl;
    std::cout << "  remotecontrol" << std::endl;
    std::cout << "  trackpad"      << std::endl;
    std::cout << "  knob"          << std::endl;
    std::cout << "  gamepad"       << std::endl;
    std::cout << "  touchpad"      << std::endl;
    std::cout << "  touchscreen"   << std::endl;
    std::cout << "  pen"           << std::endl;
    std::cout << "-S all &        --start all &        start all &           -start devices " << std::endl;
    std::cout << "commands for close:                                                       " << std::endl;
    std::cout << "-C <pid>        --close <pid>        close <pid>           -close a pid   " << std::endl;
    std::cout << "-C all          --close all          close all             -close pids    " << std::endl;
    std::cout << "-?  --help   help                                                         " << std::endl;
}
} // namespace MMI
} // namespace OHOS
