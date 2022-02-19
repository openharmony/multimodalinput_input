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

#include "hdi_inject.h"
#include <iostream>
#include "singleton.h"
#include "libmmi_util.h"
#include "proto.h"
#include "util.h"

#ifdef OHOS_BUILD_HDF
using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "HdiInject" };
}

bool HdiInject::Init(UDSServer &sess)
{
    MMI_LOGD("enter");
    udsServerPtr_ = &sess;
    StartHdiserver();
    MMI_LOGD("leave");
    return true;
}

int32_t HdiInject::ManageHdfInject(const SessionPtr sess, NetPacket &pkt)
{
    MMI_LOGD("enter");
    MMI_LOGI("into function ManageHdfInject");
    int32_t sendType = 0;
    uint32_t devIndex = 0;
    uint32_t devSatatus = 0;
    RawInputEvent speechEvent = {};
    vector<RawInputEvent> allEvent;
    pkt >> sendType;
    switch (sendType) {
        case GET_STATUS_INFO:
            OnInitHdiServerStatus();
            break;
        case SET_EVENT_INJECT:
            pkt >> devIndex >> speechEvent;
            MMI_LOGI("hdi server recv massage: devIndex:%{public}d", devIndex);
            OnSetEventInject(speechEvent, devIndex);
            break;
        case SHOW_DEVICE_INFO:
            ShowAllDeviceInfo();
            break;
        case SET_HOT_PLUGS:
            pkt >> devIndex >> devSatatus;
            MMI_LOGI("recv inject tool hot data, devIndex:%{public}d,status:%{public}d", devIndex, devSatatus);
            OnSetHotPlugs(devIndex, devSatatus);
            break;
        default:
            MMI_LOGE("The message type:%{public}d cannot be processed", sendType);
            return RET_ERR;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t HdiInject::OnSetEventInject(const RawInputEvent& allEvent, int32_t devIndex)
{
    MMI_LOG("enter");
    EventPackage* pack[EVENT_PACKAGE_ARROW_SIZE];
    pack[0] = (EventPackage*)malloc(sizeof(EventPackage));
    pack[0]->type = (int32_t)allEvent.ev_type;
    pack[0]->code = (uint32_t)allEvent.ev_code;
    pack[0]->value = (int32_t)allEvent.ev_value;
    pack[0]->timestamp = GetSysClockTime();
    MMIHdiInject->eventcallback_.EventPkgCallback((const EventPackage**)pack, 1, devIndex);
    free(pack[0]);
    MMI_LOGD("leave");

    return RET_OK;
}

void HdiInject::OnSetHotPlugs(uint32_t devIndex, uint32_t devSatatus)
{
    MMI_LOGD("enter");
    if (!(ReportHotPlugEvent(devIndex, devSatatus))) {
        MMI_LOGE("OnSetHotPlugs ReportHotPlugEvent faild");
        return;
    }
    MMI_LOGI("OnSetHotPlugs ReportHotPlugEvent success");
    MMI_LOGD("leave");
}

void HdiInject::InitDeviceInfo()
{
    MMI_LOGD("enter");
    DeviceInformation deviceInfoArray[] = {
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_POINTER_INDEX, HDF_MOUSE_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "mouse"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_KEYBOARD_INDEX, HDF_KEYBOARD_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "keyboard"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_TOUCH_INDEX, HDF_TOUCH_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "touch"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_TABLET_TOOL_INDEX, HDF_TABLET_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "pen"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_TABLET_PAD_INDEX, HDF_TABLET_PAD_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "pad"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_FINGER_INDEX, HDF_TOUCH_FINGER_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "finger"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_SWITCH_INDEX, HDF_SWITCH_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "knob"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_TRACKPAD5_INDEX, HDF_TRACK_PAD_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "trackPad"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_JOYSTICK_INDEX, HDF_JOYSTICK_DEV_TYPE,
            HDF_DEVICE_FD_DEFAULT_STATUS, "joyStick"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_GAMEPAD_INDEX, HDF_GAMEPAD_DEV_TYPE,
            HDF_DEVICE_FD_DEFAULT_STATUS, "gamePad"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_TOUCH_PAD, HDF_TOUCH_PAD_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "touchPad"},
        {HDI_DEVICE_REMOVE_STATUS, INPUT_DEVICE_REMOTE_CONTROL, HDF_TRACK_BALL_DEV_TYPE,
         HDF_DEVICE_FD_DEFAULT_STATUS, "remoteControl"},
    };
    int32_t counts = sizeof(deviceInfoArray) / sizeof(DeviceInformation);
    deviceArray_.insert(deviceArray_.begin(), deviceInfoArray, deviceInfoArray + counts);
    MMI_LOGD("leave");
}

void HdiInject::StartHdiserver()
{
    MMI_LOGD("enter");
    initStatus_ = true;
}

void HdiInject::OnInitHdiServerStatus()
{
    MMI_LOGD("enter");
    StartHdiserver();
}

void HdiInject::ShowAllDeviceInfo()
{
    MMI_LOGD("enter");
    for (const auto &item : deviceArray_) {
        MMI_LOGI("deviceName:%{public}s,devIndex:%{public}d,status:%{public}d,devType:%{public}d",
            item.chipName, item.devIndex, item.status, item.devType);
    }
    MMI_LOGD("leave");
}

int32_t HdiInject::GetDeviceCount()
{
    MMI_LOGD("enter");
    return static_cast<int32_t>(deviceArray_.size());
}

bool HdiInject::SetDeviceHotStatus(int32_t devIndex, int32_t status)
{
    MMI_LOGD("enter");
    for (auto iter = deviceArray_.begin(); iter != deviceArray_.end(); ++iter) {
        if (iter->devIndex == devIndex) {
            if (iter->status == status) {
                MMI_LOGE("Failed to find status");
                return false;
            }
            iter->status = ~status + 1;
            return true;
        }
    }
    MMI_LOGD("leave");
    return false;
}

bool HdiInject::SyncDeviceHotStatus()
{
    MMI_LOGD("enter");
    const uint16_t count = static_cast<uint16_t>(deviceArray_.size());
    event_ = (HotPlugEvent**)malloc(count * sizeof(HotPlugEvent));
    CHKPF(event_);
    for (int32_t i = 0; i < count; i++) {
        event_[i]->devIndex = deviceArray_[i].devIndex;
        event_[i]->devType = deviceArray_[i].devType;
        event_[i]->status = deviceArray_[i].status;
        MMIHdiInject->hotPlugcallback_.HotPlugCallback((const HotPlugEvent*)&event_[i]);
    }
    MMI_LOGD("leave");
    return true;
}

bool HdiInject::ReportHotPlugEvent()
{
    MMI_LOGD("enter");
    SyncDeviceHotStatus();
    MMIHdiInject->hotPlugcallback_.HotPlugCallback(*event_);
    MMI_LOGD("leave");
    return true;
}

bool HdiInject::ReportHotPlugEvent(uint32_t devIndex, uint32_t status)
{
    MMI_LOGD("enter");
    if (!(SetDeviceHotStatus(devIndex, status))) {
        MMI_LOGE("SetDeviceHotStatus error devIndex:%{public}d,status:%{public}d", devIndex, status);
        return false;
    }
    int32_t devType = GetDevTypeByIndex(devIndex);
    if (devType == -1) {
        return false;
    }
    HotPlugEvent event = {
        static_cast<uint32_t>(devIndex),
        static_cast<uint32_t>(devType),
        static_cast<uint32_t>(status)
    };
    MMIHdiInject->hotPlugcallback_.HotPlugCallback(&event);
    MMI_LOGD("leave");
    return true;
}

int32_t HdiInject::GetDevTypeByIndex(int32_t devIndex)
{
    MMI_LOGD("enter");
    for (const auto &item : deviceArray_) {
        if (item.devIndex == devIndex) {
            return item.devType;
        }
    }
    MMI_LOGD("leave");
    return RET_ERR;
}

int32_t HdiInject::GetDevIndexByType(int32_t devType)
{
    MMI_LOGD("enter");
    vector<DeviceInformation>::iterator iter;
    for (const auto &item : deviceArray_) {
        if (item.devType == devType) {
            return item.devIndex;
        }
    }
    MMI_LOGD("leave");
    return RET_ERR;
}

int32_t HdiInject::ScanInputDevice(uint32_t arrLen, DevDesc *staArr)
{
    MMI_LOGD("enter");
    uint16_t count = static_cast<uint16_t>(deviceArray_.size());
    int32_t index = 0;
    for (int i = 0; i < count; i++) {
        if (deviceArray_[i].status == 1) {
            continue;
        }
        staArr[index].devIndex = deviceArray_[i].devIndex;
        staArr[index].devType = deviceArray_[i].devType;
        index++;
    }
    MMI_LOGD("leave");
    return 0;
}

static int32_t ScanInputDevice(uint32_t arrLen, DevDesc *staArr)
{
    return MMIHdiInject->ScanInputDevice(arrLen, staArr);
}

static int32_t OpenInputDevice(uint32_t devIndex)
{
    return 0;
}

static int32_t CloseInputDevice(uint32_t devIndex)
{
    return 0;
}

static int32_t GetInputDevice(uint32_t devIndex, DeviceInfo **devInfo)
{
    return 0;
}

static int32_t GetInputDeviceList(uint32_t *devNum, DeviceInfo **devList, uint32_t size)
{
    return 0;
}

static int32_t SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    return 0;
}

static int32_t GetPowerStatus(uint32_t devIndex, uint32_t *status)
{
    return 0;
}

static int32_t GetDeviceType(uint32_t devIndex, uint32_t *deviceType)
{
    return 0;
}

static int32_t GetChipInfo(uint32_t devIndex, char *chipInfo, uint32_t length)
{
    return 0;
}

static int32_t GetVendorName(uint32_t devIndex, char *vendorName, uint32_t length)
{
    return 0;
}


static int32_t GetChipName(uint32_t devIndex, char *chipName, uint32_t length)
{
    return 0;
}

static int32_t SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    return 0;
}

static int32_t RunCapacitanceTest(uint32_t devIndex, uint32_t testType, char *result, uint32_t length)
{
    return 0;
}

static int32_t RunExtraCommand(uint32_t devIndex, InputExtraCmd *cmd)
{
    return 0;
}

static int32_t RegisterReportCallback(uint32_t devIndex, InputEventCb *callback)
{
    MMI_LOGD("enter");
    MMIHdiInject->eventcallback_.EventPkgCallback = callback->EventPkgCallback;
    MMI_LOGD("leave");
    return 0;
}

static int32_t UnregisterReportCallback(uint32_t devIndex)
{
    return 0;
}

static int32_t RegisterHotPlugCallback(InputHostCb *callback)
{
    MMI_LOGD("enter");
    MMIHdiInject->hotPlugcallback_.HotPlugCallback = callback->HotPlugCallback;
    MMI_LOGD("leave");
    return 0;
}

static int32_t UnregisterHotPlugCallback(void)
{
    return 0;
}

static InputManager interfaceManager = {
    .ScanInputDevice = ScanInputDevice,
    .OpenInputDevice = OpenInputDevice,
    .CloseInputDevice = CloseInputDevice,
    .GetInputDevice = GetInputDevice,
    .GetInputDeviceList = GetInputDeviceList,
};

static InputController interfaceControl = {
    .SetPowerStatus = SetPowerStatus,
    .GetPowerStatus = GetPowerStatus,
    .GetDeviceType = GetDeviceType,
    .GetChipInfo = GetChipInfo,
    .GetVendorName = GetVendorName,
    .GetChipName = GetChipName,
    .SetGestureMode = SetGestureMode,
    .RunCapacitanceTest = RunCapacitanceTest,
    .RunExtraCommand = RunExtraCommand,
};

static InputReporter interfaceReport = {
    .RegisterReportCallback = RegisterReportCallback,
    .UnregisterReportCallback = UnregisterReportCallback,
    .RegisterHotPlugCallback = RegisterHotPlugCallback,
    .UnregisterHotPlugCallback = UnregisterHotPlugCallback,
};

int32_t GetInputInterfaceFromInject(IInputInterface **interface)
{
    MMI_LOGD("enter");
    MMIHdiInject->InitDeviceInfo();
    int32_t ret = 0;
    IInputInterface* injectInterface = new(IInputInterface);
    *interface = injectInterface;
    injectInterface->iInputController = &interfaceControl;
    injectInterface->iInputManager = &interfaceManager;
    injectInterface->iInputReporter = &interfaceReport;
    MMI_LOGD("leave");
    return ret;
}
#endif