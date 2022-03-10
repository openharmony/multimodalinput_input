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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "HdiInject" };
} // namespace

bool HdiInject::Init(UDSServer &sess)
{
    udsServerPtr_ = &sess;
    StartHdiserver();
    return true;
}

int32_t HdiInject::ManageHdfInject(const SessionPtr sess, NetPacket &pkt)
{
    MMI_LOGI("into function ManageHdfInject");
    int32_t sendType = 0;
    pkt >> sendType;
    uint32_t devIndex = 0;
    uint32_t devSatatus = 0;
    RawInputEvent speechEvent = {};
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
    return RET_OK;
}

int32_t HdiInject::OnSetEventInject(const RawInputEvent& allEvent, int32_t devIndex)
{
    CALL_LOG_ENTER;
    EventPackage* pack[EVENT_PACKAGE_ARROW_SIZE];
    pack[0] = (EventPackage*)malloc(sizeof(EventPackage));
    pack[0]->type = static_cast<int32_t>(allEvent.ev_type);
    pack[0]->code = static_cast<uint32_t>allEvent.ev_code;
    pack[0]->value = static_cast<int32_t>(allEvent.ev_value);
    pack[0]->timestamp = static_cast<uint64_t>(GetSysClockTime());
    MMIHdiInject->eventcallback_.EventPkgCallback((const EventPackage**)pack, 1, devIndex);
    free(pack[0]);
    return RET_OK;
}

void HdiInject::OnSetHotPlugs(uint32_t devIndex, uint32_t devSatatus)
{
    if (!(ReportHotPlugEvent(devIndex, devSatatus))) {
        MMI_LOGE("ReportHotPlugEvent faild");
        return;
    }
    MMI_LOGI("ReportHotPlugEvent success");
}

void HdiInject::InitDeviceInfo()
{
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
    auto iter = deviceArray_.insert(deviceArray_.begin(), deviceInfoArray, deviceInfoArray + counts);
    if (!iter.second) {
        MMI_LOGE("Insert value failed");
    }
}

void HdiInject::StartHdiserver()
{
    initStatus_ = true;
}

void HdiInject::OnInitHdiServerStatus()
{
    StartHdiserver();
}

void HdiInject::ShowAllDeviceInfo()
{
    for (const auto &item : deviceArray_) {
        MMI_LOGI("deviceName:%{public}s,devIndex:%{public}d,status:%{public}d,devType:%{public}d",
            item.chipName, item.devIndex, item.status, item.devType);
    }
}

int32_t HdiInject::GetDeviceCount()
{
    return static_cast<int32_t>(deviceArray_.size());
}

bool HdiInject::SetDeviceHotStatus(int32_t devIndex, int32_t status)
{
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
    return false;
}

bool HdiInject::SyncDeviceHotStatus()
{
    const uint16_t count = static_cast<uint16_t>(deviceArray_.size());
    event_ = (HotPlugEvent**)malloc(count * sizeof(HotPlugEvent));
    CHKPF(event_);
    for (int32_t i = 0; i < count; i++) {
        event_[i]->devIndex = deviceArray_[i].devIndex;
        event_[i]->devType = deviceArray_[i].devType;
        event_[i]->status = deviceArray_[i].status;
        MMIHdiInject->hotPlugcallback_.HotPlugCallback((const HotPlugEvent*)&event_[i]);
    }
    return true;
}

bool HdiInject::ReportHotPlugEvent()
{
    SyncDeviceHotStatus();
    MMIHdiInject->hotPlugcallback_.HotPlugCallback(*event_);
    return true;
}

bool HdiInject::ReportHotPlugEvent(uint32_t devIndex, uint32_t status)
{
    if (!(SetDeviceHotStatus(devIndex, status))) {
        MMI_LOGE("SetDeviceHotStatus error devIndex:%{public}d,status:%{public}d", devIndex, status);
        return false;
    }
    int32_t devType = GetDevTypeIndex(devIndex);
    if (devType == -1) {
        return false;
    }
    HotPlugEvent event = {
        static_cast<uint32_t>(devIndex),
        static_cast<uint32_t>(devType),
        static_cast<uint32_t>(status)
    };
    MMIHdiInject->hotPlugcallback_.HotPlugCallback(&event);
    return true;
}

int32_t HdiInject::GetDevTypeIndex(int32_t devIndex)
{
    for (const auto &item : deviceArray_) {
        if (item.devIndex == devIndex) {
            return item.devType;
        }
    }
    return RET_ERR;
}

int32_t HdiInject::GetDevIndexType(int32_t devType)
{
    vector<DeviceInformation>::iterator iter;
    for (const auto &item : deviceArray_) {
        if (item.devType == devType) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}

int32_t HdiInject::ScanInputDevice(uint32_t arrLen, DevDesc *staArr)
{
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
    MMIHdiInject->eventcallback_.EventPkgCallback = callback->EventPkgCallback;
    return 0;
}

static int32_t UnregisterReportCallback(uint32_t devIndex)
{
    return 0;
}

static int32_t RegisterHotPlugCallback(InputHostCb *callback)
{
    MMIHdiInject->hotPlugcallback_.HotPlugCallback = callback->HotPlugCallback;
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
    MMIHdiInject->InitDeviceInfo();
    int32_t ret = 0;
    IInputInterface* injectInterface = new(IInputInterface);
    *interface = injectInterface;
    injectInterface->iInputController = &interfaceControl;
    injectInterface->iInputManager = &interfaceManager;
    injectInterface->iInputReporter = &interfaceReport;
    return ret;
}
#endif