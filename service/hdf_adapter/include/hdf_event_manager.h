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
#ifndef OHOS_HDF_EVENT_MANAGER_H
#define OHOS_HDF_EVENT_MANAGER_H

#include <iostream>
#include <functional>
#include <map>
#include <list>
#include "input_manager.h"
#include "libinput.h"
#include "evdev.h"
#include "input_type.h"
#include "s_input.h"
#define MAX_INPUT_DEVICE_COUNT MAX_INPUT_DEV_NUM
#define TOTAL_INPUT_DEVICE_COUNT (2 * MAX_INPUT_DEV_NUM)
#define TOTAL_INPUT_DEVICE_STATUS_COUNT (TOTAL_INPUT_DEVICE_COUNT + 1)
#define IOCTL_CMD_MASK (0x3fff)
#define IOCTL_CMD_SHIFT (16)
#define USEC_PER_SEC (1000000)
#define MAX_EVENT_PKG_NUM (256)

namespace OHOS {
namespace MMI {
enum hdf_event_type {
    HDF_NONE = 0,
    HDF_EVENT,
    HDF_ADD_DEVICE,
    HDF_RMV_DEVICE,
};
struct Devcmd {
    int index;
    int cmd;
};
class HdfEventManager {
public:
    bool Init();
    HdfEventManager();
    virtual ~HdfEventManager();
    void SetupCallback();
    bool OpenHdfDevice(uint32_t devIndex, bool oper);
    int GetDeviceCount();
    int GetJectDeviceCount();
    static int EvdevSimIoctl(int hdindex, int pcmd, void *iobuff);
    static int EvdevIoctl(int hdiindex, int pcmd, void *iobuff);
    static void HotPlugCallback(const HotPlugEvent *event);
    static void GetEventCallback(const EventPackage **pkgs, uint32_t count, uint32_t devIndex);
    static int DeviceAddHandle(uint32_t devIndex, uint32_t devType);
    static int DeviceRemoveHandle(uint32_t devIndex, uint32_t devType);
    void AddDevice(uint32_t devIndex, uint32_t typeIndex);
    int HdfdevtypeMapLibinputType(uint32_t devIndex, uint32_t devType);
    static libinput *HdfLibinputInit();
    static int HdfDevHandle(int index, hdf_event_type cmd);
private:
    libinput *hdiinput_ = nullptr;
    std::list<uhdf *> hdflist_;
    static OHOS::MMI::HdfEventManager *m_globleThis;
    bool devStatus[TOTAL_INPUT_DEVICE_STATUS_COUNT];
    DevDesc mountDevIndex_[TOTAL_INPUT_DEVICE_COUNT];
    IInputInterface *inputInterface_;
    IInputInterface *injectInterface_;
    InputEventCb eventcallback;
    InputHostCb  hostplugcallback;
};
}
}
extern OHOS::MMI::HdfEventManager  hdfEventManager;
#endif // OHOS_HDF_EVENT_MANAGER_H
