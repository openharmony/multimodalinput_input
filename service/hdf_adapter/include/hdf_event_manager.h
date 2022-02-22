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
#ifndef HDF_EVENT_MANAGER_H
#define HDF_EVENT_MANAGER_H

#include <iostream>
#include <functional>
#include <map>
#include <list>
#include "input_manager.h"
#include "libinput.h"
#include "evdev.h"
#include "input_type.h"
#include "nocopyable.h"
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
    int32_t index;
    int32_t cmd;
};
class HdfEventManager {
public:
    bool Init();
    HdfEventManager();
    DISALLOW_COPY_AND_MOVE(HdfEventManager);
    virtual ~HdfEventManager();
    void SetupCallback();
    bool OpenHdfDevice(uint32_t devIndex, bool oper);
    int32_t GetDeviceCount();
    int32_t GetJectDeviceCount();
    static int32_t EvdevSimIoctl(int32_t hdindex, int32_t pcmd, void *iobuff);
    static int32_t EvdevIoctl(int32_t hdiindex, int32_t pcmd, void *iobuff);
    static void HotPlugCallback(const HotPlugEvent *event);
    static void GetEventCallback(const EventPackage **pkgs, uint32_t count, uint32_t devIndex);
    static int32_t DeviceAddHandle(uint32_t devIndex, uint32_t devType);
    static int32_t DeviceRemoveHandle(uint32_t devIndex, uint32_t devType);
    void AddDevice(uint32_t devIndex, uint32_t typeIndex);
    int32_t HdfdevtypeMapLibinputType(uint32_t devIndex, uint32_t devType);
    static libinput *HdfLibinputInit();
    static int32_t HdfDevHandle(int32_t index, hdf_event_type cmd);
private:
    libinput *hdiinput_ = nullptr;
    std::list<uhdf *> hdflist_;
    static OHOS::MMI::HdfEventManager *globleThis_;
    bool devStatus[TOTAL_INPUT_DEVICE_STATUS_COUNT];
    DevDesc mountDevIndex_[TOTAL_INPUT_DEVICE_COUNT];
    IInputInterface *inputInterface_;
    IInputInterface *injectInterface_;
    InputEventCb eventCallBack_;
    InputHostCb  hostPlugCallBack_;
};
} // namespace MMI
} // namespace OHOS
extern OHOS::MMI::HdfEventManager  hdfEventManager;
#endif // HDF_EVENT_MANAGER_H