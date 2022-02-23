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
#ifndef HDI_INJECT_H
#define HDI_INJECT_H
#ifdef OHOS_BUILD_HDF

#include <vector>
#include <list>
#include "input_type.h"
#include "uds_server.h"
#include "register_eventhandle_manager.h"
#include "input_manager.h"

namespace OHOS {
namespace MMI {
    constexpr int32_t HDF_MOUSE_DEV_TYPE = 5;
    constexpr int32_t HDF_KEYBOARD_DEV_TYPE = 3;
    constexpr int32_t HDF_TOUCH_DEV_TYPE = 17;
    constexpr int32_t HDF_TABLET_DEV_TYPE = 33;
    constexpr int32_t HDF_TABLET_PAD_DEV_TYPE = 289;
    constexpr int32_t HDF_SWITH_PAD_DEV_TYPE = 2089;
    constexpr int32_t HDF_TOUCH_FINGER_DEV_TYPE = 2089;
    constexpr int32_t HDF_SWITCH_DEV_TYPE = 7;
    constexpr int32_t HDF_TRACK_PAD_DEV_TYPE = 7;
    constexpr int32_t HDF_JOYSTICK_DEV_TYPE = 65;
    constexpr int32_t HDF_GAMEPAD_DEV_TYPE = 65;
    constexpr int32_t HDF_TOUCH_PAD_DEV_TYPE = 5;
    constexpr int32_t HDF_TRACK_BALL_DEV_TYPE = 3;
    constexpr int32_t HDF_DEVICE_FD_DEFAULT_STATUS = -1;
    constexpr int32_t EVENT_PACKAGE_ARROW_SIZE = 1;

class HdiInject {
    enum HdiInfoType {
        GET_STATUS_INFO = 1001,
        SET_HOT_PLUGS = 1002,
        SET_EVENT_INJECT = 1003,
        GET_DEVICE_INFO = 1004,
        SHOW_DEVICE_INFO = 1005,
        REPLY_STATUS_INFO = 2001,
    };

    enum HdiDeviceStatus {
        HDI_DEVICE_ADD_STATUS = 0,
        HDI_DEVICE_REMOVE_STATUS = 1,
    };

    struct DeviceInformation {
        bool status;
        int32_t devIndex;
        int32_t devType;
        int16_t fd;
        char chipName[32];
    };
public:
    bool Init(UDSServer &sess);
    void StartHdiserver();
    void ShowAllDeviceInfo();
    void InitDeviceInfo();
    int32_t GetDeviceCount();
    bool SyncDeviceHotStatus();
    bool ReportHotPlugEvent();
    void OnInitHdiServerStatus();
    int32_t GetDevTypeIndex(int32_t devIndex);
    int32_t GetDevIndexType(int32_t devType);
    int32_t ManageHdfInject(const MMI::SessionPtr sess, MMI::NetPacket &pkt);
    void OnSetHotPlugs(uint32_t devIndex, uint32_t devSatatus);
    int32_t OnSetEventInject(const RawInputEvent& allEvent, int32_t devType);
    bool SetDeviceHotStatus(int32_t devIndex, int32_t status);
    int32_t ScanInputDevice(uint32_t arrLen, DevDesc *staArr);
    bool ReportHotPlugEvent(uint32_t devIndex, uint32_t status);
public:
    InputHostCb hotPlugcallback_;
    InputEventCb eventcallback_;
private:
    bool initStatus_ = false;
    HotPlugEvent** event_ = nullptr;
    MMI::UDSServer* udsServerPtr_ = nullptr;
    std::vector<DeviceInformation> deviceArray_ = {};
};
} // namespace MMI
} // namespace OHOS
#define MMIHdiInject OHOS::MMI::DelayedSingleton<OHOS::MMI::HdiInject>::GetInstance()
#endif // OHOS_BUILD_HDF
#endif // HDI_INJECT_H