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

#ifndef INJECTION_EVENT_DISPATCH_H
#define INJECTION_EVENT_DISPATCH_H
#include "test_aux_tool_client.h"
#include "manage_inject_device.h"
#include "injection_tools_help_func.h"

namespace OHOS {
namespace MMI {
using InjectFunction = std::function<int32_t()>;

enum HdiDeviceStatus : int32_t {
    HDI_ADD = 0,
    HDI_REMOVE = 1,
};

struct InjectFunctionMap {
    std::string id;
    int32_t injectToHdi;
    bool needStartSocket;
    InjectFunction fun;
};

constexpr int32_t ARGV_VALID = 2;

class InjectionEventDispatch {
public:
    InjectionEventDispatch() = default;
    ~InjectionEventDispatch() = default;
    void Init();
    void InitManageFunction();
    void InitDeviceInfo();
    void Run();
    bool StartSocket();
    void HandleInjectCommandItems();
    bool SendMsg(OHOS::MMI::NetPacket ckt);
    int32_t OnAisensor();
    int32_t OnHdi();
    int32_t OnHdiHot();
    int32_t OnHdiStatus();
#ifndef OHOS_BUILD_HDF
    int32_t OnSendEvent();
#endif
    int32_t OnJson();
    int32_t OnAisensorAll();
    int32_t OnAisensorEach();
    int32_t OnKnuckleAll();
    int32_t OnKnuckleEach();
    int32_t OnHelp();
    int32_t OnAisensorOne(MmiMessageId code, uint32_t value);
    int32_t OnKnuckleOne(MmiMessageId code, uint32_t value);
    int32_t ExecuteFunction(std::string funId);
    int32_t GetDevTypeByIndex(int32_t devIndex);
    int32_t GetDevIndexByType(int32_t devType);
    int32_t GetDeviceIndex(const std::string& deviceNameText);
    int32_t GetDeviceStatus(const std::string& deviceStatusText);
    std::string GetFunId();
    bool VirifyArgvs(const int32_t& argc, const std::vector<std::string>& argv);
    bool GetStartSocketPermission(std::string id);
    bool RegistInjectEvent(InjectFunctionMap& msg)
    {
        auto it = injectFuns_.find(msg.id);
        if (it != injectFuns_.end()) {
            return false;
        }
        injectFuns_[msg.id] = msg.fun;
        needStartSocket_[msg.id] = msg.needStartSocket;
        return true;
    }

    InjectFunction* GetFun(std::string id)
    {
        auto it = injectFuns_.find(id);
        if (it == injectFuns_.end()) {
            return nullptr;
        }
        return &it->second;
    }
private:
    void ProcessAiSensorInfoByCycleNum(uint16_t cycleNum);
    void ProcessKnuckleInfoByCycleNum(uint16_t cycleNum);
private:
    std::string funId_ = "";
    int32_t argvNum_ = 0;
    ManageInjectDevice manageInjectDevice_;
    std::vector<std::string> injectArgvs_;
    std::map<std::string, InjectFunction> injectFuns_;
    std::map<std::string, bool> needStartSocket_;
    std::map<std::string, int32_t> sendEventType_;
    std::vector<DeviceInformation> allDevices_ = {};
private:
    static constexpr uint32_t SEND_EVENT_ARGV_COUNTS = 5;
    static constexpr uint32_t SEND_EVENT_DEV_NODE_INDEX = 1;
    static constexpr uint32_t SEND_EVENT_TYPE_INDEX = 2;
    static constexpr uint32_t SEND_EVENT_CODE_INDEX = 3;
    static constexpr uint32_t SEND_EVENT_VALUE_INDEX = 4;
    static constexpr uint32_t AI_ALL_ARGV_INVALID = 2;
    static constexpr uint32_t AI_EACH_ARGV_INVALID = 3;
    static constexpr int32_t ARGVS_TARGET_INDEX = 1;
    static constexpr int32_t ARGVS_CODE_INDEX = 2;
    static constexpr int32_t SEND_EVENT_TO_DEVICE = 0;
    static constexpr int32_t SEND_EVENT_TO_HDI = 1;
    static constexpr int32_t HDI_STATUS_INDEX = 2;
    static constexpr int32_t HDI_DEVICE_NAME_INDEX = 3;
    static constexpr int32_t HDI_STATUS_COUNTS = 2;
    static constexpr int32_t HDI_HOT_COUNTS = 4;
    static constexpr int32_t HDI_MIN_ARGV_NUMS = 2;
    static constexpr int32_t HDI_MAX_ARGV_NUMS = 4;
    static constexpr int32_t AI_SENDOR_MIN_ARGV_NUMS = 2;
    static constexpr int32_t AI_SENSOR_TARGET_INDEX = 1;
    static constexpr int32_t AI_SENSOR_CODE_INDEX = 1;
    static constexpr int32_t AI_SENSOR_VALUE_INDEX = 2;
    static constexpr int32_t AI_SENSOR_DEFAULT_NUMS = 1;
    static constexpr int32_t AI_SENSOR_DEFAULT_CYCLE_NUMS = 1;
    static constexpr int32_t AI_SENSOR_CYCLE_NUMS = 2;
    static constexpr int32_t AI_SENSOR_CYCLE_INDEX = 1;
    static constexpr int32_t HDF_MOUSE_DEV_TYPE = 5;
    static constexpr int32_t HDF_KEYBOARD_DEV_TYPE = 3;
    static constexpr int32_t HDF_TOUCH_DEV_TYPE = 17;
    static constexpr int32_t HDF_TABLET_DEV_TYPE = 33;
    static constexpr int32_t HDF_TABLET_PAD_DEV_TYPE = 289;
    static constexpr int32_t HDF_SWITH_PAD_DEV_TYPE = 2049;
    static constexpr int32_t HDF_TOUCH_FINGER_DEV_TYPE = 2089;
    static constexpr int32_t HDF_SWITCH_DEV_TYPE = 7;
    static constexpr int32_t HDF_TRACK_PAD_DEV_TYPE = 7;
    static constexpr int32_t HDF_JOYSTICK_DEV_TYPE = 65;
    static constexpr int32_t HDF_GAMEPAD_DEV_TYPE = 65;
    static constexpr int32_t HDF_TOUCH_PAD_DEV_TYPE = 5;
    static constexpr int32_t HDF_TRACK_BALL_DEV_TYPE = 3;
    static constexpr int32_t HDF_DEVICE_FD_DEFAULT_STATUS = -1;
    static constexpr int32_t HDF_TARGET_INDEX = 1;
    static constexpr int32_t JSON_FILE_PATH_INDEX = 1;
};
} // namespace MMI
} // namespace OHOS
#endif // INJECTION_EVENT_DISPATCH_H