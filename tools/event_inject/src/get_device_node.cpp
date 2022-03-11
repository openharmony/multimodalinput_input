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

#include "get_device_node.h"

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "GetDeviceNode" };
} // namespace

GetDeviceNode::GetDeviceNode()
{
    InitDeviceInfo();
}

int32_t GetDeviceNode::GetDeviceNodeName(const std::string &targetName, std::string &deviceNode, uint16_t devIndex)
{
    std::string cmd = "cat /proc/bus/input/devices";
    std::vector<std::string> cmdResult;
    ExecuteCmd(cmd, cmdResult);
    DeviceMapData deviceMapData;
    GetDeviceInfoCmdResult(cmdResult, deviceMapData);
    std::string deviceName = deviceMap_[targetName];
    auto iter = deviceMapData.find(deviceName);
    if (iter == deviceMapData.end()) {
        MMI_LOGE("faild for find deviceName:%{public}s", deviceName.c_str());
        return RET_ERR;
    }
    size_t targetSize = iter->second.size();
    if (devIndex > targetSize) {
        MMI_LOGE("faild for devIndex:%{public}d > targetSize:%{public}zu", devIndex, targetSize);
        return RET_ERR;
    }
    std::string nodeRootPath = "/dev/input/";
    deviceNode = nodeRootPath + iter->second[devIndex];
    MMI_LOGI("%{public}s[%{public}d] --> %{public}s", targetName.c_str(), devIndex,
             deviceNode.c_str());

    return RET_OK;
}

void GetDeviceNode::InitDeviceInfo()
{
    deviceMap_["mouse"] = "Virtual Mouse";
    deviceMap_["touch"] = "Virtual TouchScreen";
    deviceMap_["finger"] = "Virtual Finger";
    deviceMap_["pad"] = "Virtual Touchpad";
    deviceMap_["pen"] = "Virtual Stylus";
    deviceMap_["gamePad"] = "Virtual GamePad";
    deviceMap_["joystick"] = "Virtual Joystick";
    deviceMap_["remoteControl"] = "Virtual RemoteControl";
    deviceMap_["knob model1"] = "Virtual KnobConsumerCtrl";
    deviceMap_["knob model2"] = "Virtual Knob";
    deviceMap_["knob model3"] = "Virtual KnobMouse";
    deviceMap_["keyboard model1"] = "Virtual keyboard";
    deviceMap_["keyboard model2"] = "Virtual KeyboardConsumerCtrl";
    deviceMap_["keyboard model3"] = "Virtual KeyboardSysCtrl";
    deviceMap_["trackball"] = "Virtual Trackball";
    deviceMap_["trackpad model1"] = "Virtual TrackPadMouse";
    deviceMap_["trackpad model2"] = "Virtual Trackpad";
}

int32_t GetDeviceNode::ExecuteCmd(const std::string cmd, std::vector<std::string> &cmdResult)
{
    if (cmd.empty()) {
        return RET_ERR;
    }
    char buffer[READ_CMD_BUFF_SIZE] = {};
    FILE* pin = popen(cmd.c_str(), "r");
    if (pin == nullptr) {
        return RET_ERR;
    }
    cmdResult.clear();
    while (!feof(pin)) {
        if (fgets(buffer, sizeof(buffer), pin) != nullptr) {
            cmdResult.push_back(buffer);
        }
    }
    return pclose(pin);
}

void GetDeviceNode::GetDeviceInfoCmdResult(const std::vector<std::string>& cmdResult,
                                           DeviceMapData& deviceMapData) const
{
    std::string name;
    std::string target;
    std::string temp;
    uint64_t endPos = 0;
    uint64_t startPos = 0;
    uint64_t eventLength = CMD_EVENT_LENGTH;
    for (const auto &item : cmdResult) {
        temp = item.substr(0, 1);
        if (temp == "N") {
            startPos = item.find("=") + strlen("N:");
            endPos = item.size() - 1;
            name = item.substr(startPos, endPos - startPos - 1);
        } else if (temp == "H") {
            startPos = item.find("event");
            std::string endString = item.substr(startPos + strlen("event") + 1, 1);
            if (endString != " ") {
                eventLength = CMD_EVENT_LENGTH + 1;
            }
            target = item.substr(startPos, eventLength);
            if (!(name.empty())) {
                deviceMapData[name].push_back(target);
                name.clear();
                target.clear();
            }
        } else {
            // nothing to do.
        }
    }
}