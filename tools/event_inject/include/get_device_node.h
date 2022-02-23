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

#ifndef GET_DEVICE_NODE_H
#define GET_DEVICE_NODE_H

#include "msg_head.h"

#define DeviceMapData std::map<std::string, std::vector<std::string>>

namespace OHOS {
namespace MMI {
class GetDeviceNode {
public:
    GetDeviceNode();
    ~GetDeviceNode() = default;
    int32_t GetDeviceNodeName(const std::string& targetName, std::string& deviceNode, uint16_t devIndex = 0);
private:
    void InitDeviceInfo();
    int32_t ExecuteCmd(const std::string cmd, std::vector<std::string> &cmdResult);
    void GetDeviceInfoCmdResult(const std::vector<std::string>& cmdResult, DeviceMapData& deviceMapData);
private:
    std::map<std::string, std::string> deviceMap_;
    static constexpr int32_t READ_CMD_BUFF_SIZE = 1024;
    static constexpr int32_t CMD_EVENT_LENGTH = 6;
};
} // namespace MMI
} // namespace OHOS
#endif // GET_DEVICE_NODE_H