/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef GET_DEVICE_NODE_H
#define GET_DEVICE_NODE_H

#include "nocopyable.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
class GetDeviceNode {
public:
    GetDeviceNode();
    ~GetDeviceNode() = default;
    DISALLOW_COPY_AND_MOVE(GetDeviceNode);
    int32_t GetDeviceNodeName(const std::string &targetName, uint16_t devIndex, std::string &deviceNode);
private:
    void InitDeviceInfo();
    std::vector<std::string> ReadDeviceFile();
    void AnalyseDevices(const std::vector<std::string> &cmdResult,
        std::map<std::string, std::vector<std::string>> &deviceList) const;
private:
    std::map<std::string, std::string> deviceList_;
};
} // namespace MMI
} // namespace OHOS
#endif // GET_DEVICE_NODE_H