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

#include "manage_inject_device.h"

#include <chrono>
#include <thread>

using namespace OHOS::MMI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ManageInjectDevice" };
} // namespace

int32_t ManageInjectDevice::TransformJsonData(const DeviceItems& configData)
{
    CALL_LOG_ENTER;
    if (configData.empty()) {
        MMI_HILOGE("input data from json file is empty");
        return RET_ERR;
    }
    for (const auto &item : configData) {
        std::string deviceName = item.deviceName;
        uint16_t devIndex = item.deviceIndex;
        std::string deviceNode;
        if (getDeviceNodeObject_.GetDeviceNodeName(deviceName, devIndex, deviceNode) == RET_ERR) {
            MMI_HILOGE("fail get device:%{public}s node", deviceName.c_str());
            return RET_ERR;
        }
        InputEventArray inputEventArray = {};
        inputEventArray.deviceName = deviceName;
        inputEventArray.target = deviceNode;
        auto devicePtr = GetDeviceObject::CreateDeviceObject(deviceName);
        CHKPR(devicePtr, RET_ERR);
        int32_t ret = devicePtr->TransformJsonDataToInputData(item, inputEventArray);
        if (devicePtr != nullptr) {
            delete devicePtr;
            devicePtr = nullptr;
        }
        if (ret == RET_ERR) {
            MMI_HILOGE("fail read json file");
            return ret;
        }
        ret = SendEvent(inputEventArray);
        if (ret == RET_ERR) {
            MMI_HILOGE("SendEvent fail");
            return ret;
        }
    }

    return RET_OK;
}

int32_t ManageInjectDevice::SendEvent(const InputEventArray& inputEventArray)
{
    return SendEventToDeviveNode(inputEventArray);
}

int32_t ManageInjectDevice::SendEventToDeviveNode(const InputEventArray& inputEventArray)
{
    CALL_LOG_ENTER;
    std::string deviceNode = inputEventArray.target;
    if (deviceNode.empty()) {
        MMI_HILOGE("device node:%{public}s is not exit", deviceNode.c_str());
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(deviceNode.c_str(), realPath) == nullptr) {
        MMI_HILOGE("path is error, path:%{public}s", deviceNode.c_str());
        return RET_ERR;
    }
    int32_t fd = open(realPath, O_RDWR);
    if (fd < 0) {
        MMI_HILOGE("open device node:%{public}s faild", deviceNode.c_str());
        return RET_ERR;
    }
    for (const auto &item : inputEventArray.events) {
        write(fd, &item.event, sizeof(item.event));
        int64_t blockTime = (item.blockTime == 0) ? INJECT_SLEEP_TIMES : item.blockTime;
        std::this_thread::sleep_for(std::chrono::milliseconds(blockTime));
    }
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
    return RET_OK;
}