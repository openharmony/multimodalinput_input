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

int32_t ManageInjectDevice::TransformJsonData(const Json& configData)
{
    MMI_LOGD("Enter");
    if (configData.empty()) {
        MMI_LOGE("input data from json file is empty");
        return RET_ERR;
    }
    int32_t ret = RET_ERR;
    std::string deviceName;
    std::string sendType;
    std::string deviceNode;
    GetDeviceObject getDeviceObject;
    for (const auto &item : configData) {
        deviceName = item.at("deviceName").get<std::string>();
        InputEventArray inputEventArray = {};
        inputEventArray.deviceName = deviceName;

        uint16_t devIndex = 0;
        if (item.find("devIndex") != item.end()) {
            devIndex = item.at("devIndex").get<uint16_t>();
        }
        if (getDeviceNodeObject_.GetDeviceNodeName(deviceName, deviceNode, devIndex) == RET_ERR) {
            return RET_ERR;
        }
        inputEventArray.target = deviceNode;

        devicePtr_ = getDeviceObject.CreateDeviceObject(deviceName);
        if (devicePtr_ == nullptr) {
            return RET_ERR;
        }
        ret = devicePtr_->TransformJsonDataToInputData(item, inputEventArray);
        if (ret != RET_ERR) {
            ret = SendEvent(inputEventArray);
        }
    }
    if (devicePtr_ != nullptr) {
        delete devicePtr_;
        devicePtr_ = nullptr;
    }
    MMI_LOGD("Leave");

    return ret;
}

int32_t ManageInjectDevice::SendEvent(const InputEventArray& inputEventArray)
{
    return SendEventToDeviveNode(inputEventArray);
}

int32_t ManageInjectDevice::SendEventToDeviveNode(const InputEventArray& inputEventArray)
{
    MMI_LOGD("Enter");
    std::string deviceNode = inputEventArray.target;
    if (deviceNode.empty()) {
        MMI_LOGE("device node:%{public}s is not exit", deviceNode.c_str());
        return RET_ERR;
    }
    int32_t fd = open(deviceNode.c_str(), O_RDWR);
    if (fd < 0) {
        MMI_LOGE("open device node:%{public}s faild", deviceNode.c_str());
        return RET_ERR;
    }
    for (const auto &item : inputEventArray.events) {
        write(fd, &item.event, sizeof(item.event));
        int32_t blockTime = (item.blockTime == 0) ? INJECT_SLEEP_TIMES : item.blockTime;
        std::this_thread::sleep_for(std::chrono::milliseconds(blockTime));
    }
    if (fd >= 0) {
        close(fd);
    }
    MMI_LOGD("Leave");
    return RET_OK;
}