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

#include "manage_inject_device.h"
#include <chrono>
#include <thread>

using namespace std;
using namespace OHOS::MMI;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "ManageInjectDevice" };
}

int32_t ManageInjectDevice::TransformJsonData(const Json& configData)
{
    MMI_LOGI("Enter TransformJsonData function.");
    if (configData.empty()) {
        MMI_LOGE("input data from json file is empty.");
        return RET_ERR;
    }
    int ret = RET_ERR;
    string deviceName;
    string sendType;
    string deviceNode;
    GetDeviceObject getDeviceObject;
    for (auto item : configData) {
        deviceName = item.at("deviceName").get<std::string>();
        InputEventArray inputEventArray = {};
        inputEventArray.deviceName = deviceName;
#ifndef OHOS_BUILD_HDF
        uint16_t devIndex = 0;
        if (item.find("devIndex") != item.end()) {
            devIndex = item.at("devIndex").get<uint16_t>();
        }
        if (getDeviceNodeObject_.GetDeviceNodeByName(deviceName, deviceNode, devIndex) == RET_ERR) {
            return RET_ERR;
        }
        inputEventArray.target = deviceNode;
#endif
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
    MMI_LOGI("Leave TransformJsonData function.");

    return ret;
}

int32_t ManageInjectDevice::SendEvent(const InputEventArray& inputEventArray)
{
#ifdef OHOS_BUILD_HDF
    return SendEventToHdi(inputEventArray);
#else
    return SendEventToDeviveNode(inputEventArray);
#endif
}

int32_t ManageInjectDevice::SendEventToHdi(const InputEventArray& inputEventArray)
{
    SendMessage sendMessage;
    return sendMessage.SendToHdi(inputEventArray);
}

int32_t ManageInjectDevice::SendEventToDeviveNode(const InputEventArray& inputEventArray)
{
    MMI_LOGI("Enter sendEventToDeviveNode function.");
    string deviceNode = inputEventArray.target;
    if (deviceNode.empty()) {
        MMI_LOGE("device node:%{public}s is not exit.", deviceNode.c_str());
        return RET_ERR;
    }
    int32_t fd = open(deviceNode.c_str(), O_RDWR);
    if (fd < 0) {
        MMI_LOGE("open device node:%{public}s faild.", deviceNode.c_str());
        return RET_ERR;
    }
    for (InjectEvent injectEvent : inputEventArray.events) {
        write(fd, &injectEvent.event, sizeof(injectEvent.event));
        int32_t blockTime = (injectEvent.blockTime == 0) ? INJECT_SLEEP_TIMES : injectEvent.blockTime;
        std::this_thread::sleep_for(std::chrono::milliseconds(blockTime));
    }
    if (fd > 0) {
        close(fd);
    }
    MMI_LOGI("Leave sendEventToDeviveNode function.");
    return RET_OK;
}