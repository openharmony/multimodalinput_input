/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "injection_event_dispatch.h"

#include <cctype>
#include <cstdio>
#include <iostream>
#include <regex>
#include <string>
#include <typeinfo>

#include "error_multimodal.h"
#include "input_parse.h"
#include "proto.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InjectionEventDispatch"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t SEND_EVENT_ARGV_COUNTS { 5 };
constexpr uint32_t SEND_EVENT_DEV_NODE_INDEX { 1 };
constexpr uint32_t SEND_EVENT_TYPE_INDEX { 2 };
constexpr uint32_t SEND_EVENT_CODE_INDEX { 3 };
constexpr uint32_t SEND_EVENT_VALUE_INDEX { 4 };
constexpr int32_t ARGVS_TARGET_INDEX { 0 };
constexpr int32_t ARGVS_CODE_INDEX { 2 };
constexpr int32_t JSON_FILE_PATH_INDEX { 1 };
constexpr uint32_t INPUT_TYPE_LENGTH { 3 };
constexpr uint16_t INPUT_TYPE_MAX { 100 };
constexpr uint32_t INPUT_CODE_LENGTH { 6 };
constexpr uint32_t INPUT_VALUE_LENGTH { 11 };
} // namespace

void InjectionEventDispatch::Init()
{
    InitManageFunction();
}

void InjectionEventDispatch::InitManageFunction()
{
    CALL_DEBUG_ENTER;
    InjectFunctionMap funs[] = {
        {"help", [this] { return this->OnHelp(); }},
        {"sendevent", [this] { return this->OnSendEvent(); }},
        {"json", [this] { return this->OnJson(); }},
    };

    for (auto &it : funs) {
        if (!RegisterInjectEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
}

int32_t InjectionEventDispatch::OnJson()
{
    CALL_DEBUG_ENTER;
    if (injectArgvs_.size() < ARGVS_CODE_INDEX) {
        MMI_HILOGE("Path is error");
        return RET_ERR;
    }
    std::string jsonBuf = ReadJsonFile(injectArgvs_.at(JSON_FILE_PATH_INDEX));
    if (jsonBuf.empty()) {
        MMI_HILOGE("Read file failed");
        return RET_ERR;
    }
    bool logStatus = false;
    if (injectArgvs_.size() > ARGVS_CODE_INDEX) {
        if (injectArgvs_.at(ARGVS_CODE_INDEX) == "log") {
            logStatus = true;
        }
    }
    return manageInjectDevice_.TransformJsonData(DataInit(jsonBuf, logStatus));
}

void InjectionEventDispatch::SetArgvs(const std::vector<std::string> &injectArgvs)
{
    injectArgvs_ = injectArgvs;
}

std::string InjectionEventDispatch::GetFunId() const
{
    return funId_;
}

bool InjectionEventDispatch::VerifyArgvs()
{
    CALL_DEBUG_ENTER;
    std::string temp = injectArgvs_.at(ARGVS_TARGET_INDEX);
    if (temp.empty()) {
        MMI_HILOGE("Invalid Input parameter");
        return false;
    }
    auto it = injectFuns_.find(temp);
    if (it == injectFuns_.end()) {
        MMI_HILOGE("Parameter bound function not found");
        return false;
    }
    funId_ = temp;
    return true;
}

void InjectionEventDispatch::Run()
{
    CALL_DEBUG_ENTER;
    std::string id = GetFunId();
    auto fun = GetFun(id);
    CHKPV(fun);
    auto ret = (*fun)();
    if (ret == RET_OK) {
        MMI_HILOGI("Inject function success id:%{public}s", id.c_str());
    } else {
        MMI_HILOGE("Inject function failed id:%{public}s", id.c_str());
    }
}

int32_t InjectionEventDispatch::ExecuteFunction(std::string funId)
{
    if (funId.empty()) {
        return RET_ERR;
    }
    auto fun = GetFun(funId);
    if (!fun) {
        MMI_HILOGE("Event injection Unknown fuction id:%{public}s", funId.c_str());
        return false;
    }
    MMI_HILOGI("Inject tools into function:%{public}s", funId.c_str());
    int32_t ret = RET_ERR;
    ret = (*fun)();
    if (ret == RET_OK) {
        MMI_HILOGI("Inject function success id:%{public}s", funId.c_str());
    } else {
        MMI_HILOGE("Inject function failed id:%{public}s", funId.c_str());
    }

    return ret;
}

int32_t InjectionEventDispatch::OnHelp()
{
    InjectionToolsHelpFunc helpFunc;
    helpFunc.ShowUsage();
    return RET_OK;
}

int32_t InjectionEventDispatch::GetDeviceIndex(const std::string &deviceNameText) const
{
    if (deviceNameText.empty()) {
        MMI_HILOGE("The deviceNameText is empty");
        return RET_ERR;
    }
    for (const auto &item : allDevices_) {
        if (deviceNameText == item.chipName) {
            return item.devIndex;
        }
    }
    MMI_HILOGW("Get device index failed");
    return RET_ERR;
}

bool InjectionEventDispatch::CheckValue(const std::string &inputValue)
{
    if ((inputValue.length()) > INPUT_VALUE_LENGTH) {
        MMI_HILOGE("The value entered is out of range, value:%{public}s", inputValue.c_str());
        return false;
    }
    bool isValueNumber = regex_match(inputValue, std::regex("(-[\\d+]+)|(\\d+)"));
    if (isValueNumber) {
        int32_t numberValue = stoi(inputValue);
        if ((numberValue >= INT32_MIN) && (numberValue <= INT32_MAX)) {
            return true;
        }
    }
    return false;
}

bool InjectionEventDispatch::CheckCode(const std::string &inputCode)
{
    if ((inputCode.length()) > INPUT_CODE_LENGTH) {
        MMI_HILOGE("The value entered is out of range, code:%{public}s", inputCode.c_str());
        return false;
    }
    bool isCodeNumber = regex_match(inputCode, std::regex("\\d+"));
    if (isCodeNumber) {
        int32_t numberCode = stoi(inputCode);
        if ((numberCode >= 0) && (numberCode <= UINT16_MAX)) {
            return true;
        }
    }
    return false;
}

bool InjectionEventDispatch::CheckType(const std::string &inputType)
{
    if ((inputType.length()) > INPUT_TYPE_LENGTH) {
        MMI_HILOGE("The value entered is out of range, type:%{public}s", inputType.c_str());
        return false;
    }
    bool isTypeNumber = regex_match(inputType, std::regex("\\d+"));
    if (isTypeNumber) {
        int32_t numberType = stoi(inputType);
        if ((numberType >= 0) && (numberType <= INPUT_TYPE_MAX)) {
            return true;
        }
    }
    return false;
}

bool InjectionEventDispatch::CheckEventValue(const std::string &inputType, const std::string &inputCode,
    const std::string &inputValue)
{
    if (!(CheckType(inputType))) {
        MMI_HILOGE("Input error in type, type:%{public}s", inputType.c_str());
        return false;
    }
    if (!(CheckCode(inputCode))) {
        MMI_HILOGE("Input error in code, code:%{public}s", inputCode.c_str());
        return false;
    }
    if (!(CheckValue(inputValue))) {
        MMI_HILOGE("Input error in value, value:%{public}s", inputValue.c_str());
        return false;
    }
    return true;
}

int32_t InjectionEventDispatch::OnSendEvent()
{
    if (injectArgvs_.size() != SEND_EVENT_ARGV_COUNTS) {
        MMI_HILOGE("Wrong number of input parameters, errCode:%{public}d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    std::string deviceNode = injectArgvs_[SEND_EVENT_DEV_NODE_INDEX];
    if (deviceNode.empty()) {
        MMI_HILOGE("Device node:%{public}s is not existent", deviceNode.c_str());
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(deviceNode.c_str(), realPath) == nullptr) {
        MMI_HILOGE("Path is error, path:%{public}s", deviceNode.c_str());
        return RET_ERR;
    }
    int32_t fd = open(realPath, O_RDWR);
    if (fd < 0) {
        MMI_HILOGE("Open device node:%{public}s failed, errCode:%{public}d", deviceNode.c_str(), FILE_OPEN_FAIL);
        return RET_ERR;
    }
    struct timeval tm;
    gettimeofday(&tm, 0);
    struct input_event event = {};
    event.input_event_sec = tm.tv_sec;
    event.input_event_usec = tm.tv_usec;
    if (!(CheckEventValue(injectArgvs_[SEND_EVENT_TYPE_INDEX], injectArgvs_[SEND_EVENT_CODE_INDEX],
        injectArgvs_[SEND_EVENT_VALUE_INDEX]))) {
        return RET_ERR;
    }
    event.type = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_TYPE_INDEX]));
    event.code = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_CODE_INDEX]));
    event.value = static_cast<int32_t>(std::stoi(injectArgvs_[SEND_EVENT_VALUE_INDEX]));
    int32_t ret = write(fd, &event, sizeof(event));
    if (ret != sizeof(event)) {
        MMI_HILOGE("Send event to device node failed");
        return RET_ERR;
    }
    if (fd >= 0) {
        close(fd);
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::GetDevTypeIndex(int32_t devIndex) const
{
    for (const auto &item : allDevices_) {
        if (devIndex == item.devIndex) {
            return item.devType;
        }
    }
    return RET_ERR;
}

int32_t InjectionEventDispatch::GetDevIndexType(int32_t devType) const
{
    for (const auto &item : allDevices_) {
        if (item.devType == devType) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}
} // namespace MMI
} // namespace OHOS
