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

#include "injection_event_dispatch.h"

#include <cctype>
#include <cstdio>
#include <iostream>
#include <regex>
#include <string>
#include <typeinfo>

#include "error_multimodal.h"
#include "proto.h"
#include "util.h"
#include "input_parse.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InjectionEventDispatch" };
} // namespace

void InjectionEventDispatch::Init()
{
    InitManageFunction();
}

void InjectionEventDispatch::InitManageFunction()
{
    InjectFunctionMap funs[] = {
        {"help", std::bind(&InjectionEventDispatch::OnHelp, this)},
        {"sendevent", std::bind(&InjectionEventDispatch::OnSendEvent, this)},
        {"json", std::bind(&InjectionEventDispatch::OnJson, this)},
    };

    for (auto &it : funs) {
        if (!RegistInjectEvent(it)) {
            MMI_HILOGW("Failed to register event errCode:%{public}d", EVENT_REG_FAIL);
            continue;
        }
    }
}

bool InjectionEventDispatch::IsFileExists(const std::string& fileName)
{
    if ((access(fileName.c_str(), F_OK)) == 0) {
        return true;
    }
    return false;
}

int32_t InjectionEventDispatch::VerifyFile(const std::string& fileName)
{
    std::string findcmd = "find /data -name " + fileName;
    FILE* findJson = popen(findcmd.c_str(), "r");
    if (!findJson) {
        return RET_ERR;
    }
    return RET_OK;
}

std::string InjectionEventDispatch::GetFileExtendName(const std::string& fileName)
{
    if (fileName.empty()) {
        return "";
    }
    size_t nPos = fileName.find_last_of('.');
    if (fileName.npos == nPos) {
        return fileName;
    }
    return fileName.substr(nPos + 1, fileName.npos);
}

int32_t InjectionEventDispatch::GetFileSize(const std::string& fileName)
{
    FILE* pFile = fopen(fileName.c_str(), "rb");
    if (pFile) {
        fseek(pFile, 0, SEEK_END);
        long fileSize = ftell(pFile);
        if (fileSize > INT32_MAX) {
            MMI_HILOGE("The file is too large for 32-bit systems, filesize:%{public}ld", fileSize);
            fclose(pFile);
            return RET_ERR;
        }
        fclose(pFile);
        return fileSize;
    }
    return RET_ERR;
}

bool InjectionEventDispatch::ReadFile(const std::string &jsonFile, std::string& jsonBuf)
{
    FILE* fp = fopen(jsonFile.c_str(), "r");
    CHKPF(fp);
    char buf[256] = {};
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        jsonBuf += buf;
    }
    if (fclose(fp) < 0) {
        MMI_HILOGW("close file failed");
    }
    return true;
}

int32_t InjectionEventDispatch::OnJson()
{
    CALL_LOG_ENTER;
    if (injectArgvs_.size() < ARGVS_CODE_INDEX) {
        MMI_HILOGE("path is error");
        return RET_ERR;
    }
    const std::string jsonFile = injectArgvs_.at(JSON_FILE_PATH_INDEX);
    char Path[PATH_MAX] = {};
    if (realpath(jsonFile.c_str(), Path) == nullptr) {
        MMI_HILOGE("json path is error, jsonFile:%{public}s", jsonFile.c_str());
        return RET_ERR;
    }
    if (!(IsFileExists(jsonFile))) {
        MMI_HILOGE("This file does not exist, jsonFile:%{public}s", jsonFile.c_str());
        return RET_ERR;
    }
    if (VerifyFile(jsonFile)) {
        MMI_HILOGE("This file is not in data, jsonFile:%{public}s", jsonFile.c_str());
        return RET_ERR;
    }
    if (GetFileExtendName(jsonFile) != "json") {
        MMI_HILOGE("Unable to parse files other than json format jsonFile:%{public}s", jsonFile.c_str());
        return RET_ERR;
    }
    int32_t fileSize = GetFileSize(jsonFile);
    if ((fileSize <= 0) || (fileSize > JSON_FILE_SIZE)) {
        MMI_HILOGE("The file size is out of range 2M or empty. filesize:%{public}d", fileSize);
        return RET_ERR;
    }
    std::string jsonBuf;
    if (!ReadFile(jsonFile, jsonBuf)) {
        MMI_HILOGE("read file failed");
        return RET_ERR;
    }
    bool logStatus = false;
    if (injectArgvs_.size() > ARGVS_CODE_INDEX) {
        if (injectArgvs_.at(ARGVS_CODE_INDEX) == "log") {
            logStatus = true;
        }
    }
    InputParse InputParse;
    return manageInjectDevice_.TransformJsonData(InputParse.DataInit(jsonBuf, logStatus));
}

std::string InjectionEventDispatch::GetFunId() const
{
    return funId_;
}

bool InjectionEventDispatch::VirifyArgvs(const int32_t &argc, const std::vector<std::string> &argv)
{
    CALL_LOG_ENTER;
    if (argc < ARGV_VALID || argv.at(ARGVS_TARGET_INDEX).empty()) {
        MMI_HILOGE("Invaild Input Para, Plase Check the validity of the para. errCode:%{public}d", PARAM_INPUT_FAIL);
        return false;
    }

    bool result = false;
    for (const auto &item : injectFuns_) {
        std::string temp(argv.at(ARGVS_TARGET_INDEX));
        if (temp == item.first) {
            funId_ = temp;
            result = true;
            break;
        }
    }
    if (result) {
        injectArgvs_.clear();
        for (uint64_t i = 1; i < static_cast<uint64_t>(argc); i++) {
            injectArgvs_.push_back(argv[i]);
        }
        argvNum_ = argc - 1;
    }

    return result;
}

void InjectionEventDispatch::Run()
{
    CALL_LOG_ENTER;
    std::string id = GetFunId();
    auto fun = GetFun(id);
    CHKPV(fun);

    auto ret = (*fun)();
    if (ret == RET_OK) {
        MMI_HILOGI("inject function success id:%{public}s", id.c_str());
    } else {
        MMI_HILOGE("inject function failed id:%{public}s", id.c_str());
    }
}

int32_t InjectionEventDispatch::ExecuteFunction(std::string funId)
{
    if (funId.empty()) {
        return RET_ERR;
    }
    auto fun = GetFun(funId);
    if (!fun) {
        MMI_HILOGE("event injection Unknown fuction id:%{public}s", funId.c_str());
        return false;
    }
    MMI_HILOGI("Inject tools into function:%{public}s", funId.c_str());
    int32_t ret = RET_ERR;
    ret = (*fun)();
    if (ret == RET_OK) {
        MMI_HILOGI("inject function success id:%{public}s", funId.c_str());
    } else {
        MMI_HILOGE("inject function failed id:%{public}s", funId.c_str());
    }

    return ret;
}

int32_t InjectionEventDispatch::OnHelp()
{
    InjectionToolsHelpFunc helpFunc;
    std::string ret = helpFunc.GetHelpText();
    MMI_HILOGI("%{public}s", ret.c_str());

    return RET_OK;
}

int32_t InjectionEventDispatch::GetDeviceIndex(const std::string& deviceNameText) const
{
    if (deviceNameText.empty()) {
        MMI_HILOGE("Get device index failed");
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

bool InjectionEventDispatch::CheckValue(const std::string& inputValue)
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

bool InjectionEventDispatch::CheckCode(const std::string& inputCode)
{
    if ((inputCode.length()) > INPUT_CODE_LENGTH) {
        MMI_HILOGE("The value entered is out of range, code:%{public}s", inputCode.c_str());
        return false;
    }
    bool isCodeNumber = regex_match(inputCode, std::regex("\\d+"));
    if (isCodeNumber) {
        uint16_t numberCode = stoi(inputCode);
        if ((numberCode >= 0) && (numberCode <= UINT16_MAX)) {
            return true;
        }
    }
    return false;
}

bool InjectionEventDispatch::CheckType(const std::string& inputType)
{
    if ((inputType.length()) > INPUT_TYPE_LENGTH) {
        MMI_HILOGE("The value entered is out of range, type:%{public}s", inputType.c_str());
        return false;
    }
    bool isTypeNumber = regex_match(inputType, std::regex("\\d+"));
    if (isTypeNumber) {
        uint16_t numberType = stoi(inputType);
        if ((numberType >= 0) && (numberType <= INPUT_TYPE_MAX)) {
            return true;
        }
    }
    return false;
}

bool InjectionEventDispatch::CheckEventValue(const std::string& inputType, const std::string& inputCode,
    const std::string& inputValue)
{
    if (!(CheckType(inputType))) {
        MMI_HILOGE("input error in type, type:%{public}s", inputType.c_str());
        return false;
    }
    if (!(CheckCode(inputCode))) {
        MMI_HILOGE("input error in code, code:%{public}s", inputCode.c_str());
        return false;
    }
    if (!(CheckValue(inputValue))) {
        MMI_HILOGE("input error in value, value:%{public}s", inputValue.c_str());
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
        MMI_HILOGE("open device node:%{public}s failed, errCode:%{public}d", deviceNode.c_str(), FILE_OPEN_FAIL);
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
        MMI_HILOGE("send event to device node faild.");
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
