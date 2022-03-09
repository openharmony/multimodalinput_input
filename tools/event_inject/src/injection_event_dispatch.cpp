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
#include "proto.h"
#include "util.h"

using namespace OHOS::MMI;

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
        CHKC(RegistInjectEvent(it), EVENT_REG_FAIL);
    }
}

int32_t InjectionEventDispatch::OnJson()
{
    MMI_LOGD("Enter");
    const std::string path = injectArgvs_.at(JSON_FILE_PATH_INDEX);
    std::ifstream reader(path);
    if (!reader) {
        MMI_LOGE("json file is empty");
        return RET_ERR;
    }
    Json inputEventArrays;
    reader >> inputEventArrays;
    reader.close();

    int32_t ret = manageInjectDevice_.TransformJsonData(inputEventArrays);
    MMI_LOGI("Leave");
    return ret;
}

std::string InjectionEventDispatch::GetFunId()
{
    return funId_;
}

bool InjectionEventDispatch::VirifyArgvs(const int32_t &argc, const std::vector<std::string> &argv)
{
    MMI_LOGD("enter");
    if (argc < ARGV_VALID || argv.at(ARGVS_TARGET_INDEX).empty()) {
        MMI_LOGE("Invaild Input Para, Plase Check the validity of the para. errCode:%{public}d", PARAM_INPUT_FAIL);
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
    MMI_LOGD("enter");
    std::string id = GetFunId();
    auto fun = GetFun(id);
    if (!fun) {
        MMI_LOGE("event injection Unknown fuction id:%{public}s", id.c_str());
        return;
    }

    auto ret = (*fun)();
    if (ret == RET_OK) {
        MMI_LOGI("injecte function success id:%{public}s", id.c_str());
    } else {
        MMI_LOGE("injecte function faild id:%{public}s", id.c_str());
    }
}

int32_t InjectionEventDispatch::ExecuteFunction(std::string funId)
{
    if (funId.empty()) {
        return RET_ERR;
    }
    auto fun = GetFun(funId);
    if (!fun) {
        MMI_LOGE("event injection Unknown fuction id:%{public}s", funId.c_str());
        return false;
    }
    int32_t ret = RET_ERR;
    MMI_LOGI("Inject tools into function:%{public}s", funId.c_str());
    ret = (*fun)();
    if (ret == RET_OK) {
        MMI_LOGI("injecte function success id:%{public}s", funId.c_str());
    } else {
        MMI_LOGE("injecte function faild id:%{public}s", funId.c_str());
    }

    return ret;
}

int32_t InjectionEventDispatch::OnHelp()
{
    InjectionToolsHelpFunc helpFunc;
    std::string ret = helpFunc.GetHelpText();
    MMI_LOGI("%s", ret.c_str());

    return RET_OK;
}

int32_t InjectionEventDispatch::GetDeviceIndex(const std::string& deviceNameText)
{
    if (deviceNameText.empty()) {
        MMI_LOGE("Get device index failed");
        return RET_ERR;
    }
    for (const auto &item : allDevices_) {
        if (deviceNameText == item.chipName) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}

int32_t InjectionEventDispatch::OnSendEvent()
{
    if (injectArgvs_.size() != SEND_EVENT_ARGV_COUNTS) {
        MMI_LOGE("Wrong number of input parameters, errCode:%d", PARAM_INPUT_FAIL);
        return RET_ERR;
    }

    std::string deviceNode = injectArgvs_[SEND_EVENT_DEV_NODE_INDEX];
    if (deviceNode.empty()) {
        MMI_LOGE("device node:%s is not exit", deviceNode.c_str());
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(deviceNode.c_str(), realPath) == nullptr) {
        MMI_LOGE("path is error, path:%{public}s", deviceNode.c_str());
        return RET_ERR;
    }
    int32_t fd = open(realPath, O_RDWR);
    if (fd < 0) {
        MMI_LOGE("open device node:%s faild", deviceNode.c_str());
        return RET_ERR;
    }

    struct timeval tm;
    gettimeofday(&tm, 0);
    struct input_event event = {};
    event.input_event_sec = tm.tv_sec;
    event.input_event_usec = tm.tv_usec;
    event.type = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_TYPE_INDEX]));
    event.code = static_cast<uint16_t>(std::stoi(injectArgvs_[SEND_EVENT_CODE_INDEX]));
    event.value = static_cast<int32_t>(std::stoi(injectArgvs_[SEND_EVENT_VALUE_INDEX]));
    write(fd, &event, sizeof(event));
    if (fd >= 0) {
        close(fd);
    }
    return RET_OK;
}

int32_t InjectionEventDispatch::GetDevTypeIndex(int32_t devIndex)
{
    for (const auto &item : allDevices_) {
        if (devIndex == item.devIndex) {
            return item.devType;
        }
    }
    return RET_ERR;
}

int32_t InjectionEventDispatch::GetDevIndexType(int32_t devType)
{
    for (const auto &item : allDevices_) {
        if (item.devType == devType) {
            return item.devIndex;
        }
    }
    return RET_ERR;
}
