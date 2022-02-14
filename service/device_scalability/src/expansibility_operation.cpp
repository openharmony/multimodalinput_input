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

#include "expansibility_operation.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <dlfcn.h>
#include <unistd.h>

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ExpansibilityOperation" };
    }
}

OHOS::MMI::ExpansibilityOperation::ExpansibilityOperation()
{
    libPath_ = ' ';
}

OHOS::MMI::ExpansibilityOperation::~ExpansibilityOperation()
{
}

std::string OHOS::MMI::ExpansibilityOperation::GetFileName(const std::string& line)
{
    std::istringstream stream(line);
    std::string deviceName;
    std::string fileName;
    stream >> deviceName;
    stream >> fileName;

    return fileName;
}

int32_t OHOS::MMI::ExpansibilityOperation::GetNewDeviceFd(const std::string& fileName)
{
    // load dyn file
    std::string filePath;
    filePath.append(libPath_).append(fileName);
    void *libmHandle = dlopen(filePath.c_str(), RTLD_LAZY);
    if (libmHandle == nullptr) {
        MMI_LOGE("Open Error:%{public}s.", dlerror());
        return -1;
    }

    // get symbol name
    int32_t (*initDeviceInfo)();
    initDeviceInfo = reinterpret_cast<int32_t(*)()>(dlsym(libmHandle, "initDeviceInfo"));
    char *errorInfo = dlerror();
    if (errorInfo != nullptr) {
        MMI_LOGE("Dlsym Error:%{public}s.", errorInfo);
        dlclose(libmHandle);
        return -1;
    }

    // get event fd
    int32_t deviceEventFd = (*initDeviceInfo)();
    if (deviceEventFd > 0) {
        MMI_LOGE("get new device failed. errCode:%{public}d", ILLEGAL_DEV_ID);
        dlclose(libmHandle);
        return -1;
    }

    // close file
    dlclose(libmHandle);
    return deviceEventFd;
}

void OHOS::MMI::ExpansibilityOperation::LoadExteralLibrary(const std::string& cfg, const std::string& libPath)
{
    CHK(cfg.length() > 1, PARAM_INPUT_INVALID);
    CHK(libPath.length() > 1, PARAM_INPUT_INVALID);
    libPath_ = libPath;
    std::ifstream labels(cfg.c_str());
    if (!labels.is_open()) {
        MMI_LOGE("Can't open the label file![%{public}s], errCode:%{public}d", cfg.c_str(), FILE_OPEN_FAIL);
        return;
    }

    std::string line;
    while (std::getline(labels, line)) {
        // get x.so filename
        std::string fileName = GetFileName(line);
        if (fileName.empty()) {
            break;
        }
        // get event fd
        int32_t deviceEventFd = GetNewDeviceFd(fileName);
        // regist new fd
        if (!RegistDeviceEventFd(deviceEventFd)) {
            MMI_LOGE("regist new device failed. file name:%{public}s, errCode:%{public}d",
                     fileName.c_str(), DEV_REG_FAIL);
            return;
        }
    }
    return;
}

bool OHOS::MMI::ExpansibilityOperation::RegistDeviceEventFd(int32_t deviceEventFd)
{
    MMI_LOGD("The New Device fd:%{public}d", deviceEventFd);
    return true;
}

bool OHOS::MMI::ExpansibilityOperation::UnRegistDeviceEventFd(int32_t deviceEventFd)
{
    return true;
}
