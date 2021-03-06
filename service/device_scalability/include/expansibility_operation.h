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
#ifndef OHOS_EXPANSIBILITY_OPERATION_H
#define OHOS_EXPANSIBILITY_OPERATION_H
#include "libmmi_util.h"

namespace OHOS {
namespace MMI {
class ExpansibilityOperation {
public:
    ExpansibilityOperation();
    ~ExpansibilityOperation();
    void LoadExteralLibrary(const std::string& cfg, const std::string& libPath);
    bool RegistDeviceEventFd(int32_t deviceEventFd);
    bool UnRegistDeviceEventFd(int32_t deviceEventFd);

protected:
    std::string GetFileName(const std::string& line);
    int32_t GetNewDeviceFd(const std::string& fileName);

protected:
    std::string libPath_;
};
}
}
#endif
