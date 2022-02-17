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
#include "multi_input_common.h"
#include <climits>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include "utils/log.h"
#include "libmmi_util.h"
namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultiInputCommon" };
}

void MultiInputCommon::InjectionIni(const std::string &iniFilePath, const std::string &fileName,
                                    const std::string &jsonEventValue)
{
    if (iniFilePath.empty()) {
        return;
    }

    const std::string eventsFile = iniFilePath + fileName;
    std::ofstream file_writer(eventsFile, std::ios_base::trunc);
    file_writer.close();

    std::ofstream file;
    char path[PATH_MAX] = {};
    if (realpath(eventsFile.c_str(), path) == nullptr) {
        MMI_LOGE("file path:%{public}s error", eventsFile.c_str());
        return;
    }
    file.open(path, std::ios::app);
    if (!file.is_open()) {
        std::cout << "cannot open file" << std::endl;
    }
    file << jsonEventValue << std::endl;
    file.close();
}

void MultiInputCommon::SetIniFile(const std::string &fileName, const std::string &jsonEventValue)
{
    const std::string iniFilePath = "/data/mmi/";
    InjectionIni(iniFilePath, fileName, jsonEventValue);
}
} // namespace MMI
} // namespace OHOS
