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
        void MultiInputCommon::InjectionIni(const std::string &iniFilePath, const std::string &fileName,
                                            const std::string &jsonEventValue)
        {
            HILOG_INFO("InjectionIni: start");
            if (iniFilePath.empty()) {
                return;
            }

            const std::string eventsFile = iniFilePath + fileName;
            HILOG_INFO("eventsfile=%s", eventsFile.c_str());
            std::ofstream file_writer(eventsFile, std::ios_base::trunc);
            file_writer.close();

            std::ofstream file;
            char path[PATH_MAX] = {};
            if (realpath(eventsFile.c_str(), path) == nullptr) {
                HILOG_INFO("path is error, eventsFile = %{public}s", eventsFile.c_str());
                return;
            }
            file.open(path, std::ios::app);
            if (!file.is_open()) {
                std::cout << "cannot open file" << std::endl;
            }
            HILOG_INFO("jsonEventValue=%s", jsonEventValue.c_str());
            file << jsonEventValue << std::endl;
            file.close();
            HILOG_INFO("InjectionIni: end");
        }

        void MultiInputCommon::SetIniFile(const std::string &fileName,const std::string &jsonEventValue)
        {
            HILOG_INFO("SetIniFile: start");
            const std::string iniFilePath = "/data/mmi/";
            HILOG_INFO("jsonEventValue=%{public}s", jsonEventValue.c_str());
            InjectionIni(iniFilePath,fileName,jsonEventValue);
            HILOG_INFO("SetIniFile: end");
        }
    }
}
