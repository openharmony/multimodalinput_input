/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "mmi_log.h"
#include "parameters.h"
#include "input_scene_board_judgement.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMISceneBoardJudgement"

namespace OHOS {
namespace MMI {
bool MMISceneBoardJudgement::IsSceneBoardEnabled()
{
    static bool isSceneBoardEnabled = false;
    static bool initialized = false;
    if (!initialized) {
        InitWithConfigFile("/etc/sceneboard.config", isSceneBoardEnabled);
        initialized = true;
    }
    return isSceneBoardEnabled;
}

bool MMISceneBoardJudgement::IsResampleEnabled()
{
    static bool isResampleEnabled = false;
    static bool resampleInited = false;
    if (!resampleInited) {
        MMI_HILOGD("Resample algorithm switch is not inited");
        isResampleEnabled =
        (std::atoi((OHOS::system::GetParameter("persist.sys.input.resampleEnabled", "0")).c_str()) != 0);
        MMI_HILOGD("isResampleEnabled is set to %{public}d", isResampleEnabled);
        resampleInited = true;
    }
    return isResampleEnabled;
}
std::ifstream& MMISceneBoardJudgement::SafeGetLine(std::ifstream& configFile, std::string& line)
{
    std::getline(configFile, line);
    if (!line.empty() && (line.back() == '\r')) {
        line.pop_back();
    }
    return configFile;
}

void MMISceneBoardJudgement::InitWithConfigFile(const char* filePath, bool& enabled)
{
    char checkPath[PATH_MAX] = { 0 };
    if (realpath(filePath, checkPath) == nullptr) {
        MMI_HILOGE("canonicalize failed. path:%{public}s", filePath);
        return;
    }
    std::ifstream configFile(checkPath);
    std::string line;
    if (configFile.is_open() && SafeGetLine(configFile, line) && line == "ENABLED") {
        enabled = true;
    }
    configFile.close();
}
} // namespace MMI
} // namespace OHOS
