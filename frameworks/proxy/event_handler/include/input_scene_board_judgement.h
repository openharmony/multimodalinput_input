/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ROSEN_MMI_SCENE_SCENE_BOARD_JUDGEMENT_H
#define OHOS_ROSEN_MMI_SCENE_SCENE_BOARD_JUDGEMENT_H

#include <fstream>

namespace OHOS {
namespace MMI {
class MMISceneBoardJudgement final {
public:
    static bool IsSceneBoardEnabled();
    static bool IsResampleEnabled();
private:
    // Dealing with Windows type end of line "\r\n".
    static std::ifstream& SafeGetLine(std::ifstream& configFile, std::string& line);
    static void InitWithConfigFile(const char* filePath, bool& enabled);
};
} // namespace MMI
} // namespace OHOS
#endif // OHOS_ROSEN_MMI_SCENE_SCENE_BOARD_JUDGEMENT_H
