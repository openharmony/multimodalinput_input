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

#ifndef RUN_SHELL_UTIL_H
#define RUN_SHELL_UTIL_H

#include <regex>
#include <string>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class RunShellUtil {
public:
    RunShellUtil();
    DISALLOW_COPY_AND_MOVE(RunShellUtil);
    ~RunShellUtil();
    int32_t RunShellCommand(const std::string &command, std::vector<std::string> &vLog);
    int32_t SetLogMaxSize(int32_t logSize);

    static int32_t StringToVectorByRegex(const std::string &log, std::vector<std::string> &vLog, const std::regex &r);

private:
    FILE *fp_ {nullptr};
    int32_t logMaxSize_;
};
} // namespace MMI
} // namespace OHOS
#endif // RUN_SHELL_UTIL_H