/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CMD_PARSER_H
#define CMD_PARSER_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace MMI {
class InputReplayCommand {
public:
    InputReplayCommand(int32_t argc, char** argv);
    bool Parse();
    bool Execute();

    static int32_t HandleRecordReplayCommand(int32_t argc, char** argv);
private:
    bool ParseOptions();
    bool ParseDeviceMapping(const std::string& mappingStr);
    void SetupSignalHandlers();
    bool ParseRecordCommand();
    bool ParseReplayCommand();
    bool ExecuteRecordCommand();
    bool ExecuteReplayCommand();
    void PrintUsage() const;

    int32_t argc_;
    char *const *argv_;
    std::string programName_;
    std::string command_;
    std::string filePath_;
    std::vector<std::string> devicePaths_;
    bool useAllDevices_ { false };
    std::map<uint16_t, uint16_t> deviceMapping_;
};
} // namespace MMI
} // namespace OHOS
#endif // CMD_PARSER_H