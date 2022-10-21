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
#ifndef UTIL_H
#define UTIL_H

#include <ctime>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "define_multimodal.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
struct DeviceConfig {
    int32_t autoSwitch { 1 };
    int32_t delayTime { 300 };
    int32_t intervalTime { 100 };
    int32_t keyboardType { 0 };
};
const char *GetMmiErrorTypeDesc(int32_t errorCodeEnum);
std::string UuIdGenerate();
int64_t GetMicrotime();
int64_t GetSysClockTime();
int64_t GetMillisTime();
std::string GetUUid();
std::string GetThisThreadIdOfString();
uint64_t GetThisThreadId();
size_t StringToken(std::string &str, const std::string &sep, std::string &token);
size_t StringSplit(const std::string &str, const std::string &sep, std::vector<std::string> &vecList);
std::string IdsListToString(const std::vector<int32_t> &list, const std::string &sep = ", ");
void LocalTime(tm &t, time_t curTime = 0);
std::string Strftime(const std::string &format = "%F %T", time_t curTime = 0);
void PrintEventJoyStickAxisInfo(const EventJoyStickAxis &r, const int32_t fd,
    const int32_t abilityId, const int32_t focusId, const int64_t preHandlerTime);
void PrintWMSInfo(const std::string &str, const int32_t fd, const int32_t abilityId, const int32_t focusId);
int32_t GetPid();
std::string GetFileName(const std::string &strPath);
const char* GetProgramName();
char* MmiBasename(char* path);
void SetThreadName(const std::string &name);
const std::string &GetThreadName();
void AddId(std::vector<int32_t> &list, int32_t id);
size_t CalculateDifference(const std::vector<int32_t> &list1, std::vector<int32_t> &list2,
    std::vector<int32_t> &difList);
void ReadProFile(const std::string &filePath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configMap);
void ReadProConfigFile(const std::string &realPath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configKey);
std::string StringFmt(const char* str, ...);
std::string ReadJsonFile(const std::string &filePath);
std::string ReadUinputToolFile(const std::string &filePath);
int32_t ReadCursorStyleFile(const std::string &filePath);
int32_t ReadTomlFile(const std::string &filePath, DeviceConfig &devConf);
int32_t ReadConfigFile(const std::string &realPath, DeviceConfig &devConf);
int32_t ConfigItemSwitch(const std::string &configItem, const std::string &value, DeviceConfig &devConf);
std::string StringPrintf(const char *format, ...);
inline bool IsNum(const std::string &str)
{
    std::istringstream sin(str);
    double num;
    return (sin >> num) && sin.eof();
}
inline void RemoveSpace(std::string &str)
{
    str.erase(remove_if(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c);}), str.end());
}
template <typename T>
bool AddInt(T op1, T op2, T minVal, T maxVal, T &res);
inline bool AddInt32(int32_t op1, int32_t op2, int32_t &res)
{
    return AddInt(op1, op2, INT32_MIN, INT32_MAX, res);
}
inline bool AddInt64(int64_t op1, int64_t op2, int64_t &res)
{
    return AddInt(op1, op2, INT64_MIN, INT64_MAX, res);
}
template<typename T>
bool AddInt(T op1, T op2, T minVal, T maxVal, T &res)
{
    if (op1 >= 0) {
        if (op2 > maxVal - op1) {
            return false;
        }
    } else {
        if (op2 < minVal - op1) {
            return false;
        }
    }
    res = op1 + op2;
    return true;
}
} // namespace MMI
} // namespace OHOS
#endif // UTIL_H
