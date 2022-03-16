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
#include <string>
#include <vector>

#include "define_multimodal.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
const char *GetMmiErrorTypeDesc(int32_t errorCodeEnum);
std::string UuIdGenerate();
int64_t GetMicrotime();
int64_t GetSysClockTime();
int64_t GetMillisTime();
std::string GetUUid();
std::string GetThisThreadIdOfString();
uint64_t GetNowThreadId();
size_t StringToken(std::string& str, const std::string& sep, std::string& token);
size_t StringSplit(const std::string& str, const std::string& sep, std::vector<std::string>& vecList);
std::string IdsListToString(const std::vector<int32_t>& list, const std::string& sep);
void LocalTime(tm& t, time_t curTime = 0);
std::string Strftime(const std::string& format = "%F %T", time_t curTime = 0);
void PrintEventJoyStickAxisInfo(const EventJoyStickAxis& r, const int32_t fd,
    const int32_t abilityId, const int32_t focusId, const int64_t preHandlerTime);
void PrintWMSInfo(const std::string& str, const int32_t fd, const int32_t abilityId, const int32_t focusId);
int32_t GetPid();
std::string GetFileName(const std::string& strPath);
const char* GetProgramName();
char* MmiBasename(char* path);
std::string GetStackInfo();
void SetThreadName(const std::string& name);
const std::string& GetThreadName();
void AddId(std::vector<int32_t> &list, int32_t id);
size_t CalculateDifference(const std::vector<int32_t> &list1, std::vector<int32_t> &list2,
    std::vector<int32_t> &difList);
std::string StringFmt(const char* str, ...);
bool IsFileExists(const std::string& fileName);
int32_t VerifyFile(const std::string& fileName);
std::string GetFileExtendName(const std::string& fileName);
int32_t GetFileSize(const std::string& fileName);
} // namespace MMI
} // namespace OHOS

#endif // UTIL_H
