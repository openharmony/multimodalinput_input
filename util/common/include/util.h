/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
 
#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include "mmi_log.h"
#include "define_multimodal.h"
#include "struct_multimodal.h"

namespace OHOS {

extern "C" {
    int32_t ReadConfigInfo(const char* line, int32_t len, int32_t* element_key, int32_t* element_value);
}

namespace MMI {
struct DeviceConfig {
    int32_t autoSwitch { 1 };
    int32_t delayTime { 500 };
    int32_t intervalTime { 50 };
    int32_t keyboardType { 0 };
};

int64_t GetSysClockTime();
 
int64_t GetMillisTime();

uint64_t GetThisThreadId();

size_t StringSplit(const std::string &str, const std::string &sep, std::vector<std::string> &vecList);

std::string IdsListToString(const std::vector<int32_t> &list, const std::string &sep = ", ");

int32_t GetPid();

const char* GetProgramName();

void SetThreadName(const std::string &name);

void ReadProFile(const std::string &filePath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configMap);

void ReadProConfigFile(const std::string &realPath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configKey);

bool IsValidJsonPath(const std::string &filePath);

std::string ReadJsonFile(const std::string &filePath);

int32_t ReadCursorStyleFile(const std::string &filePath);

int32_t ReadTomlFile(const std::string &filePath, DeviceConfig &devConf);

std::string FileVerification(std::string &filePath, const std::string &checkExtension);

std::string StringPrintf(const char *format, ...);

inline void RemoveSpace(std::string &str)
{
    str.erase(remove_if(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c);}), str.end());
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

inline bool AddInt32(int32_t op1, int32_t op2, int32_t &res)
{
    return AddInt(op1, op2, INT32_MIN, INT32_MAX, res);
}

inline bool AddInt64(int64_t op1, int64_t op2, int64_t &res)
{
    return AddInt(op1, op2, INT64_MIN, INT64_MAX, res);
}

template<typename T>
inline constexpr bool MMI_EQ(const T& x, const T& y)
{
    if constexpr (std::is_floating_point<T>::value) {
        return (std::abs((x) - (y)) <= (std::numeric_limits<T>::epsilon()));
    } else {
        return x == y;
    }
}

template<typename T>
inline bool MMI_EQ(T x, T y, T epsilon)
{
    return (std::abs((x) - (y)) <= (epsilon));
}

template<typename T>
inline bool MMI_EQ(const std::weak_ptr<T>& x, const std::weak_ptr<T>& y)
{
    return !(x.owner_before(y) || y.owner_before(x));
}

inline bool MMI_LNE(float left, float right) //less not equal
{
    constexpr float epsilon = -0.001f;
    return (left - right) < epsilon;
}

inline bool MMI_GNE(float left, float right) //great not equal
{
    constexpr float epsilon = 0.001f;
    return (left - right) > epsilon;
}

inline bool MMI_GE(float left, float right) //great or equal
{
    constexpr float epsilon = -0.001f;
    return (left - right) > epsilon;
}

inline bool MMI_LE(float left, float right) //less or equal
{
    constexpr float epsilon = 0.001f;
    return (left - right) < epsilon;
}

inline constexpr int64_t MS2US(int64_t ms)
{
    constexpr int64_t unit { 1000 };
    return (ms * unit);
}
} // namespace MMI
} // namespace OHOS
#endif // UTIL_H
