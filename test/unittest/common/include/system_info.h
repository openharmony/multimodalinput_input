/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SYSTEM_INFO_H
#define SYSTEM_INFO_H

#include <iostream>

namespace OHOS {
namespace MMI {
namespace SYSTEM_INFO {
static constexpr double CPU_USAGE_UNKONW = -1.0;
static constexpr double CPU_USAGE_LOAD = 20.0;
static constexpr double CPU_USAGE_MAX = 100.0;
class SystemInfo {
public:
    SystemInfo() = default;
    virtual ~SystemInfo() = default;
    virtual double GetSystemCpuUsage();
    virtual double GetProcCpuUsage(const std::string &process_name);
};

class CpuInfo : public SystemInfo {
public:
    double GetSystemCpuUsage();
    double GetProcCpuUsage(const std::string &process_name);
private:
    struct Total_Cpu_Occupy {
        char name[20] { 0 };
        int32_t user { 0 };
        int32_t nice { 0 };
        int32_t system { 0 };
        int32_t idle { 0 };
        int32_t lowait { 0 };
        int32_t irq { 0 };
        int32_t softirq { 0 };
        int32_t steal { 0 };
        int32_t guest { 0 };
        int32_t guest_nice { 0 };
    };
    struct Proc_Cpu_Occupy {
        int32_t utime { 0 };
        int32_t stime { 0 };
        int32_t cutime { 0 };
        int32_t cstime { 0 };
    };
    int32_t GetTaskPidFile(const std::string &process_name);
    int32_t GetTaskPidCmd(const std::string &process_name, int32_t flag = 0, std::string user = "");
    int32_t GetProcOccupy(int32_t pid);

    int32_t GetSystemCpuStatInfo(Total_Cpu_Occupy &info);
    int64_t GetSystemTotalOccupy();
    double GetCpuUsage(const Total_Cpu_Occupy &first, const Total_Cpu_Occupy &second);
};
} // namespace SYSTEM_INFO
} // namespace MMI
} // namespace OHOS
#endif
