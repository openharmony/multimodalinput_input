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

#include "util.h"
#include <chrono>
#include <cstdarg>
#include <iomanip>
#include <sstream>
#include <thread>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef OHOS_BUILD
#include <execinfo.h>
#endif // OHOS_BUILD
#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "log.h"
#include "securec.h"
#include "uuid.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "Util"};
    }
}

namespace OHOS {
namespace MMI {
const std::map<int32_t, std::string> ERROR_STRING_MAP = {
    {MSG_SEND_FAIL, "Send Message Failed"},
    {NON_STD_EVENT, "Non-Standardized Event"},
    {UNKNOWN_EVENT, "Unknown Event"},
    {UNPROC_MSG, "Unprocessed Message"},
    {UNKNOWN_MSG_ID, "Unknown Message Id"},
    {UNKNOWN_DEV, "Unknown Device"},
    {NULL_POINTER, "Null Pointer"},
    {FILE_OPEN_FAIL, "Open File Failed"},
    {FILE_READ_FAIL, "Read File Failed"},
    {FILE_WRITE_FAIL, "Write File Failed"},
    {API_PARAM_TYPE_FAIL, "API Param Type Error"},
    {API_OUT_OF_RANGE, "API Out Of Range Error"},
    {FOCUS_ID_OBTAIN_FAIL, "Obtain FocusID Failed"},
};

const char *GetMmiErrorTypeDesc(int32_t errorCodeEnum)
{
    auto str = ERROR_STRING_MAP.find(errorCodeEnum);
    if (str == ERROR_STRING_MAP.end()) {
        return nullptr;
    }
    return str->second.c_str();
}

std::string GetEnv(const std::string &name)
{
    CHKR(!name.empty(), PARAM_INPUT_INVALID, "");
    auto val = getenv(name.c_str());
    if (val == nullptr) {
        return "";
    }
    return val;
}

int64_t GetMicrotime()
{
    struct timeval currentTime = {};
    gettimeofday(&currentTime, nullptr);
    return currentTime.tv_sec * static_cast<int32_t>(1e6) + currentTime.tv_usec;
}

uint64_t GetSysClockTime()
{
    const int32_t conversionStep = 1000;
    struct timespec ts = { 0, 0 };

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        MMI_LOGT("clock_gettime failed: %{public}s\n", strerror(errno));
        return 0;
    }

    return (ts.tv_sec * static_cast<uint64_t>(1e6)) + (ts.tv_nsec / conversionStep);
}

int64_t GetMillisTime()
{
    auto timeNow = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(timeNow.time_since_epoch());
    return tmp.count();
}

std::string UuIdGenerate()
{
    constexpr int32_t UUID_BUF_SIZE = 64;
    char buf[UUID_BUF_SIZE] = {};
    return buf;
}

std::string GetUUid()
{
    Uuid uid;
    std::string strUuid;
    uid.ConvertToStdString(strUuid);
    return strUuid;
}

std::string GetThisThreadIdOfString()
{
    thread_local std::string threadLocalId;
    if (threadLocalId.empty()) {
        long tid = syscall(SYS_gettid);
        const size_t bufSize = 10;
        char buf[bufSize] = {};
        const int ret = sprintf_s(buf, bufSize, "%06d", tid);
        if (ret < 0) {
            printf("ERR: in %s, #%d, call sprintf_s fail, ret = %d.", __func__, __LINE__, ret);
            return threadLocalId;
        }
        buf[bufSize - 1] = '\0';
        threadLocalId = buf;
    }

    return threadLocalId;
}

uint64_t GetThisThreadIdOfLL()
{
    std::string stid = GetThisThreadIdOfString();
    auto tid = std::stoull(stid);
    return tid;
}

size_t StringToken(std::string &str, const std::string &sep, std::string &token)
{
    token = "";
    if (str.empty()) {
        return str.npos;
    }
    size_t pos = str.npos;
    size_t tmp = 0;
    for (auto it : sep) {
        tmp = str.find(it);
        if (str.npos != tmp) {
            pos = (std::min)(pos, tmp);
        }
    }
    if (str.npos != pos) {
        token = str.substr(0, pos);
        if (str.npos != pos + 1) {
            str = str.substr(pos + 1, str.npos);
        }
        if (pos == 0) {
            return StringToken(str, sep, token);
        }
    } else {
        token = str;
        str = "";
    }
    return token.size();
}

size_t StringSplit(const std::string &str, const std::string &sep, std::vector<std::string>&vecList)
{
    size_t size;
    auto strs = str;
    std::string token;
    while (str.npos != (size = StringToken(strs, sep, token))) {
        vecList.push_back(token);
    }
    return vecList.size();
}

std::string IdsListToString(const std::vector<int32_t> &list, const std::string &sep)
{
    std::string str;
    for (auto &it : list) {
        str += std::to_string(it) + sep;
    }
    if (str.size() > 0) {
        str.resize(str.size() - sep.size());
    }
    return str;
}

void LocalTime(struct tm &t, time_t curTime)
{
    time_t curTimeTemp = curTime;
    if (curTimeTemp == 0) {
        curTimeTemp = time(nullptr);
    }
    auto tm = localtime(&curTimeTemp);
    if (tm) {
        t = *tm;
    }
}

std::string Strftime(const std::string &format, time_t curTime)
{
    if (format.empty()) {
        return format;
    }
    tm t = {};
    LocalTime(t, curTime);
    char szDTime[32] = "";
    (void)strftime(szDTime, sizeof(szDTime), format.c_str(), &t);
    return szDTime;
}

static void PrintEventJoyStickAxisInfo(const std::string &axisName, const EventJoyStickAxisAbsInfo &r)
{
    MMI_LOGT("%{public}s: {code: %{public}d; value: %{public}d; min: %{public}d; max: %{public}d, "
             "fuzz: %{public}d, flat: %{public}d, resolution: %{public}d,"
             "standardValue: %{public}lf, isChanged: %{public}d}, \n",
             axisName.c_str(), r.code, r.value, r.minimum, r.maximum, r.fuzz, r.flat, r.resolution,
             r.standardValue, r.isChanged);
}

void PrintEventJoyStickAxisInfo(const EventJoyStickAxis& r, const int32_t fd,
    const int32_t abilityId, const int32_t focusId, const uint64_t preHandlerTime)
{
    MMI_LOGT("4.event dispatcher of server: EventJoyStickAxis:devicePhys: %{public}s;"
             "fd: %{public}d; preHandlerTime: %{public}" PRId64 "; "
             "time: %{public}" PRId64 "; deviceType: %{public}u; eventType: %{public}d; deviceName: %{public}s\n",
             r.devicePhys, fd, preHandlerTime, r.time, r.deviceType,
             r.eventType, r.deviceName);

    PrintEventJoyStickAxisInfo(std::string("abs_throttle"), r.abs_throttle);
    PrintEventJoyStickAxisInfo(std::string("abs_hat0x"), r.abs_hat0x);
    PrintEventJoyStickAxisInfo(std::string("abs_hat0y"), r.abs_hat0y);
    PrintEventJoyStickAxisInfo(std::string("abs_x"), r.abs_x);
    PrintEventJoyStickAxisInfo(std::string("abs_y"), r.abs_y);
    PrintEventJoyStickAxisInfo(std::string("abs_z"), r.abs_z);
    PrintEventJoyStickAxisInfo(std::string("abs_rx"), r.abs_rx);
    PrintEventJoyStickAxisInfo(std::string("abs_ry"), r.abs_ry);
    PrintEventJoyStickAxisInfo(std::string("abs_rz"), r.abs_rz);
}

void PrintWMSInfo(const std::string& str, const int32_t fd, const int32_t abilityId, const int32_t focusId)
{
    MMI_LOGT("\nMMIWMS:windowId=[%{public}s]\n", str.c_str());
    if (focusId == -1) {
        MMI_LOGT("\nWMS:windowId = ''\n");
    } else {
        MMI_LOGT("\nWMS:windowId = %{public}d\n", focusId);
    }
    MMI_LOGT("\nCALL_AMS:windowId = ''\n");
    MMI_LOGT("\nMMIAPPM:fd =%{public}d,abilityID = %{public}d\n", fd, abilityId);
}

int GetPid()
{
    return (int)getpid();
}

std::string GetFileName(const std::string& strPath)
{
    size_t nPos = strPath.find_last_of('/');
    if (strPath.npos == nPos)
        nPos = strPath.find_last_of('\\');
    if (strPath.npos == nPos)
        return strPath;
    return strPath.substr(nPos + 1, strPath.npos);
}

const char* GetProgramName()
{
    const size_t programNameSize = 256;
    static char programName[programNameSize] = {};
    if (programName[0] != '\0') {
        return programName;
    }

    const size_t bufSize = 512;
    char buf[bufSize] = { 0 };
    if (sprintf_s(buf, bufSize, "/proc/%d/cmdline", static_cast<int32_t>(getpid())) == -1) {
        KMSG_LOGE("GetProcessInfo sprintf_s /proc/.../cmdline error");
        return "";
    }
    FILE *fp = fopen(buf, "rb");
    if (fp == nullptr) {
        KMSG_LOGE("fp is nullptr, filename = %s.", buf);
        return "";
    }
    const size_t bufLineSize = 512;
    char bufLine[bufLineSize] = { 0 };
    if ((fgets(bufLine, bufLineSize, fp) == nullptr)) {
        KMSG_LOGE("fgets fail.");
        (void)fclose(fp);
        fp = nullptr;
        return "";
    }
    (void)fclose(fp);
    fp = nullptr;

    std::string tempName(bufLine);
    tempName = GetFileName(tempName);
    if (tempName.empty()) {
        KMSG_LOGE("tempName is empty.");
        return "";
    }
    const size_t copySize = (std::min)(tempName.size(), programNameSize - 1);
    if (copySize == 0) {
        KMSG_LOGE("copySize is 0.");
        return "";
    }
    int ret = memcpy_s(programName, programNameSize, tempName.c_str(), copySize);
    if (RET_OK != ret) {
        return "";
    }

    KMSG_LOGI("GetProgramName success. programName = %s", programName);

    return programName;
}

char* MmiBasename(char* path)
{
    if (path == nullptr) {
        return nullptr;
    }

    char* rightSlash = strrchr(path, '/');
    char* pBasename = nullptr;
    if (rightSlash != nullptr) {
        pBasename = (rightSlash + 1);
    } else {
        pBasename = path;
    }

    return pBasename;
}

std::string GetStackInfo()
{
#ifndef OHOS_BUILD
    std::ostringstream oss;
    const size_t bufferSize = 1024;
    void* buffer[bufferSize];

    const int nptrs = backtrace(buffer, bufferSize);
    char** strings = backtrace_symbols(buffer, nptrs);
    if (strings == nullptr) {
        perror("backtrace_symbols");
        return std::string();
    }

    for (int i = 1; i < nptrs; i++) {
        oss << strings[i] << std::endl;
    }
    free(strings);
    return std::string(oss.str());
#else
    return std::string();
#endif
}

void SetThreadName(const std::string& name)
{
    prctl(PR_SET_NAME, name.c_str());
}

namespace {
thread_local std::string g_threadName;
}
const std::string& GetThreadName()
{
    if (!g_threadName.empty()) {
        return g_threadName;
    }

    const size_t MAX_THREAD_NAME_SIZE = 16;
    char thisThreadName[MAX_THREAD_NAME_SIZE + 1];

    // Get current thread name and compare with the specified one.
    int32_t ret = prctl(PR_GET_NAME, thisThreadName);
    if (ret == 0) {
        thisThreadName[MAX_THREAD_NAME_SIZE] = '\0';
        g_threadName = thisThreadName;
    } else {
        const int errnoSaved = errno;
        printf("in GetThreadName, call prctl get name fail, errno: %d, error msg: %s.\n",
               errnoSaved, strerror(errnoSaved));
    }

    return g_threadName;
}

void AddId(IdsList &list, int32_t id)
{
    if (id <= 0) {
        return;
    }
    auto it = std::find(list.begin(), list.end(), id);
    if (it != list.end()) {
        return;
    }
    list.push_back(id);
}

size_t CalculateDifference(const IdsList &list1, IdsList &list2, IdsList &difList)
{
    if (list1.empty()) {
        difList = list2;
        return difList.size();
    }
    if (list2.empty()) {
        difList = list1;
        return difList.size();
    }
    IdsList l1 = list1;
    std::sort(l1.begin(), l1.end());
    IdsList l2 = list2;
    std::sort(l2.begin(), l2.end());
    std::set_difference(l1.begin(), l1.end(), l2.begin(), l2.end(), std::back_inserter(difList));
    return difList.size();
}

}
}
