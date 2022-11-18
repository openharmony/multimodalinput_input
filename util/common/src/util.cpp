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

#include "util.h"

#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <fstream>
#include <iomanip>
#include <thread>

#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "mmi_log.h"
#include "securec.h"
#include "uuid.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "Util"};
constexpr int32_t FILE_SIZE_MAX = 0x5000;
constexpr int32_t MAX_PRO_FILE_SIZE = 128000;
constexpr int32_t KEY_ELEMENT_COUNT = 4;
constexpr int32_t INVALID_FILE_SIZE = -1;
constexpr int32_t MIN_INTERVALTIME = 50;
constexpr int32_t MAX_INTERVALTIME = 500;
constexpr int32_t MIN_DELAYTIME = 200;
constexpr int32_t MAX_DELAYTIME = 1000;
constexpr int32_t COMMENT_SUBSCRIPT = 0;
const std::string CONFIG_ITEM_REPEAT = "Key.autorepeat";
const std::string CONFIG_ITEM_DELAY = "Key.autorepeat.delaytime";
const std::string CONFIG_ITEM_INTERVAL = "Key.autorepeat.intervaltime";
const std::string CONFIG_ITEM_TYPE = "Key.keyboard.type";
const std::string CURSORSTYLE_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string DATA_PATH = "/data";
const std::string INPUT_PATH = "/system/";
const std::string KEY_PATH = "/vendor/etc/keymap/";
constexpr size_t BUF_TID_SIZE = 10;
constexpr size_t BUF_CMD_SIZE = 512;
constexpr size_t PROGRAM_NAME_SIZE = 256;
} // namespace

const std::map<int32_t, std::string> ERROR_STRING_MAP = {
    {MSG_SEND_FAIL, "Send Message Failed"},
    {NON_STD_EVENT, "Non-Standardized Event"},
    {UNKNOWN_EVENT, "Unknown Event"},
    {UNPROC_MSG, "Unprocessed Message"},
    {UNKNOWN_MSG_ID, "Unknown Message Id"},
    {UNKNOWN_DEV, "Unknown Device"},
    {ERROR_NULL_POINTER, "Null Pointer"},
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

int64_t GetMicrotime()
{
    struct timeval currentTime = {};
    gettimeofday(&currentTime, nullptr);
    return currentTime.tv_sec * 1000 * 1000 + currentTime.tv_usec;
}

int64_t GetSysClockTime()
{
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        MMI_HILOGD("clock_gettime failed:%{public}d", errno);
        return 0;
    }
    return (ts.tv_sec * 1000 * 1000) + (ts.tv_nsec / 1000);
}

int64_t GetMillisTime()
{
    auto timeNow = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(timeNow.time_since_epoch());
    return tmp.count();
}

std::string UuIdGenerate()
{
    static constexpr int32_t uuidBufSize = 64;
    char buf[uuidBufSize] = {};
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
        char buf[BUF_TID_SIZE] = {};
        const int32_t ret = sprintf_s(buf, BUF_TID_SIZE, "%06d", tid);
        if (ret < 0) {
            printf("ERR: in %s, #%d, call sprintf_s failed, ret = %d.", __func__, __LINE__, ret);
            return threadLocalId;
        }
        buf[BUF_TID_SIZE - 1] = '\0';
        threadLocalId = buf;
    }

    return threadLocalId;
}

uint64_t GetThisThreadId()
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
    for (auto &item : sep) {
        tmp = str.find(item);
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
    for (const auto &it : list) {
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
    struct tm t = {};
    LocalTime(t, curTime);
    char szDTime[32] = "";
    (void)strftime(szDTime, sizeof(szDTime), format.c_str(), &t);
    return szDTime;
}

static void PrintEventJoyStickAxisInfo(const std::string &axisName, const EventJoyStickAxisAbsInfo &r)
{
    MMI_HILOGD("%{public}s: {code:%{public}d,value:%{public}d,min:%{public}d,max:%{public}d,"
               "fuzz:%{public}d,flat:%{public}d,resolution:%{public}d,"
               "standardValue:%{public}lf,isChanged:%{public}d}, ",
               axisName.c_str(), r.code, r.value, r.minimum, r.maximum, r.fuzz, r.flat, r.resolution,
               r.standardValue, r.isChanged);
}

void PrintEventJoyStickAxisInfo(const EventJoyStickAxis &r, const int32_t fd,
    const int32_t abilityId, const int32_t focusId, const int64_t preHandlerTime)
{
    MMI_HILOGD("Event dispatcher of server, EventJoyStickAxis:physical:%{public}s,"
               "fd:%{public}d,preHandlerTime:%{public}" PRId64 ","
               "time:%{public}" PRId64 ",deviceType:%{public}u,eventType:%{public}d,deviceName:%{public}s",
               r.physical, fd, preHandlerTime, r.time, r.deviceType,
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

void PrintWMSInfo(const std::string &str, const int32_t fd, const int32_t abilityId, const int32_t focusId)
{
    MMI_HILOGD("MMIWMS:windowId:%{public}s", str.c_str());
    if (focusId == -1) {
        MMI_HILOGD("WMS:windowId = ''");
    } else {
        MMI_HILOGD("WMS:windowId:%{public}d", focusId);
    }
    MMI_HILOGI("CALL_AMS, fd:%{public}d,abilityID:%{public}d", fd, abilityId);
}

int32_t GetPid()
{
    return static_cast<int32_t>(getpid());
}

std::string GetFileName(const std::string &strPath)
{
    size_t nPos = strPath.find_last_of('/');
    if (strPath.npos == nPos) {
        nPos = strPath.find_last_of('\\');
    }
    if (strPath.npos == nPos) {
        return strPath;
    }
    return strPath.substr(nPos + 1, strPath.npos);
}

const char* GetProgramName()
{
    static char programName[PROGRAM_NAME_SIZE] = {};
    if (programName[0] != '\0') {
        return programName;
    }

    char buf[BUF_CMD_SIZE] = { 0 };
    if (sprintf_s(buf, BUF_CMD_SIZE, "/proc/%d/cmdline", static_cast<int32_t>(getpid())) == -1) {
        KMSG_LOGE("GetProcessInfo sprintf_s /proc/.../cmdline error");
        return "";
    }
    FILE *fp = fopen(buf, "rb");
    if (fp == nullptr) {
        KMSG_LOGE("The fp is nullptr, filename = %s.", buf);
        return "";
    }
    static constexpr size_t bufLineSize = 512;
    char bufLine[bufLineSize] = { 0 };
    if ((fgets(bufLine, bufLineSize, fp) == nullptr)) {
        KMSG_LOGE("fgets failed.");
        if (fclose(fp) != 0) {
            KMSG_LOGW("Close file:%s failed", buf);
        }
        fp = nullptr;
        return "";
    }
    if (fclose(fp) != 0) {
        KMSG_LOGW("Close file:%s failed", buf);
    }
    fp = nullptr;

    std::string tempName(bufLine);
    tempName = GetFileName(tempName);
    if (tempName.empty()) {
        KMSG_LOGE("tempName is empty.");
        return "";
    }
    const size_t copySize = std::min(tempName.size(), PROGRAM_NAME_SIZE - 1);
    if (copySize == 0) {
        KMSG_LOGE("The copySize is 0.");
        return "";
    }
    errno_t ret = memcpy_s(programName, PROGRAM_NAME_SIZE, tempName.c_str(), copySize);
    if (ret != EOK) {
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

void SetThreadName(const std::string &name)
{
    prctl(PR_SET_NAME, name.c_str());
}

namespace {
thread_local std::string g_threadName;
} // namespace
const std::string& GetThreadName()
{
    if (!g_threadName.empty()) {
        return g_threadName;
    }
    static constexpr size_t maxThreadNameSize = 16;
    char thisThreadName[maxThreadNameSize + 1];
    int32_t ret = prctl(PR_GET_NAME, thisThreadName);
    if (ret == 0) {
        thisThreadName[maxThreadNameSize] = '\0';
        g_threadName = thisThreadName;
    } else {
        printf("in GetThreadName, call prctl get name fail, errno: %d.\n", errno);
    }
    return g_threadName;
}

void AddId(std::vector<int32_t> &list, int32_t id)
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

size_t CalculateDifference(const std::vector<int32_t> &list1, std::vector<int32_t> &list2,
    std::vector<int32_t> &difList)
{
    if (list1.empty()) {
        difList = list2;
        return difList.size();
    }
    if (list2.empty()) {
        difList = list1;
        return difList.size();
    }
    std::vector<int32_t> l1 = list1;
    std::sort(l1.begin(), l1.end());
    std::vector<int32_t> l2 = list2;
    std::sort(l2.begin(), l2.end());
    std::set_difference(l1.begin(), l1.end(), l2.begin(), l2.end(), std::back_inserter(difList));
    return difList.size();
}

std::string StringFmt(const char* str, ...)
{
    if (str == nullptr) {
        MMI_HILOGW("Str is nullptr");
        return "";
    }
    va_list args;
    va_start(args, str);
    char buf[MAX_PACKET_BUF_SIZE] = {};
    if (vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, str, args) == -1) {
        MMI_HILOGE("vsnprintf_s error");
        va_end(args);
        return "";
    }
    va_end(args);
    return buf;
}

static bool IsFileExists(const std::string &fileName)
{
    return (access(fileName.c_str(), F_OK) == 0);
}

static bool CheckFileExtendName(const std::string &filePath, const std::string &checkExtension)
{
    std::string::size_type pos = filePath.find_last_of('.');
    if (pos == std::string::npos) {
        MMI_HILOGE("File is not find extension");
        return false;
    }
    return (filePath.substr(pos + 1, filePath.npos) == checkExtension);
}

static int32_t GetFileSize(const std::string &filePath)
{
    struct stat statbuf = {0};
    if (stat(filePath.c_str(), &statbuf) != 0) {
        MMI_HILOGE("Get file size error");
        return INVALID_FILE_SIZE;
    }
    return statbuf.st_size;
}

static std::string ReadFile(const std::string &filePath)
{
    FILE* fp = fopen(filePath.c_str(), "r");
    CHKPS(fp);
    std::string dataStr;
    char buf[256] = {};
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        dataStr += buf;
    }
    if (fclose(fp) != 0) {
        MMI_HILOGW("Close file failed");
    }
    return dataStr;
}

static bool IsValidPath(const std::string &rootDir, const std::string &filePath)
{
    return (filePath.compare(0, rootDir.size(), rootDir) == 0);
}

static bool IsValidJsonPath(const std::string &filePath)
{
    return IsValidPath(DATA_PATH, filePath) ||
        IsValidPath(INPUT_PATH, filePath);
}

static bool IsValidProPath(const std::string &filePath)
{
    return IsValidPath(KEY_PATH, filePath);
}

static bool IsValidTomlPath(const std::string &filePath)
{
    return IsValidPath(KEY_PATH, filePath);
}

void ReadProFile(const std::string &filePath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configMap)
{
    CALL_DEBUG_ENTER;
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        MMI_HILOGE("Path is error");
        return;
    }
    if (!IsValidProPath(realPath)) {
        MMI_HILOGE("File path is error");
        return;
    }
    if (!IsFileExists(realPath)) {
        MMI_HILOGE("File is not existent");
        return;
    }
    if (!CheckFileExtendName(realPath, "pro")) {
        MMI_HILOGE("Unable to parse files other than json format");
        return;
    }
    auto fileSize = GetFileSize(realPath);
    if ((fileSize == INVALID_FILE_SIZE) || (fileSize >= MAX_PRO_FILE_SIZE)) {
        MMI_HILOGE("The configuration file size is incorrect");
        return;
    }
    ReadProConfigFile(realPath, deviceId, configMap);
}

void ReadProConfigFile(const std::string &realPath, int32_t deviceId,
    std::map<int32_t, std::map<int32_t, int32_t>> &configKey)
{
    CALL_DEBUG_ENTER;
    std::ifstream reader(realPath);
    if (!reader.is_open()) {
        MMI_HILOGE("Failed to open config file");
        return;
    }
    std::string strLine;
    int32_t sysKeyValue;
    int32_t nativeKeyValue;
    std::map<int32_t, int32_t> tmpConfigKey;
    while (std::getline(reader, strLine)) {
        size_t pos = strLine.find('#');
        if (pos != strLine.npos && pos != COMMENT_SUBSCRIPT) {
            MMI_HILOGE("The comment line format is error");
            reader.close();
            return;
        }
        if (!strLine.empty() && strLine.front() != '#') {
            std::istringstream stream(strLine);
            std::array<std::string, KEY_ELEMENT_COUNT> keyElement;
            stream >> keyElement[0] >> keyElement[1] >> keyElement[2] >> keyElement[3];
            if (keyElement[0].empty() || keyElement[1].empty() || keyElement[2].empty() || keyElement[3].empty()) {
                MMI_HILOGE("The key value data is incomplete");
                reader.close();
                return;
            }
            if (!IsNum(keyElement[1]) || !IsNum(keyElement[2])) {
                MMI_HILOGE("Get key value is invalid");
                reader.close();
                return;
            }
            nativeKeyValue = stoi(keyElement[1]);
            sysKeyValue = stoi(keyElement[2]);
            tmpConfigKey.insert(std::pair<int32_t, int32_t>(nativeKeyValue, sysKeyValue));
        }
    }
    reader.close();
    auto iter = configKey.insert(std::make_pair(deviceId, tmpConfigKey));
    if (!iter.second) {
        MMI_HILOGE("The file name is duplicated");
        return;
    }
}

std::string ReadJsonFile(const std::string &filePath)
{
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return "";
    }
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        MMI_HILOGE("Path is error");
        return "";
    }
    if (!IsValidJsonPath(realPath)) {
        MMI_HILOGE("File path is error");
        return "";
    }
    if (!CheckFileExtendName(realPath, "json")) {
        MMI_HILOGE("Unable to parse files other than json format");
        return "";
    }
    if (!IsFileExists(realPath)) {
        MMI_HILOGE("File is not existent");
        return "";
    }
    int32_t fileSize = GetFileSize(realPath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        MMI_HILOGE("File size out of read range");
        return "";
    }
    return ReadFile(filePath);
}

int32_t ReadTomlFile(const std::string &filePath, DeviceConfig &devConf)
{
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        MMI_HILOGI("The realpath return nullptr");
        return RET_ERR;
    }
    if (!IsValidTomlPath(realPath)) {
        MMI_HILOGE("File path is error");
        return RET_ERR;
    }
    if (!IsFileExists(realPath)) {
        MMI_HILOGE("File is not existent");
        return RET_ERR;
    }
    if (!CheckFileExtendName(realPath, "TOML")) {
        MMI_HILOGE("Unable to parse files other than json format");
        return RET_ERR;
    }
    int32_t fileSize = GetFileSize(realPath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        MMI_HILOGE("File size out of read range");
        return RET_ERR;
    }
    if (ReadConfigFile(realPath, devConf) == RET_ERR) {
        MMI_HILOGE("Read device config file failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ReadConfigFile(const std::string &realPath, DeviceConfig &devConf)
{
    CALL_DEBUG_ENTER;
    std::ifstream cfgFile(realPath);
    if (!cfgFile.is_open()) {
        MMI_HILOGE("Failed to open config file");
        return FILE_OPEN_FAIL;
    }
    std::string tmp;
    while (std::getline(cfgFile, tmp)) {
        RemoveSpace(tmp);
        size_t pos = tmp.find('#');
        if (pos != tmp.npos && pos != COMMENT_SUBSCRIPT) {
            MMI_HILOGE("File format is error");
            cfgFile.close();
            return RET_ERR;
        }
        if (tmp.empty() || tmp.front() == '#') {
            continue;
        }
        pos = tmp.find('=');
        if (pos == (tmp.size() - 1) || pos == tmp.npos) {
            MMI_HILOGE("Find config item error");
            cfgFile.close();
            return RET_ERR;
        }
        std::string configItem = tmp.substr(0, pos);
        std::string value = tmp.substr(pos + 1);
        if (ConfigItemSwitch(configItem, value, devConf) == RET_ERR) {
            MMI_HILOGE("Configuration item error");
            cfgFile.close();
            return RET_ERR;
        }
    }
    cfgFile.close();
    return RET_OK;
}

int32_t ConfigItemSwitch(const std::string &configItem, const std::string &value, DeviceConfig &devConf)
{
    CALL_DEBUG_ENTER;
    if (configItem.empty() || value.empty()) {
        MMI_HILOGE("Get key config item is invalid");
        return RET_ERR;
    }
    if (!IsNum(value)) {
        MMI_HILOGE("Get key config item is invalid");
        return RET_ERR;
    }
    if (configItem == CONFIG_ITEM_REPEAT) {
        devConf.autoSwitch = stoi(value);
    } else if (configItem == CONFIG_ITEM_DELAY) {
        devConf.delayTime = stoi(value);
        if (devConf.delayTime < MIN_DELAYTIME || devConf.delayTime > MAX_DELAYTIME) {
            MMI_HILOGE("Unusual the delaytime");
            return RET_ERR;
        }
    } else if (configItem == CONFIG_ITEM_INTERVAL) {
        devConf.intervalTime = stoi(value);
        if (devConf.intervalTime < MIN_INTERVALTIME || devConf.intervalTime > MAX_INTERVALTIME) {
            MMI_HILOGE("Unusual the intervaltime");
            return RET_ERR;
        }
    } else if (configItem == CONFIG_ITEM_TYPE) {
        devConf.keyboardType = stoi(value);
    }
    return RET_OK;
}

int32_t ReadCursorStyleFile(const std::string &filePath)
{
    CALL_DEBUG_ENTER;
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return RET_ERR;
    }
    if (!IsFileExists(filePath)) {
        MMI_HILOGE("File is not existent");
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        MMI_HILOGE("Path is error");
        return RET_ERR;
    }
    int32_t fileSize = GetFileSize(realPath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        MMI_HILOGE("File size out of read range");
        return RET_ERR;
    }
    return RET_OK;
}

std::string StringPrintf(const char *format, ...)
{
    char space[1024];

    va_list ap;
    va_start(ap, format);
    std::string result;
    int32_t ret = vsnprintf_s(space, sizeof(space), sizeof(space) - 1, format, ap);
    if (ret >= RET_OK && (size_t)ret < sizeof(space)) {
        result = space;
    } else {
        MMI_HILOGE("The buffer is overflow");
    }
    va_end(ap);
    return result;
}
} // namespace MMI
} // namespace OHOS
