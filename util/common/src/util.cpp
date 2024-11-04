/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "util.h"

#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <fstream>
#include <iostream>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "aggregator.h"
#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "mmi_log.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "Util"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FILE_SIZE_MAX { 0x6C445 };
constexpr int32_t MAX_PRO_FILE_SIZE { 128000 };
constexpr int32_t INVALID_FILE_SIZE { -1 };
constexpr int32_t MIN_INTERVALTIME { 36 };
constexpr int32_t MAX_INTERVALTIME { 100 };
constexpr int32_t MIN_DELAYTIME { 300 };
constexpr int32_t MAX_DELAYTIME { 1000 };
constexpr int32_t COMMENT_SUBSCRIPT { 0 };
const std::string CONFIG_ITEM_REPEAT = "Key.autorepeat";
const std::string CONFIG_ITEM_DELAY = "Key.autorepeat.delaytime";
const std::string CONFIG_ITEM_INTERVAL = "Key.autorepeat.intervaltime";
const std::string CONFIG_ITEM_TYPE = "Key.keyboard.type";
const std::string CURSORSTYLE_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string DATA_PATH = "/data";
const std::string INPUT_PATH = "/system/";
const std::string KEY_PATH = "/vendor/etc/keymap/";
constexpr size_t BUF_TID_SIZE { 10 };
constexpr size_t BUF_CMD_SIZE { 512 };
constexpr size_t PROGRAM_NAME_SIZE { 256 };
constexpr int32_t TIME_CONVERSION_UNIT { 1000 };
} // namespace

int64_t GetSysClockTime()
{
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        MMI_HILOGD("clock_gettime failed:%{public}d", errno);
        return 0;
    }
    return (ts.tv_sec * TIME_CONVERSION_UNIT * TIME_CONVERSION_UNIT) + (ts.tv_nsec / TIME_CONVERSION_UNIT);
}

int64_t GetMillisTime()
{
    auto timeNow = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(timeNow.time_since_epoch());
    return tmp.count();
}

static std::string GetThisThreadIdOfString()
{
    thread_local std::string threadLocalId;
    if (threadLocalId.empty()) {
        long tid = syscall(SYS_gettid);
        char buf[BUF_TID_SIZE] = {};
        const int32_t ret = sprintf_s(buf, BUF_TID_SIZE, "%06d", tid);
        if (ret < 0) {
            printf("ERR: in %s, #%d, call sprintf_s failed, ret = %d", __func__, __LINE__, ret);
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

static size_t StringToken(std::string &str, const std::string &sep, std::string &token)
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

size_t StringSplit(const std::string &str, const std::string &sep, std::vector<std::string> &vecList)
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

int32_t GetPid()
{
    return static_cast<int32_t>(getpid());
}

static std::string GetFileName(const std::string &strPath)
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

const char *GetProgramName()
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
    CHKPS(fp);
    static constexpr size_t bufLineSize = 512;
    char bufLine[bufLineSize] = { 0 };
    if ((fgets(bufLine, bufLineSize, fp) == nullptr)) {
        KMSG_LOGE("fgets failed");
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
        KMSG_LOGE("tempName is empty");
        return "";
    }
    const size_t copySize = std::min(tempName.size(), PROGRAM_NAME_SIZE - 1);
    if (copySize == 0) {
        KMSG_LOGE("The copySize is 0");
        return "";
    }
    errno_t ret = memcpy_s(programName, PROGRAM_NAME_SIZE, tempName.c_str(), copySize);
    if (ret != EOK) {
        return "";
    }
    KMSG_LOGI("GetProgramName success. programName = %s", programName);

    return programName;
}

void SetThreadName(const std::string &name)
{
    prctl(PR_SET_NAME, name.c_str());
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
    struct stat statbuf = { 0 };
    if (stat(filePath.c_str(), &statbuf) != 0) {
        MMI_HILOGE("Get file size error");
        return INVALID_FILE_SIZE;
    }
    return statbuf.st_size;
}

static std::string ReadFile(const std::string &filePath)
{
    FILE *fp = fopen(filePath.c_str(), "r");
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

bool IsValidJsonPath(const std::string &filePath)
{
    return IsValidPath(DATA_PATH, filePath) || IsValidPath(INPUT_PATH, filePath);
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
    CHKPV(realpath(filePath.c_str(), realPath));
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

static inline bool IsNum(const std::string &str)
{
    std::istringstream sin(str);
    double num;
    return (sin >> num) && sin.eof();
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
    int32_t elementKey = 0;
    int32_t elementValue = 0;
    std::map<int32_t, int32_t> tmpConfigKey;
    while (std::getline(reader, strLine)) {
        const char* line = strLine.c_str();
        int32_t len = strlen(line);
        char* realLine = static_cast<char*>(malloc(len + 1));
        CHKPV(realLine);
        if (strcpy_s(realLine, len + 1, line) != EOK) {
            MMI_HILOGE("strcpy_s error");
            free(realLine);
            realLine = nullptr;
            return;
        }
        *(realLine + len + 1) = '\0';
        int32_t ret = ReadConfigInfo(realLine, len, &elementKey, &elementValue);
        free(realLine);
        realLine = nullptr;
        if (ret != RET_OK) {
            MMI_HILOGE("Failed to read from line of config info");
            reader.close();
            return;
        }
        nativeKeyValue = elementKey;
        sysKeyValue = elementValue;
        MMI_HILOGD("The nativeKeyValue is:%{public}d, sysKeyValue is:%{public}d", nativeKeyValue, sysKeyValue);
        tmpConfigKey.insert(std::pair<int32_t, int32_t>(nativeKeyValue, sysKeyValue));
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
    CHKPS(realpath(filePath.c_str(), realPath));
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

static int32_t ConfigItemSwitch(const std::string &configItem, const std::string &value, DeviceConfig &devConf)
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

static int32_t ReadConfigFile(const std::string &realPath, DeviceConfig &devConf)
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
        if ((pos == std::string::npos) || (tmp.back() == '=')) {
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

int32_t ReadTomlFile(const std::string &filePath, DeviceConfig &devConf)
{
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return RET_ERR;
    }
    char realPath[PATH_MAX] = {};
    CHKPR(realpath(filePath.c_str(), realPath), RET_ERR);
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
    CHKPR(realpath(filePath.c_str(), realPath), RET_ERR);
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

std::string FileVerification(std::string &filePath, const std::string &checkExtension)
{
    if (filePath.empty()) {
        MMI_HILOGE("FilePath is empty");
        return "";
    }
    char realPath[PATH_MAX] = {};
    CHKPS(realpath(filePath.c_str(), realPath));
    if (!IsFileExists(realPath)) {
        MMI_HILOGE("File is not existent");
        return "";
    }
    if (!CheckFileExtendName(realPath, checkExtension)) {
        MMI_HILOGE("Unable to parse files other than json format");
        return "";
    }
    int32_t fileSize = GetFileSize(realPath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        MMI_HILOGE("File size out of read range");
        return "";
    }
    return realPath;
}


bool Aggregator::Record(const LogHeader &lh, const std::string &key, const std::string &record)
{
    constexpr int32_t oneSecond = 1000;
    if (timerId_ != -1) {
        resetTimer_(timerId_);
    } else {
        timerId_ = addTimer_(oneSecond, 1, [this, lh]() {
            FlushRecords(lh);
            timerId_ = -1;
        });
    }
    if (key == key_) {
        auto now = std::chrono::system_clock::now();
        records_.push_back({record, now});
        if (records_.size() >= maxRecordCount_) {
            FlushRecords(lh);
        }
        return true;
    } else {
        FlushRecords(lh, key, record);
        key_ = key;
        return false;
    }
}

void Aggregator::FlushRecords(const LogHeader &lh, const std::string &key, const std::string &extraRecord)
{
    constexpr uint32_t milliSecondWidth = 3;
    constexpr uint32_t microToMilli = 1000;
    size_t recordCount = records_.size();
    std::ostringstream oss;
    if (!records_.empty()) {
        oss << key_;
        oss << ", first: " << records_.front().record << "-(";
        auto firstTime = records_.front().timestamp;
        time_t firstTimeT = std::chrono::system_clock::to_time_t(firstTime);
        std::tm *bt = std::localtime(&firstTimeT);
        if (bt == nullptr) {
            MMI_HILOGE("bt is nullptr, this is a invalid time");
            return;
        }
        oss << std::put_time(bt, "%Y-%m-%d %H:%M:%S");
        auto since_epoch = firstTime.time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch).count() % microToMilli;
        oss << '.' << std::setfill('0') << std::setw(milliSecondWidth) << millis << "ms)";

        if (records_.size() > 1) {
            size_t i = records_.size() - 1;
            const auto &recordInfo = records_[i];
            oss << ", " << recordInfo.record;
        }
        records_.clear();
        oss << ", count: " << recordCount;
    }
    if (!extraRecord.empty()) {
        if (!oss.str().empty()) {
            oss << ", last: ";
        }
        oss << key << ": " << extraRecord;
    }
    if (!oss.str().empty()) {
        MMI_HILOG_HEADER(LOG_INFO, lh, "%{public}s", oss.str().c_str());
    }
}

Aggregator::~Aggregator()
{
    FlushRecords(MMI_LOG_HEADER);
}

} // namespace MMI
} // namespace OHOS
