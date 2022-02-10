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

#include "log.h"
#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config_multimodal.h"
#include "klog.h"
#include "securec.h"
#include "util.h"

#ifdef OHOS_BUILD_MMI_DEBUG

namespace OHOS {
namespace MMI {
const static std::string LOG_CONFIG_PATH = "path";
const static std::string LOG_CONFIG_LEVEL = "level";
const static std::string LOG_CONFIG_DISPLAY = "display";
const static std::string LOG_CONFIG_LIMIT_SIZE = "limitsize";
const static std::string LOG_CONFIG_FILELINE = "fileline";

const static std::string LOG_LEVEL_TRACE = "trace";
const static std::string LOG_LEVEL_DEBUG = "debug";
const static std::string LOG_LEVEL_INFO = "info";
const static std::string LOG_LEVEL_WARN = "warn";
const static std::string LOG_LEVEL_ERROR = "error";
const static std::string LOG_LEVEL_ALARM = "alarm";
const static std::string LOG_LEVEL_FATAL = "fatal";

const static std::string LOG_CONFIG_CLOSE = "false";

const static std::string LOG_COLORS[] = {
    "\e[1;37m", // WHITE
    "\e[1;37m", // WHITE
    "\e[0;34m", // BLUE
    "\e[1;33m", // YELLOW
    "\e[0;31m", // RED
    "\e[1;32m", // L_GREEN
    "\e[1;35m"  // L_PURPLE
};

const static std::string LOG_LEVELSTR[] = {
    "TRACE",
    "DEBUG",
    "INFO ",
    "WARN ",
    "ERROR",
    "ALARM",
    "FATAL"
};

constexpr static int32_t SECONDE_UNIT = 1000;
constexpr static int32_t USLEEP_DELAY = 50000;
constexpr static int32_t AD_1900 = 1900;
constexpr static int32_t PERCENT = 100;
constexpr static int32_t TIME_OUT = 3000;
constexpr static int32_t RATE_PARA = 2;
constexpr static int32_t ONE_MILLION = 1024 * 1024;

namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MmiConsoleLog" };
}

// LogManager
void mmi_console_log(bool withoutFileInfo, char* fileName, int lineNo, int level, const std::string& threadName,
                     const char* fmt, ...);

#define MMI_LOG_MANAGER_OUT(fmt, ...) do { \
    printf(fmt, ##__VA_ARGS__); \
} while (0)

#define LOGLOG(fmt, ...) do { \
    mmi_console_log(false, (char *)__FILE__, __LINE__, OHOS::MMI::LL_INFO, OHOS::MMI::GetThreadName(), \
    MMI_FUNC_FMT fmt "[only_console]", MMI_FUNC_INFO, ##__VA_ARGS__); \
    OHOS::HiviewDFX::HiLog::Error(LABEL, MMI_FUNC_FMT fmt, MMI_FUNC_INFO, ##__VA_ARGS__); \
} while(0)

static std::string ExtIgnore(const std::string& str)
{
    auto text = str;
    size_t n = str.find_last_not_of(" \r\n\t");
    if (n != std::string::npos) {
        text.erase(n + 1, text.size() - n);
    }
    n = str.find_first_not_of(" \r\n\t");
    if (n != std::string::npos) {
        text.erase(0, n);
    }
    return text;
}

static std::pair<std::string, std::string> SplitString(const std::string& str, const std::string& separator)
{
    auto inStr = str;
    auto last = std::remove(inStr.begin(), inStr.end(), ' ');
    inStr.erase(last, inStr.end());
    std::string::size_type pos = inStr.find(separator.c_str());
    if (pos == std::string::npos) {
        return std::make_pair(inStr, "");
    }
    return std::make_pair(inStr.substr(0, pos), inStr.substr(pos + separator.length(), inStr.length()));
}

const std::vector<char> RemovePrivacyIdentifierInFmt(const std::string& format)
{
    const size_t formatLen = format.size();
    const size_t oneLineSize = 10;
    std::vector<char> format2;
    format2.reserve(formatLen + 1);

    size_t readPos = 0;
    size_t writePos = 0;
    while (readPos < formatLen) {
        if (formatLen - readPos >= (oneLineSize - 1)) {
            const size_t publicFormatLen = 9;
            if (format.size() >= publicFormatLen && format.substr(readPos, publicFormatLen) == "%{public}") {
                readPos += (oneLineSize - 1);
                format2.push_back('%');
                ++writePos;
                continue;
            }
        }

        if (formatLen - readPos >= oneLineSize) {
            const size_t privateFormatLen = 10;
            if (format.size() >= privateFormatLen && format.substr(readPos, privateFormatLen) == "%{private}") {
                readPos += oneLineSize;
                format2.push_back('%');
                ++writePos;
                continue;
            }
        }

        format2.push_back(format[readPos++]);
        ++writePos;
    }

    while (readPos < formatLen) {
        format2.push_back(format[readPos++]);
        ++writePos;
    };

    format2.push_back('\0');

    return format2;
}

const std::string& GetProcessId()
{
    static std::string localProId_;
    if (!localProId_.empty()) {
        return localProId_;
    }
    char buf[LOG_MAX_LINE_LEN] = { 0 };
    if (sprintf_s(buf, LOG_MAX_LINE_LEN, "%06d", getpid()) == -1) {
        LOGLOG("*** FATAL ERROR ***: GetProcessInfo sprintf_s pid error.\n");
        return localProId_;
    }
    localProId_ = buf;

    return localProId_;
}

const std::string& GetThreadId()
{
    static std::string tmpId;
    if (!tmpId.empty()) {
        return tmpId;
    }
    tmpId = GetThisThreadIdOfString();

    return tmpId;
}

void mmi_console_log(bool withoutFileInfo, char *fileName, int lineNo, int level, const std::string &threadName,
                     const char* fmt, ...)
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    struct tm* p = localtime(&tv.tv_sec);
    CHKP(p);
    const uint32_t precise = uint32_t(tv.tv_usec / SECONDE_UNIT); // 毫秒

    int32_t ret;
    // 时间
    char longTime[LOG_MAX_TIME_LEN] = {};
    ret = snprintf_s(longTime, sizeof(longTime), LOG_MAX_TIME_LEN, "%02d-%02d-%02d %02d:%02d:%02d.%03d",
        p->tm_year + AD_1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, precise);
    if (ret < 0) {
        printf("FATAL ERROR, call LOGLOG fail. in %s, #%d\n", __func__, __LINE__);
        return;
    }

    const std::vector<char> newFormat = RemovePrivacyIdentifierInFmt(fmt);
    char buf[LOG_MAX_BUF_LEN] = {};
    va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvarargs"
    va_start(args, &newFormat[0]);
#pragma GCC diagnostic pop
    if (vsnprintf_s(buf, LOG_MAX_BUF_LEN, LOG_MAX_BUF_LEN - 1, &newFormat[0], args) == -1) {
        printf("call vsnprintf_s error");
        va_end(args);
        return;
    }
    va_end(args);

    printf("%s%s [%s] [%s] [%s] [%s] %s ",
        LOG_COLORS[level].c_str(), longTime, GetProcessId().c_str(), GetThreadId().c_str(),
        threadName.c_str(), LOG_LEVELSTR[level].c_str(), buf);

    if (withoutFileInfo) {
        printf("%s:%d", MmiBasename(fileName), lineNo);
        printf(" [PRINT_BY_LOGLOG]");
    }
    printf("\e[0m\n");
}

bool LogManager::SemCreate(int32_t count)
{
    if (isCreate_) {
        LOGLOG("LogManager::SemCreate ok");
        return true;
    }
    if (count < 0) {
        count = 0;
    }

    if (sem_init(&semId_, 0, count) != 0) {
        LOGLOG("LogManager::SemCreate sem_init error");
        return false;
    }

    isCreate_ = true;
    return true;
}

bool LogManager::SemWait(int32_t timeout)
{
    if (timeout <= 0) {
        return (sem_wait(&semId_) == 0);
    } else {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            LOGLOG("LogManager::SemWait clock_gettime");
        }
        ts.tv_sec += timeout;
        int s = 0;
        while ((s = sem_timedwait(&semId_, &ts)) == -1 && errno == EINTR) {
            continue;
        }

        if (s == -1) {
            if (errno == ETIMEDOUT) {
                LOGLOG("LogManager::SemWait sem_timedwait() timedout");
                return false;
            } else {
                LOGLOG("LogManager::SemWait sem_timedwait error");
                return false;
            }
        } else {
            LOGLOG("LogManager::SemWait sem_timedwait()succeeded");
            return true;
        }

        return false;
    }
    return true;
}

bool LogManager::SemPost(void)
{
    return (sem_post(&semId_) == 0);
}

bool LogManager::Wait(void)
{
    if (t_.joinable()) {
        t_.join();
    } else {
        LOGLOG("in %s, can not join.", __func__);
    }
    return true;
}

void LogManager::WriteFile(LogDataPtr pLog)
{
    if (!pLog) {
        LOGLOG("pLog is nullptr.");
        return;
    }
    // 时间
    char longTime[LOG_MAX_TIME_LEN] = {};
    struct tm* p = localtime(&pLog->curTime);
    CHKP(p);
    int32_t ret = snprintf_s(longTime, sizeof(longTime), LOG_MAX_TIME_LEN, "%02d-%02d-%02d %02d:%02d:%02d.%03d",
                             p->tm_year + AD_1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, pLog->precise);
    if (ret < 0) {
        LOGLOG("*** FATAL ERROR ***: in %s, #%d, call snprintf_s fail.", __func__, __LINE__);
        return;
    }

    if (runing_) {
        std::ostringstream oss;
        oss << longTime << " [" << proId_ << "] [" << pLog->threadId_ << "] [" << pLog->threadName_ << "] ["
            << LOG_LEVELSTR[pLog->level] << "] " << pLog->data << " ("
            << pLog->curFile << ")";
        if (logFileline_) {
            oss << ":" << pLog->curLine;
        }

        oss << std::endl;
        if (!oss.good()) {
            LOGLOG("%s [%s] [%s] %s, %s:%d[oss is not good]", longTime, proId_.c_str(),
                pLog->threadId_.c_str(), pLog->data.c_str(), pLog->curFile.c_str(), pLog->curLine);
        } else {
            f_.Write(oss.str().c_str(), strlen(oss.str().c_str()));
        }
    }

    // 控制台输出
    if (logDisplay_) {
        MMI_LOG_MANAGER_OUT("%s%s [%s] [%s] [%s] [%s] %s ",
            LOG_COLORS[pLog->level].c_str(), longTime, proId_.c_str(), pLog->threadId_.c_str(),
            pLog->threadName_.c_str(), LOG_LEVELSTR[pLog->level].c_str(), pLog->data.c_str());

        if (logFileline_) {
            auto tmpStr = GetFileName(pLog->curFile);
            MMI_LOG_MANAGER_OUT("%s:%d", tmpStr.c_str(), pLog->curLine);
        }

        if (!runing_) {
            MMI_LOG_MANAGER_OUT(" [LGMGR_NO_RUN]");
        }

        MMI_LOG_MANAGER_OUT("\e[0m\n");
    }
}

LogManager::LogManager()
{
    runing_ = false;
    proId_ = "0";
    proName_ = "process";
    isCreate_ = false;
    logLevel_ = LL_TRACE;
    limitSize_ = LOG_MAX_FILE_SIZE;
    logDisplay_ = true;
    logFileline_ = false;

    pthread_mutexattr_t attr = {};
    pthread_mutexattr_init(&attr);
    pthread_mutex_init(&mutex_, &attr);
    pthread_mutexattr_destroy(&attr);

    GetProcessInfo();
}

LogManager::~LogManager()
{
    Stop();
    pthread_mutex_destroy(&mutex_);

    if (isCreate_) {
        isCreate_ = false;
        sem_destroy(&semId_);
    }
}

bool LogManager::SetLogName(const std::string& name)
{
    if (name.empty()) {
        LOGLOG("LogManager::SetLogName error, name is empty");
        return false;
    }
    proFileName_ = name;
    return true;
}

bool LogManager::SetLogPath(const std::string& path)
{
    if (path.empty()) {
        LOGLOG("LogManager::SetLogPath error, path is empty");
        return false;
    }

    filePath_ = path;
    char ch = filePath_.at(filePath_.length() - 1);
    if ((ch != '\\') && (ch != '/')) {
        filePath_.append("/");
    }
    return true;
}

// 获取进程ID和进程名
void LogManager::GetProcessInfo(void)
{
    proId_ = GetProcessId();
    proName_ = GetProgramName();
}

bool LogManager::OpenFileHandle()
{
    if (fileName_.empty()) {
        return false;
    }
    // 打开日志句柄
    f_.Open(fileName_.c_str(), "wb+");
    if (!f_.IsOpen()) {
        LOGLOG("LogManager::CreateFile load log file error. filename=%s", fileName_.c_str());
        return false;
    }
    return true;
}

bool LogManager::CreateFile()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    fileCreateTime_ = tv.tv_sec;
    struct tm* p = nullptr;
    p = localtime(&fileCreateTime_);
    char logFileTime[LOG_MAX_TIME_LEN] = {0};
    int32_t ret = -1;
    ret = snprintf_s(logFileTime, sizeof(logFileTime), LOG_MAX_TIME_LEN, "_%02d%02d%02d%02d%02d%02d",
                     p->tm_year + AD_1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
    if (ret < 0) {
        LOGLOG("LogManager::CreateFile get logFileTime error.");
        return false;
    }

    std::string fileTime = logFileTime;
    fileName_ = filePath_ + proFileName_ + "_" + GetProcessId() + fileTime + ".log";
    return OpenFileHandle();
}

void LogManager::ParseLogLevel(const std::string& str)
{
    auto level = logLevel_;
    if (str == LOG_LEVEL_TRACE) {
        logLevel_ = LL_TRACE;
    } else if (str == LOG_LEVEL_DEBUG) {
        logLevel_ = LL_DEBUG;
    } else if (str == LOG_LEVEL_INFO) {
        logLevel_ = LL_INFO;
    } else if (str == LOG_LEVEL_WARN) {
        logLevel_ = LL_WARN;
    } else if (str == LOG_LEVEL_ERROR) {
        logLevel_ = LL_ERROR;
    } else if (str == LOG_LEVEL_ALARM) {
        logLevel_ = LL_ALARM;
    } else if (str == LOG_LEVEL_FATAL) {
        logLevel_ = LL_FATAL;
    } else { // do nothing
    }
    if (level != logLevel_) {
        LOGLOG("The log level will be modified. The old is '%s' and the new is '%s'",
               LOG_LEVELSTR[level].c_str(), LOG_LEVELSTR[logLevel_].c_str());
    }
}

void LogManager::ParseLogDisplay(const std::string& str)
{
    auto display = logDisplay_;
    if (str == LOG_CONFIG_CLOSE) {
        logDisplay_ = false;
    } else {
        logDisplay_ = true;
    }
    if (display != logDisplay_) {
        LOGLOG("The log DisplayStatus will be modified. The old is %d and the new is %d",
               display, logDisplay_);
    }
}

void LogManager::ParseLogLimitSize(const std::string& str)
{
    size_t size = limitSize_;
    size_t limit = atoi(str.c_str());
    const size_t minLimitSize = 10;
    const size_t maxLimitSize = 1024;
    limit = (limit <= 0) ? minLimitSize : limit;
    limit = (limit > maxLimitSize) ? maxLimitSize : limit;
    limitSize_ = limit * ONE_MILLION;
    if (LOG_MAX_FILE_SIZE != size && size != limitSize_) {
        LOGLOG("The log LimitSize will be modified. The old is %zu and the new is %zu",
               size, limitSize_);
    }
}

void LogManager::ParseLogFileLine(const std::string& str)
{
    auto fileLine = logFileline_;
    if (str == LOG_CONFIG_CLOSE) {
        logFileline_ = false;
    } else {
        logFileline_ = true;
    }
    if (fileLine != logFileline_) {
        LOGLOG("The log ShowFileLineStatus will be modified. The old is %d and the new is %d",
               fileLine, logFileline_);
    }
}

void LogManager::ParseConfig(const FileHandle& f)
{
    std::string line = f.ReadLine();
    while (!line.empty()) {
        std::string kvLine = ExtIgnore(line);
        std::pair<std::string, std::string> kv = SplitString(kvLine, "=");
        std::string keyConfig = kv.first;
        std::string keyValue = kv.second;
        if (keyValue.empty()) {
            line = f.ReadLine();
            continue;
        }

        if (keyConfig == LOG_CONFIG_PATH) {
            filePath_ = keyValue;
            SetLogPath(filePath_.c_str());
            if (access(filePath_.c_str(), 0) != 0) {
                char cmdStr[LOG_MAX_CMD_LEN] = {0};
                if (sprintf_s(cmdStr, LOG_MAX_CMD_LEN, "mkdir -p %s", filePath_.c_str()) == -1) {
                    LOGLOG("filePath mkdir %s sprintf_s error", filePath_.c_str());
                    return;
                }
                system(cmdStr);
            }
        } else if (keyConfig == LOG_CONFIG_LEVEL) {
            ParseLogLevel(keyValue);
        } else if (keyConfig == LOG_CONFIG_DISPLAY) {
            ParseLogDisplay(keyValue);
        } else if (keyConfig == LOG_CONFIG_LIMIT_SIZE) {
            ParseLogLimitSize(keyValue);
        } else if (keyConfig == LOG_CONFIG_FILELINE) {
            ParseLogFileLine(keyValue);
        } else { // do nothing
        }

        line = f.ReadLine();
    }
}

void LogManager::LoadConfig()
{
    FileHandle f;
    f.Open(configPath_.c_str(), "r");
    if (!f.IsOpen()) {
        LOGLOG("LogManager::LoadConfig open file error. filename=%s", configPath_.c_str());
        return;
    }
    ParseConfig(f);
    f.Close();
}

// 初始化
bool LogManager::Init(const std::string& configPath)
{
    LOGLOG("LogManager::Init starting!");
    if (!configPath.data()) {
        LOGLOG("LogManager::init error: configPath == null");
        return false;
    }
    if (access(configPath.c_str(), 0) != 0) {
        LOGLOG("LogManager::init error: configPath is not exsit, configPath = %s", configPath.c_str());
        return false;
    }
    configPath_ = configPath;
    LoadConfig();

    // 设置日志路径，如果目录不存在，创建目录
    if (filePath_.empty()) {
        filePath_ = DEF_MMI_DATA_ROOT "log/";
    }
    SetLogPath(filePath_.c_str());
    char cmdStr[LOG_MAX_CMD_LEN] = {0};
    if (access(filePath_.c_str(), 0) != 0) {
        if (sprintf_s(cmdStr, LOG_MAX_CMD_LEN, "mkdir -p %s", filePath_.c_str()) == -1) {
            LOGLOG("LogManager::Init sprintf_s error cmd: mkdir -p %s", filePath_.c_str());
            return false;
        }
        system(cmdStr);
    }
    // 设置日志文件名
    SetLogName(proName_.c_str());
    return CreateFile();
}

bool LogManager::Start(void)
{
    LOGLOG("LogManager::start log thread starting!");
    if (runing_) {
        LOGLOG("log thread started!");
        return false;
    }
    if (configPath_.empty()) {
        LOGLOG("LogManager::Start init error, start error");
        return false;
    }
    SemCreate(0);
    t_ = std::thread(std::bind(&LogManager::OnThread, this, std::ref(threadPromiseHadRunning_),
        std::ref(threadPromiseHadEnd_)));
    return SemWait(TIME_OUT);
}

bool LogManager::Stop()
{
    if (runing_) {
        LOGLOG("LogManager::stop, log thread stoping, log queue size: %" PRId64 ".", static_cast<uint64_t>(logs_.size()));
        toExit_ = true;
        // runing_ = false;
        // while (!logs_.empty()) {
            // logs_.pop();
        // }
        Wait();
        LOGLOG("LogManager::stop, wait log thread stoping end, log queue size: %" PRId64 ".", static_cast<uint64_t>(logs_.size()));
        return true;
    }

    LOGLOG("LogManager::stop, log had stoped., log queue size: %" PRId64 ".", static_cast<uint64_t>(logs_.size()));
    return false;
}

bool LogManager::PushLog(LogDataPtr pLog)
{
    if (!runing_ || (pLog == nullptr)) {
        if (pLog != nullptr) {
            // 直接写到控制台
            WriteFile(pLog);
        } else {
            LOGLOG("pLog == nullptr");
        }

        return false;
    }

    pthread_mutex_lock(&mutex_);
    logs_.push(pLog);
    pthread_mutex_unlock(&mutex_);
    return true;
}

bool LogManager::PushString(const int32_t level, const std::string& file, const int32_t line, const std::string& buf)
{
    if (buf.empty() || file.empty()) {
        LOGLOG("LogManager::PushString buf is empty or file is empty");
        return false;
    }
    int32_t count = static_cast<int32_t>(logs_.size());
    if (count > LOG_QUEUE_LIMIT_SIZE) {
        int32_t rate = (count - LOG_QUEUE_LIMIT_SIZE) * PERCENT / LOG_QUEUE_LIMIT_SIZE;
        if (rate > PERCENT) {
            rate = PERCENT;
        }
        if (rate > PERCENT / RATE_PARA) {
            LOGLOG("LogManager::PushString log count limit count : %d", count);
            return true;
        }
    }

    LogDataPtr pLog(new LogData());
    if (pLog == nullptr) {
        LOGLOG("LogManager::PushString new LogData error");
        return false;
    }

    struct timeval tv;
    gettimeofday(&tv, nullptr);

    pLog->curTime = tv.tv_sec;
    pLog->precise = uint32_t(tv.tv_usec / SECONDE_UNIT);
    pLog->level = level;
    pLog->curFile = file;
    pLog->curLine = line;
    pLog->data = buf;

    PushLog(pLog);
    return true;
}

bool LogManager::PushFormat(const int32_t level, const std::string& file, const int32_t line, std::string fm, ...)
{
    if (logLevel_ > level) {
        return true;
    }

    if (file.empty()) {
        LOGLOG("LogManager::PushFormat file is empty");
        return false;
    }

    const std::vector<char> newFormat = RemovePrivacyIdentifierInFmt(fm);

    char buf[LOG_MAX_BUF_LEN] = {};
    va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvarargs"
    va_start(args, &newFormat[0]);
#pragma GCC diagnostic pop
    if (vsnprintf_s(buf, LOG_MAX_BUF_LEN, LOG_MAX_BUF_LEN - 1, &newFormat[0], args) == -1) {
        LOGLOG("LogManager::PushFormat vsnprintf_s error");
        va_end(args);
        return false;
    }
    va_end(args);

    if (!PushString(level, file, line, std::string(buf))) {
        LOGLOG("LogManager::PushFormat PushString error");
        return false;
    }
    return true;
}

LogManager::LogDataPtr LogManager::PopLog()
{
    if (logs_.empty()) {
        return nullptr;
    }

    pthread_mutex_lock(&mutex_);
    auto log = logs_.front();
    logs_.pop();
    pthread_mutex_unlock(&mutex_);
    return log;
}

void LogManager::UpdateFile(void)
{
    LoadConfig();
    if (f_.IsOpen()) {
        if (f_.FileSize() > limitSize_) {
            f_.Close();
            CreateFile();
        }
    }
}

void LogManager::OnThread(std::promise<bool>& threadPromiseHadRunning, std::promise<bool>& threadPromiseHadEnd)
{
    OHOS::MMI::SetThreadName(std::string("log_mgr"));
    LOGLOG("LogManager::OnThread log thread started!");
    runing_ = true;
    isThreadHadRun_ = true;

    SemPost();
    threadPromiseHadRunning.set_value(true);
    int32_t count = 0;
    LogDataPtr pLog = nullptr;
    while (true) {
        count = 0;
        while ((pLog = PopLog()) != nullptr) {
            if (!f_.IsOpen() && !OpenFileHandle()) {
                LOGLOG("LogManager::run file is not Open and open %s failed", fileName_.c_str());
                PushLog(pLog);
                break;
            }
            if (f_.IsOpen()) {
                WriteFile(pLog);
                count += 1;
            }
        }
        if (count > 0 && f_.IsOpen()) {
            f_.Flush();
        }
        UpdateFile();

        // 延时，单位微秒
        usleep(USLEEP_DELAY);
        // quit
        // 所有的消息处理完，停止
        if (toExit_ && logs_.empty()) {
            runing_ = true;
            break;
        }
    }
    threadPromiseHadEnd.set_value(true);
    LOGLOG("LogManager::OnThread thread end!");
}

bool LogManager::ThreadIsEnd()
{
    if (!isThreadHadRun_) {
        LOGLOG("thread is not run.");
        return false;
    }

    const bool ret = threadFutureHadEnd_.get();
    LOGLOG("thread is end, ret = %d.", ret);
    return true;
}

bool LogManager::ThreadIsHadRunning()
{
    if (!isThreadHadRun_) {
        LOGLOG("thread is not run.");
        return false;
    }

    const bool ret = threadFutureHadRunning_.get();
    LOGLOG("thread is end, ret = %d.", ret);
    return true;
}

size_t LogManager::GetQuesSize() const
{
    return logs_.size();
}

LogData::LogData()
{
    curTime = 0;
    precise = 0;
    threadId_ = OHOS::MMI::GetThisThreadIdOfString();
    threadName_ = OHOS::MMI::GetThreadName();
    curLine = 0;
    level = 0;
}
}
}

bool VerifyLogManagerRun()
{
    printf("in %s:%d, enter", __FILE__, __LINE__);
    using namespace OHOS::MMI;
    if (LogManager::GetInstance().IsRuning()) {
        return true;
    }

    printf("in %s:%d, enter", __FILE__, __LINE__);
    auto log = GetEnv("MI_LOG");
    if (log.empty()) {
        log = DEF_LOG_CONFIG;
    }
    KMSG_LOGI("in VerifyLogManagerRun, log config: %s.", log.c_str());
    // start log
    if (!OHOS::MMI::LogManager::GetInstance().Init(log.c_str())) {
        MMI_LOGE("Failed to get log instance initialization string");
        return false;
    }
    if (!OHOS::MMI::LogManager::GetInstance().Start()) {
        MMI_LOGE("Failed to start log instance");
        return false;
    }
    return true;
}

OHOS::MMI::LogManager& GetLogManager()
{
    return OHOS::MMI::LogManager::GetInstance();
}

#endif // OHOS_BUILD_MMI_DEBUG
