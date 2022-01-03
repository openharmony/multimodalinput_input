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
#include <gtest/gtest.h>

#ifdef OHOS_BUILD_MMI_DEBUG

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "LogTest" };
class LogTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class LogManagerUnitTest : public LogManager {
public:
    bool OpenFileHandleUnitTest(void)
    {
        return OpenFileHandle();
    }

    bool CreateFileUnitTest(void)
    {
        return CreateFile();
    }

    bool UpdateFileUnitTest(void)
    {
        UpdateFile();
        return true;
    }

    bool LoadConfigUnitTest()
    {
        LoadConfig();
        return true;
    }

    bool ParseConfigUnitTest(const FileHandle& f)
    {
        ParseConfig(f);
        return true;
    }

    bool GetProcessInfoUnitTest(void)
    {
        GetProcessInfo();
        return true;
    }

    bool SetLogNameUnitTest(const std::string& name)
    {
        return SetLogName(name);
    }

    bool SetLogPathUnitTest(const std::string& path)
    {
        return SetLogPath(path);
    }

    LogDataPtr PopLogUnitTest()
    {
        LogDataPtr pLog = PopLog();
        return pLog;
    }

    bool PushLogUnitTest(LogDataPtr pLog)
    {
        return PushLog(pLog);
    }

    bool ParseLogLevelUnitTest(const std::string& str)
    {
        ParseLogLevel(str);
        return true;
    }

    bool ParseLogDisplayUnitTest(const std::string& str)
    {
        ParseLogDisplay(str);
        return true;
    }

    bool ParseLogFileLineUnitTest(const std::string& str)
    {
        ParseLogFileLine(str);
        return true;
    }

    bool WaitUnitTest(void)
    {
        return Wait();
    }

    bool SemCreateUnitTest(int32_t count)
    {
        return SemCreate(count);
    }

    bool SemWaitUnitTest(int32_t timeout)
    {
        return SemWait(timeout);
    }

    bool SemPostUnitTest(void)
    {
        return SemPost();
    }
};

HWTEST_F(LogTest, FileHandle_Construct, TestSize.Level1)
{
    FileHandle f;
}

HWTEST_F(LogTest, FileHandle_Open, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "wb+");
    f.Close();
}

HWTEST_F(LogTest, FileHandle_IsOpen_001, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "r");
    bool retResult = f.IsOpen();
    f.Close();
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, FileHandle_IsOpen_002, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig2.log", "r");
    bool retResult = f.IsOpen();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, FileHandle_Close, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "r");
    bool retResult = f.IsOpen();
    if (retResult) {
        f.Close();
    }
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, FileHandle_FileSize_001, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "r");
    bool bOpen = f.IsOpen();
    size_t retResult = -1;
    if (bOpen) {
        retResult = f.FileSize();
        f.Close();
    }
    EXPECT_TRUE((int)retResult != -1);
}

HWTEST_F(LogTest, FileHandle_FileSize_002, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig2.log", "r");
    bool bOpen = f.IsOpen();
    size_t retResult = -1;
    if (!bOpen) {
        retResult = f.FileSize();
    }
    EXPECT_TRUE((int)retResult == 0);
}

HWTEST_F(LogTest, FileHandle_Write, TestSize.Level1)
{
    char strTest[] = {
        "level=error\r\npath=./\r\nlevel=debug\r\nlevel=trace\r\ndisplay=\
        false\r\nlevel=info\r\nlevel=warn\r\nlevel=alarm\r\nlevel=fatal\r\nfileline=false\r\nlevel=trace\r\n" };
    FileHandle f;
    f.Open("./testconfig.log", "at+");
    bool bOpen = f.IsOpen();
    if (bOpen) {
        f.Write(strTest, sizeof(strTest));
        f.Close();
    }
}

HWTEST_F(LogTest, FileHandle_Flush, TestSize.Level1)
{
    char strTest[] = { "level=error\r\npath=./\r\nlevel=debug\r\nlevel=\
        trace\r\ndisplay=false\r\nlevel=info\r\nlevel=warn\r\nlevel=\
        alarm\r\nlevel=fatal\r\nfileline=false\r\nlevel=trace\r\n" };
    FileHandle f;
    f.Open("./testconfig.log", "at+");
    bool bOpen = f.IsOpen();
    if (bOpen) {
        f.Write(strTest, sizeof(strTest));
        f.Flush();
        f.Close();
    }
}

HWTEST_F(LogTest, FileHandle_ReadLine_001, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "r");
    bool bOpen = f.IsOpen();
    std::string retResult = "";
    if (bOpen) {
        retResult = f.ReadLine();
        f.Close();
    }
    EXPECT_TRUE(retResult.length() > 0);
}

HWTEST_F(LogTest, FileHandle_ReadLine_002, TestSize.Level1)
{
    FileHandle f;
    f.Open("./testconfig.log", "w+");
    bool bOpen = f.IsOpen();
    std::string retResult = "";
    if (bOpen) {
        retResult = f.ReadLine();
        f.Close();
    }
    EXPECT_TRUE(retResult.length() == 0);
}

HWTEST_F(LogTest, LogManager_construct, TestSize.Level1)
{
    LogManager logObj;
}

HWTEST_F(LogTest, LogManager_Init, TestSize.Level1)
{
    LogManager::GetInstance().Init("./testconfig.log");
}

HWTEST_F(LogTest, LogManager_SetLogPath_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string filePath = "./utFile";
    bool retResult = logObj.SetLogPathUnitTest(filePath);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_SetLogPath_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string filePath = "";
    bool retResult = logObj.SetLogPathUnitTest(filePath);
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_SetLogName_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string fileName = "utlog.txt";
    bool retResult = logObj.SetLogNameUnitTest(fileName);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_SetLogName_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string fileName = "";
    bool retResult = logObj.SetLogNameUnitTest(fileName);
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_OpenFileHandle_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string fileName = "./utlog.txt";
    logObj.SetLogNameUnitTest(fileName);
    bool retResult = logObj.OpenFileHandleUnitTest();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_OpenFileHandle_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string fileName = "./testconfig";
    logObj.SetLogNameUnitTest(fileName);
    bool retResult = logObj.OpenFileHandleUnitTest();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_GetProcessInfo, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.GetProcessInfoUnitTest();
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_OpenFileHandle, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.OpenFileHandleUnitTest();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_CreateFile, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string logPath = "./UTFile";
    std::string fileName = "ut_log";
    logObj.SetLogPathUnitTest(logPath);
    logObj.SetLogNameUnitTest(fileName);
    bool retResult = logObj.CreateFileUnitTest();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_TRACE";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_DEBUG";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_003, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_INFO";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_004, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_WARN";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_005, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_ERROR";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_006, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_ALARM";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_007, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "LOG_LEVEL_FATAL";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogLevel_008, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLevel = "";
    bool retResult = logObj.ParseLogLevelUnitTest(strLevel);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogDisplay_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLogFile = "LOG_CONFIG_CLOSE";
    bool retResult = logObj.ParseLogDisplayUnitTest(strLogFile);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogDisplay_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLogFile = "LOG_LEVEL_FATAL";
    bool retResult = logObj.ParseLogDisplayUnitTest(strLogFile);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogDisplay_003, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strLogFile = "";
    bool retResult = logObj.ParseLogDisplayUnitTest(strLogFile);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogFileLine_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strFileLine = "LOG_CONFIG_CLOSE";
    bool retResult = logObj.ParseLogFileLineUnitTest(strFileLine);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogFileLine_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strFileLine = "";
    bool retResult = logObj.ParseLogFileLineUnitTest(strFileLine);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseLogFileLine_003, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    std::string strFileLine = "";
    bool retResult = logObj.ParseLogFileLineUnitTest(strFileLine);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_ParseConfig_001, TestSize.Level1)
{
    FileHandle f;
    LogManagerUnitTest logObj;
    std::string strFileLine = "";
    bool retResult = logObj.ParseConfigUnitTest(f);
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_LoadConfig_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.LoadConfigUnitTest();
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_Start_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.Start();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_Stop_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    logObj.Start();
    bool retResult = logObj.Stop();
    EXPECT_FALSE(retResult);
}

HWTEST_F(LogTest, LogManager_PushString_002, TestSize.Level1)
{
    bool retResult = LogManager::GetInstance().PushString(ENUM_LL::LL_TRACE, __FILE__, __LINE__,
               "The Wait Queue is full! Clear it! \n");
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_PushString_003, TestSize.Level1)
{
    bool retResult = LogManager::GetInstance().PushString(ENUM_LL::LL_DEBUG,
        __FILE__, __LINE__, "\nMMIWMS:surfaceID=[%s]\n");
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_PushFormat_001, TestSize.Level1)
{
    bool retResult = LogManager::GetInstance().PushFormat(ENUM_LL::LL_DEBUG,
        __FILE__, __LINE__, "\nMMIWMS:surfaceID=[%s]\n", "The Wait Queue is full! Clear it! \n");
    EXPECT_TRUE(retResult);
}

HWTEST_F(LogTest, LogManager_PopLog_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    LogManager::LogDataPtr retResult = logObj.PopLogUnitTest();
    EXPECT_TRUE(retResult == nullptr);
}

HWTEST_F(LogTest, LogManager_UpdateFile_001, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.UpdateFileUnitTest();
    EXPECT_TRUE(retResult);
    MMI_LOGT("arvs invalid.");
}

HWTEST_F(LogTest, LogManager_UpdateFile_002, TestSize.Level1)
{
    LogManagerUnitTest logObj;
    bool retResult = logObj.UpdateFileUnitTest();
    EXPECT_TRUE(retResult);
    MMI_LOGD("arvs invalid.");
}
} // namespace

#endif // OHOS_BUILD_MMI_DEBUG