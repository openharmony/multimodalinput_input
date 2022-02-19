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

#include "app_register.h"
#include <gtest/gtest.h>
#include "key_event_value_transformation.h"
#include "proto.h"
#include "register_eventhandle_manager.h"
#include "util.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

const int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;

class AppRegisterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer, TestSize.Level1)
{
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""},
        {1006, 103, 18, "", ""},
        {1007, 104, 19, "", ""},
        {1005, 105, 20, "", ""}
    };
    AppInfo testVal;
    AppRegister appReg;
    for (int32_t i = 0; i < 5; i++) {
        appReg.RegisterAppInfoforServer(a[i]);
    }
    appReg.PrintfMap();

    testVal = appReg.FindByWinId(101);
    EXPECT_TRUE(testVal.fd != -1);

    testVal = appReg.FindBySocketFd(20);
    EXPECT_TRUE(testVal.windowId == 105);
    testVal = appReg.FindByWinId(201);
    EXPECT_TRUE(testVal.fd == -1);

    appReg.PrintfMap();

    appReg.RegisterConnectState(16);
    appReg.UnregisterConnectState(16);
    appReg.PrintfMap();
}

HWTEST_F(AppRegisterTest, QueryMapSurfaceNum, TestSize.Level1)
{
    AppRegister appReg;
    int32_t retResult = appReg.QueryMapSurfaceNum();
    EXPECT_TRUE(retResult != -1);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_001, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 3, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_002, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 1, time);
    EXPECT_TRUE(retResult == true);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_003, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 2, time);
    EXPECT_TRUE(retResult == true);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_004, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_TOUCH, 2, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_005, TestSize.Level1)
{
    const int32_t WAIT_QUEUE_EVENTS_MAX = 128;
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_COPY, WAIT_QUEUE_EVENTS_MAX + 1, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_006, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, -1, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_007, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    time += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 2, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_008, TestSize.Level1)
{
    ssize_t time2 = GetMicrotime();
    time2 += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 2, time2);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_009, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    time += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 1, time);
    EXPECT_TRUE(retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_010, TestSize.Level1)
{
    ssize_t time2 = GetMicrotime();
    time2 += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 1, time2);
    EXPECT_TRUE(retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_011, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    time += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 1, time);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_012, TestSize.Level1)
{
    ssize_t time2 = GetMicrotime();
    time2 += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 1, time2);
    EXPECT_TRUE(!retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_013, TestSize.Level1)
{
    ssize_t time = GetMicrotime();
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 3, time);
    EXPECT_TRUE(retResult);
}

HWTEST_F(AppRegisterTest, IsMultimodeInputReady_014, TestSize.Level1)
{
    ssize_t time2 = GetMicrotime();
    time2 += INPUT_UI_TIMEOUT_TIME;
    UDSServer udsServer;

    AppRegister appReg;
    appReg.Init(udsServer);

    bool retResult = appReg.IsMultimodeInputReady(MmiMessageId::ON_KEY, 3, time2);
    EXPECT_TRUE(retResult);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_001, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_002, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::KEY_EVENT_BEGIN, 2);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_003, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::MEDIA_EVENT_BEGIN, 3);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_004, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::SYSTEM_EVENT_BEGIN, 4);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_005, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::SYSTEM_EVENT_BEGIN, 99);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_006, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::TELEPHONE_EVENT_BEGIN, 5);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_007, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::TOUCH_EVENT_BEGIN, 6);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_008, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    int32_t retResult = registerEventManager.RegisterEvent(MmiMessageId::ON_STANDARD, 9);
    EXPECT_TRUE(retResult != 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_009, TestSize.Level1)
{
    int32_t testInt = -1;
    RegisterEventHandleManager registerEventManager;
    testInt = registerEventManager.RegisterEvent(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    EXPECT_TRUE(testInt == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_010, TestSize.Level1)
{
    int32_t testInt = -1;
    RegisterEventHandleManager registerEventManager;
    testInt = registerEventManager.RegisterEvent(MmiMessageId::KEY_EVENT_BEGIN, 2);
    EXPECT_TRUE(testInt == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_011, TestSize.Level1)
{
    int32_t testInt = -1;
    RegisterEventHandleManager registerEventManager;
    testInt = registerEventManager.RegisterEvent(MmiMessageId::MEDIA_EVENT_BEGIN, 3);
    EXPECT_TRUE(testInt == 0);
}

HWTEST_F(AppRegisterTest, RegisterEventHandleManager_012, TestSize.Level1)
{
    int32_t testInt = -1;
    RegisterEventHandleManager registerEventManager;
    testInt = registerEventManager.RegisterEvent(MmiMessageId::SYSTEM_EVENT_BEGIN, 4);
    EXPECT_TRUE(testInt == 0);
}

HWTEST_F(AppRegisterTest, FindSocketFds_001, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_ENTER, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_002, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_PAUSE, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_003, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_START_SCREEN_RECORD, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_004, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_STANDARD, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_005, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_ENTER, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_006, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_PAUSE, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_007, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_START_SCREEN_RECORD, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, FindSocketFds_008, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;
    std::vector<int32_t> fds;
    registerEventManager.FindSocketFds(MmiMessageId::ON_CLOSE_PAGE, fds);
    EXPECT_TRUE(fds.empty());
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_001, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::SYSTEM_EVENT_BEGIN, 4);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_002, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::KEY_EVENT_BEGIN, 2);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_003, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::MEDIA_EVENT_BEGIN, 3);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_004, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::TELEPHONE_EVENT_BEGIN, 5);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_005, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::TOUCH_EVENT_BEGIN, 5);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_006, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::TOUCH_EVENT_BEGIN, 6);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_007, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(AppRegisterTest, UnregisterEventHandleManager_008, TestSize.Level1)
{
    RegisterEventHandleManager registerEventManager;

    registerEventManager.PrintfMap();
    std::vector<int32_t> fds;
    int32_t retResult = registerEventManager.UnregisterEvent(MmiMessageId::ON_STANDARD, -1);
    EXPECT_TRUE(retResult != 0);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_001, TestSize.Level1)
{
    AppRegister appRegister;
    const AppInfo a = { 1004, 101, 16, "", ""};
    appRegister.RegisterAppInfoforServer(a);
    int32_t fd = 4;
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_002, TestSize.Level1)
{
    AppRegister appRegister;
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""}
    };
    for (int32_t i = 0; i < 2; i++) {
        appRegister.RegisterAppInfoforServer(a[i]);
    }
    int32_t fd = 8;
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_003, TestSize.Level1)
{
    AppRegister appRegister;
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""},
        {1006, 103, 18, "", ""}
    };
    for (int32_t i = 0; i < 3; i++) {
        appRegister.RegisterAppInfoforServer(a[i]);
    }
    int32_t fd = 12;
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_004, TestSize.Level1)
{
    AppRegister appRegister;
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""},
        {1006, 103, 18, "", ""},
        {1007, 104, 19, "", ""}
    };
    for (int32_t i = 0; i < 4; i++) {
        appRegister.RegisterAppInfoforServer(a[i]);
    }
    int32_t fd = 16;
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_005, TestSize.Level1)
{
    AppRegister appRegister;
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""},
        {1006, 103, 18, "", ""},
        {1007, 104, 19, "", ""},
        {1005, 105, 20, "", ""}
    };
    for (int32_t i = 0; i < 5; i++) {
        appRegister.RegisterAppInfoforServer(a[i]);
    }
    int32_t fd = 20;
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, RegisterAppInfoforServer_006, TestSize.Level1)
{
    AppRegister appRegister;
    int32_t fd = 16;
    const AppInfo a[] = {
        {1004, 101, 16, "", ""},
        {1005, 102, 17, "", ""},
        {1006, 103, 18, "", ""},
        {1007, 104, 19, "", ""},
        {1005, 105, 20, "", ""}
    };
    for (int32_t i = 0; i < 5; i++) {
        appRegister.RegisterAppInfoforServer(a[i]);
    }
    appRegister.UnregisterAppInfoBySocketFd(fd);
}

HWTEST_F(AppRegisterTest, FindSurfaceIdBySocketFd_001, TestSize.Level1)
{
    AppRegister appReg;
    appReg.FindBySocketFd(0);
}

HWTEST_F(AppRegisterTest, FindSurfaceIdBySocketFd_002, TestSize.Level1)
{
    AppRegister appReg;
    appReg.FindBySocketFd(-100);
}

HWTEST_F(AppRegisterTest, FindSurfaceIdBySocketFd_003, TestSize.Level1)
{
    AppRegister appReg;
    appReg.FindBySocketFd(100);
}

HWTEST_F(AppRegisterTest, KeyEventValueTransformation_001, TestSize.Level1)
{
    KeyEventValueTransformations valTest = {};
    const int32_t keyValueOfInput = 30;

    valTest = KeyValueTransformationByInput(keyValueOfInput);
    EXPECT_TRUE(valTest.keyValueOfHos == 2017);
}

HWTEST_F(AppRegisterTest, KeyEventValueTransformation_002, TestSize.Level1)
{
    KeyEventValueTransformations valTest = {};
    const int32_t keyValueOfInput = -1;

    valTest = KeyValueTransformationByInput(keyValueOfInput);
    EXPECT_TRUE(valTest.keyValueOfHos >= 10000);
}

HWTEST_F(AppRegisterTest, Init_001, TestSize.Level1)
{
    AppRegister appRegister;
    OHOS::MMI::UDSServer udsServer;
    appRegister.Init(udsServer);
}

HWTEST_F(AppRegisterTest, DeleteEventFromWaitQueue_001, TestSize.Level1)
{
    AppRegister appRegister;
    OHOS::MMI::UDSServer udsServer;
    appRegister.DeleteEventFromWaitQueue(0, 1);
}
} // namespace
