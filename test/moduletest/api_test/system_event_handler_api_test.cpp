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

#include <gtest/gtest.h>
#include "system_event_handler.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class SystemEventHandlerApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnScreenShot, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnScreenShot = systemEventHandlerTest.OnScreenShot(event);
    EXPECT_EQ(retOnScreenShot, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnScreenSplit, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnScreenSplit = systemEventHandlerTest.OnScreenSplit(event);
    EXPECT_EQ(retOnScreenSplit, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnStartScreenRecord, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnStartScreenRecord = systemEventHandlerTest.OnStartScreenRecord(event);
    EXPECT_EQ(retOnStartScreenRecord, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnStopScreenRecord, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnStopScreenRecord = systemEventHandlerTest.OnStopScreenRecord(event);
    EXPECT_EQ(retOnStopScreenRecord, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnGotoDesktop, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnGotoDesktop = systemEventHandlerTest.OnGotoDesktop(event);
    EXPECT_EQ(retOnGotoDesktop, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnRecent, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnRecent = systemEventHandlerTest.OnRecent(event);
    EXPECT_EQ(retOnRecent, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnShowNotification, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnShowNotification = systemEventHandlerTest.OnShowNotification(event);
    EXPECT_EQ(retOnShowNotification, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnLockScreen, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnLockScreen = systemEventHandlerTest.OnLockScreen(event);
    EXPECT_EQ(retOnLockScreen, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnSearch, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnSearch = systemEventHandlerTest.OnSearch(event);
    EXPECT_EQ(retOnSearch, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnClosePage, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnClosePage = systemEventHandlerTest.OnClosePage(event);
    EXPECT_EQ(retOnClosePage, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnLaunchVoiceAssistant, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnLaunchVoiceAssistant = systemEventHandlerTest.OnLaunchVoiceAssistant(event);
    EXPECT_EQ(retOnLaunchVoiceAssistant, false);
}

HWTEST_F(SystemEventHandlerApiTest, Api_Test_OnMute, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTest;
    const MultimodalEvent event;
    auto retOnMute = systemEventHandlerTest.OnMute(event);
    EXPECT_EQ(retOnMute, false);
}
} // namespace
