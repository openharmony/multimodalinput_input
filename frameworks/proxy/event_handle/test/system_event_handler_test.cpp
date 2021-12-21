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

class SystemEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(SystemEventHandlerTest, Construction, TestSize.Level1)
{
    SystemEventHandler systemEventHandlerTmp;
}

HWTEST_F(SystemEventHandlerTest, OnClosePage, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnClosePage(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnLaunchVoiceAssistant, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnLaunchVoiceAssistant(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnMute, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnMute(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnScreenShot, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnScreenShot(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnScreenSplit, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnScreenSplit(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnStartScreenRecord, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnStartScreenRecord(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnStopScreenRecord, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnStopScreenRecord(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnGotoDesktop, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnGotoDesktop(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnRecent, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnRecent(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnShowNotification, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnShowNotification(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnLockScreen, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnLockScreen(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SystemEventHandlerTest, OnSearch, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    SystemEventHandler systemEventHandler;
    bool retResult = systemEventHandler.OnSearch(multiModalEvent);
    EXPECT_FALSE(retResult);
}
} // namespace
