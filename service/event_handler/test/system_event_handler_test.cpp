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
#include "libmmi_util.h"
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

HWTEST_F(SystemEventHandlerTest, Test_AbnormalInvalidMsgId, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::INVALID);
    EXPECT_EQ(rt, PARAM_INPUT_INVALID);
}
HWTEST_F(SystemEventHandlerTest, Test_AbnormalUnknownMsgId, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::BEGIN);
    EXPECT_EQ(rt, UNKNOWN_MSG_ID);
}

HWTEST_F(SystemEventHandlerTest, Test_OnGotoDesktop, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_GOTO_DESKTOP);
    EXPECT_EQ(rt, RET_OK);
}

HWTEST_F(SystemEventHandlerTest, Test_OnScreenShot, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_SCREEN_SHOT);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnScreenSplit, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_SCREEN_SPLIT);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnStopScreenRecord, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_STOP_SCREEN_RECORD);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnStartScreenRecord, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_START_SCREEN_RECORD);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnShowNotification, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_SHOW_NOTIFICATION);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnRecent, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_RECENT);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnLockScreen, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_LOCK_SCREEN);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnSearch, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_SEARCH);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnClosePage, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_CLOSE_PAGE);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnLaunchVoiceAssistant, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_LAUNCH_VOICE_ASSISTANT);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnMute, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_MUTE);
    EXPECT_EQ(rt, RET_OK);
}
HWTEST_F(SystemEventHandlerTest, Test_OnBack, TestSize.Level1)
{
    auto rt = SysEveHdl->OnSystemEventHandler(MmiMessageId::ON_BACK);
    EXPECT_EQ(rt, RET_OK);
}
} // namespace
