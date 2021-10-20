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
#include "define_multimodal.h"
#include "multimodal_standardized_event_manager.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;


class StandardizedEventProcessTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(StandardizedEventProcessTest, OnKey, TestSize.Level1)
{
    KeyEvent event;
    int32_t retResult = EventManager.OnKey(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnTouch, TestSize.Level1)
{
    TouchEvent event;
    int32_t retResult = EventManager.OnTouch(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnShowMenu, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnShowMenu(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnSend, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnSend(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnCopy, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnCopy(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnPaste, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnPaste(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnCut, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnCut(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnUndo, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnUndo(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnRefresh, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnRefresh(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnStartDrag, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnStartDrag(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnCancel, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnCancel(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnEnter, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnEnter(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnPrevious, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnPrevious(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnNext, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnNext(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnBack, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnBack(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnPrint, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnPrint(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnPlay, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnPlay(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnPause, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnPause(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnMediaControl, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnMediaControl(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnScreenShot, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnScreenShot(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnScreenSplit, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnScreenSplit(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnStartScreenRecord, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnStartScreenRecord(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnStopScreenRecord, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnStopScreenRecord(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnGotoDesktop, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnGotoDesktop(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnRecent, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnRecent(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnShowNotification, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnShowNotification(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnLockScreen, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnLockScreen(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnSearch, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnSearch(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnClosePage, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnClosePage(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnLaunchVoiceAssistant, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnLaunchVoiceAssistant(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnMute, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnMute(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnAnswer, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnAnswer(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnRefuse, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnRefuse(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnHangup, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnHangup(event);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(StandardizedEventProcessTest, OnTelephoneControl, TestSize.Level1)
{
    MultimodalEvent event;
    int32_t retResult = EventManager.OnTelephoneControl(event);
    EXPECT_EQ(retResult, RET_OK);
}
} // namespace
