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

#include "standardized_event_handler.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class StandardizedEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(StandardizedEventHandlerTest, Construction, TestSize.Level1)
{
    StandardizedEventHandler standardHandlerTmp;
}

HWTEST_F(StandardizedEventHandlerTest, OnKey, TestSize.Level1)
{
    OHOS::KeyEvent event;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnKey(event);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnShowMenu, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnShowMenu(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnSend, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnSend(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnCopy, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnCopy(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnPaste, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnPaste(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnCut, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnCut(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnUndo, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnUndo(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnRefresh, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnRefresh(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnStartDrag, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnStartDrag(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnCancel, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnCancel(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnEnter, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnEnter(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnPrevious, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnPrevious(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnNext, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnNext(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnBack, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnBack(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnPrint, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnPrint(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnPlay, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnPlay(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnPause, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnPause(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnMediaControl, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnMediaControl(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnScreenShot, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnScreenShot(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnScreenSplit, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnScreenSplit(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnStartScreenRecord, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnStartScreenRecord(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnStopScreenRecord, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnStopScreenRecord(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnGotoDesktop, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnGotoDesktop(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnRecent, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnRecent(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnShowNotification, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnShowNotification(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnLockScreen, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnLockScreen(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnSearch, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnSearch(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnClosePage, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnClosePage(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnLaunchVoiceAssistant, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnLaunchVoiceAssistant(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnMute, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnMute(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnAnswer, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnAnswer(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnRefuse, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnRefuse(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnHangup, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnHangup(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnTelephoneControl, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnTelephoneControl(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnDeviceAdd, TestSize.Level1)
{
    DeviceEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnDeviceAdd(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnDeviceRemove, TestSize.Level1)
{
    DeviceEvent multiModalEvent;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnDeviceRemove(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, OnTouch, TestSize.Level1)
{
    TouchEvent event;
    StandardizedEventHandler standardHandler;
    bool retResult = standardHandler.OnTouch(event);
    EXPECT_FALSE(retResult);
}

HWTEST_F(StandardizedEventHandlerTest, SetType, TestSize.Level1)
{
    MmiMessageId typeNum = MmiMessageId::INVALID;
    StandardizedEventHandler standardHandler;
    standardHandler.SetType(typeNum);
}

HWTEST_F(StandardizedEventHandlerTest, GetType_001, TestSize.Level1)
{
    MmiMessageId typeNum = MmiMessageId::INVALID;
    StandardizedEventHandler standardHandler;
    MmiMessageId retResult = standardHandler.GetType();
    EXPECT_EQ(retResult, typeNum);
}

HWTEST_F(StandardizedEventHandlerTest, GetType_002, TestSize.Level1)
{
    MmiMessageId typeNum = MmiMessageId::LIBINPUT_EVENT_DEVICE_ADDED;
    StandardizedEventHandler standardHandler;
    standardHandler.SetType(typeNum);
    MmiMessageId retResult = standardHandler.GetType();
    EXPECT_EQ(retResult, typeNum);
}

HWTEST_F(StandardizedEventHandlerTest, GetType_003, TestSize.Level1)
{
    MmiMessageId typeNum = static_cast<MmiMessageId>(4);
    StandardizedEventHandler standardHandler;
    standardHandler.SetType(static_cast<MmiMessageId>(4));
    MmiMessageId retResult = standardHandler.GetType();
    EXPECT_NE(retResult, typeNum);
}
} // namespace
