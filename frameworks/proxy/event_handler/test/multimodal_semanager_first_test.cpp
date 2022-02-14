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

#include <codecvt>
#include <locale>
#include <gtest/gtest.h>
#include "define_multimodal.h"
#include "mmi_token.h"
#include "multimodal_event_handler.h"
#include "multimodal_standardized_event_manager.h"
#include "proto.h"
#include "string_ex.h"
#include "util_ex.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class MultimodalSemanagerFirstTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int surFaceId_ = 10;
};

class MultimodalEventThirdUnitTest : public MultimodalStandardizedEventManager {
public:
    bool MakeRegisterHandleUnitTest(MmiMessageId typeId, int32_t windowId, std::string& rhandle)
    {
        return MakeRegisterHandle(typeId, windowId, rhandle);
    }
    bool SendMsgUnitTest(NetPacket& pkt)
    {
        return SendMsg(pkt);
    }
    bool InsertMapEvent(MmiMessageId typeId, StandEventPtr standardizedEventHandle)
    {
        StandEventCallBack standEventInfo  = {};
        standEventInfo .windowId = 0;
        standEventInfo .eventCallBack = standardizedEventHandle;
        mapEvents_.insert(std::make_pair(typeId, standEventInfo ));
        return true;
    }
};

HWTEST_F(MultimodalSemanagerFirstTest, construction, TestSize.Level1)
{
    MultimodalStandardizedEventManager multimodalTestTmp;
}

HWTEST_F(MultimodalSemanagerFirstTest, SetClientHandle, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    auto clientPtr = std::shared_ptr<IfMMIClient>();
    multimodalTest.SetClientHandle(clientPtr);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t windowId = 1;
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTest.RegisterStandardizedEventHandle(iRemote,
                                                                       windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_002, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTestTmp;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto windowId = static_cast<int32_t>('b');
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTestTmp.RegisterStandardizedEventHandle(iRemote,
                                                                          windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_003, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTestTmp;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto windowId = static_cast<int32_t>('c');
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTestTmp.RegisterStandardizedEventHandle(iRemote,
                                                                          windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_004, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTestTmp;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto windowId = static_cast<int32_t>('c') + static_cast<int32_t>('u');
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTestTmp.RegisterStandardizedEventHandle(iRemote,
                                                                          windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_005, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTestTmp;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t windowId = -65535;
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTestTmp.RegisterStandardizedEventHandle(iRemote,
                                                                          windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, RegisterStandardizedEventHandle_006, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTestTmp;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t windowId = 2147483647;
    StandEventPtr standardizedEventHandle;
    int32_t retResult = multimodalTestTmp.RegisterStandardizedEventHandle(iRemote,
                                                                          windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTest.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::KEY_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::KEY_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(MmiMessageId::KEY_EVENT_BEGIN, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1), tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(MmiMessageId::KEY_EVENT_BEGIN, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnKey_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('a');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(MmiMessageId::KEY_EVENT_BEGIN, tmpObj);
    OHOS::KeyEvent event;
    int32_t retResult = multimodalTestTmp.OnKey(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    TouchEvent event;
    int32_t retResult = multimodalTest.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TOUCH_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TOUCH_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TOUCH_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TOUCH_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnTouch_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('b');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    TouchEvent event;
    int32_t retResult = multimodalTestTmp.OnTouch(event);
    EXPECT_TRUE(retResult == RET_OK);
}
HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnShowMenu_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('c');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowMenu(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnSend_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('d');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSend(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCopy_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('e');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCopy(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPaste_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('f');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPaste(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCut_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('g');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCut(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnUndo_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('h');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnUndo(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnRefresh_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('j');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefresh(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1000);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1000);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnStartDrag_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('l');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartDrag(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1000);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnCancel_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('k');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnCancel(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnEnter_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('m');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnEnter(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_001, TestSize.Level1)
{
    MultimodalEventThirdUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerFirstTest, OnPrevious_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('n');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventThirdUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPrevious(event);
    EXPECT_TRUE(retResult == RET_OK);
}
} // namespace
