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
#include "net_packet.h"
#include "proto.h"
#include "string_ex.h"
#include "util_ex.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class MultimodalSemanagerThirdTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int surFaceId_ = 10;
};

class MultimodalEventFirstUnitTest : public MultimodalStandardizedEventManager {
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
        const int32_t windowId = 11;
        struct StandEventCallBack standEventInfo = {};
        standEventInfo.windowId = windowId;
        standEventInfo.eventCallBack = standardizedEventHandle;
        mapEvents_.insert(std::make_pair(typeId, standEventInfo));
        return true;
    }
};

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnSearch_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('A');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnSearch(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnClosePage_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('A');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnClosePage(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnLaunchVoiceAssistant_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('B');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLaunchVoiceAssistant(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnMute_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('B');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMute(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnAnswer_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('C');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnAnswer(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnRefuse_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('D');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRefuse(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnHangup_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('D');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnHangup(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnTelephoneControl_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('E');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnTelephoneControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::DEVICE_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::DEVICE_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::DEVICE_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::DEVICE_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceAdd_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('F');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceAdd(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTestTmp;
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::DEVICE_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::DEVICE_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::DEVICE_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::DEVICE_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, OnDeviceRemove_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('G');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventFirstUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    DeviceEvent event;
    int32_t retResult = multimodalTestTmp.OnDeviceRemove(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, GetRegisterEvent, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    auto tmp = multimodalTest.GetRegisterEvent();
    EXPECT_TRUE(tmp != nullptr);
}

HWTEST_F(MultimodalSemanagerThirdTest, InjectionVirtual, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    bool isPressed = true;
    int32_t keyCode = 1;
    int32_t keyDownDuration = 1;
    int32_t maxKeyCode = 1;

    int32_t retResult = multimodalTest.InjectionVirtual(isPressed, keyCode, keyDownDuration, maxKeyCode);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, InjectEvent, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    OHOS::KeyEvent keyEvent;
    int32_t retResult = multimodalTest.InjectEvent(keyEvent);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, SendMsg, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    NetPacket netPkt(MmiMessageId::INVALID);

    int32_t retResult = multimodalTest.SendMsgUnitTest(netPkt);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::COMMON_EVENT_BEGIN;
    int32_t windowId = 1;
    std::string rhandle = "111";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_002, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::KEY_EVENT_BEGIN;
    int32_t windowId = 2;
    std::string rhandle = "222";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_003, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::MEDIA_EVENT_BEGIN;
    int32_t windowId = 3;
    std::string rhandle = "333";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_004, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::SYSTEM_EVENT_BEGIN;
    int32_t windowId = 4;
    std::string rhandle = "444";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_005, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::TELEPHONE_EVENT_BEGIN;
    int32_t windowId = 5;
    std::string rhandle = "555";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_006, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::TOUCH_EVENT_BEGIN;
    int32_t windowId = 6;
    std::string rhandle = "666";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_007, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::DEVICE_BEGIN;
    int32_t windowId = 7;
    std::string rhandle = "777";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, MakeRegisterHandle_Default, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    MmiMessageId typeId = MmiMessageId::BEGIN;
    int32_t windowId = 8;
    std::string rhandle = "default";
    bool retResult = multimodalTest.MakeRegisterHandleUnitTest(typeId, windowId, rhandle);
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalSemanagerThirdTest, UnregisterStandardizedEventHandle_001, TestSize.Level1)
{
    MultimodalEventFirstUnitTest multimodalTest;
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t windowId = 1;
    StandEventPtr standardizedEventHandle;

    int32_t retResult = multimodalTest.UnregisterStandardizedEventHandle(iRemote,
                                                                         windowId, standardizedEventHandle);
    EXPECT_TRUE(retResult != 1);
}
} // namespace
