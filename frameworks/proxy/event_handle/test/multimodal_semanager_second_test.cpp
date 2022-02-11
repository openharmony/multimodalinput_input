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

class MultimodalSemanagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int surFaceId_ = 10;
};

class MultimodalEventSecondUnitTest : public MultimodalStandardizedEventManager {
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
        const int32_t windowId = 22;
        struct StandEventCallBack standEventInfo = {};
        standEventInfo.windowId = windowId;
        standEventInfo.eventCallBack = standardizedEventHandle;
        mapEvents_.insert(std::make_pair(typeId, standEventInfo));
        return true;
    }
};

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnNext_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('0');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnNext(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnBack_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('p');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnBack(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::COMMON_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::COMMON_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPrint_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('q');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPrint(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPlay_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('r');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTest;
    multimodalTest.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPlay(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnPause_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('s');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnPause(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::MEDIA_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnMediaControl_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('t');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnMediaControl(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenShot_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('u');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenShot(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnScreenSplit_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('v');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnScreenSplit(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStartScreenRecord_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('w');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStartScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTest;
    MultimodalEvent event;
    int32_t retResult = multimodalTest.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnStopScreenRecord_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('w');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnStopScreenRecord(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnGotoDesktop_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('w');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnGotoDesktop(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnRecent_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('x');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnRecent(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnShowNotification_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('x');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnShowNotification(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_001, TestSize.Level1)
{
    MultimodalEventSecondUnitTest multimodalTestTmp;
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = MmiMessageId::SYSTEM_EVENT_BEGIN;
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_006, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_007, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    MmiMessageId typeNum = static_cast<MmiMessageId>(-1001);
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}

HWTEST_F(MultimodalSemanagerSecondTest, OnLockScreen_008, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto typeNum = static_cast<MmiMessageId>('y');
    auto tmpObj = StandardizedEventHandler::Create<StandardizedEventHandler>();
    tmpObj->SetType(typeNum);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, tmpObj);

    MultimodalEventSecondUnitTest multimodalTestTmp;
    multimodalTestTmp.InsertMapEvent(typeNum, tmpObj);
    MultimodalEvent event;
    int32_t retResult = multimodalTestTmp.OnLockScreen(event);
    EXPECT_TRUE(retResult == RET_OK);
}
} // namespace
