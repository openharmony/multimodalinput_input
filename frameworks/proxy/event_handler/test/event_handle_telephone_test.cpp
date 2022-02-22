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

#include <codecvt>
#include <locale>
#include <gtest/gtest.h>
#include "error_multimodal.h"
#include "mmi_log.h"
#include "mmi_token.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "string_ex.h"
#include "telephone_event_handler.h"
#include "util_ex.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class EventHandleTelephoneTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const uint32_t surFaceId_ = 10;
};

class TelephoneEventHandleUnitTest : public TelephoneEventHandler {
public:
    TelephoneEventHandleUnitTest() {}
    ~TelephoneEventHandleUnitTest() {}

    virtual bool OnAnswerUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnAnswer(multiModalEvent);
    }

    virtual bool OnRefuseUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnRefuse(multiModalEvent);
    }

    virtual bool OnHangupUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnHangup(multiModalEvent);
    }

    virtual bool OnTelephoneControlUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnTelephoneControl(multiModalEvent);
    }
};

HWTEST_F(EventHandleTelephoneTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    telephoneHandleTmp->SetType(EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleTelephoneTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();

    MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    int32_t regResultII = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResultII);
}

HWTEST_F(EventHandleTelephoneTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    telephoneHandleTmp->SetType(EnumAdd(MmiMessageId::TELEPHONE_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleTelephoneTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

auto g_telephoneHandle = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
HWTEST_F(EventHandleTelephoneTest, RegisterStandardizedEventHandle_sec001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, g_telephoneHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleTelephoneTest, RegisterStandardizedEventHandle_sec002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, g_telephoneHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleTelephoneTest, UnregisterStandardizedEventHandle_sec001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, g_telephoneHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleTelephoneTest, UnregisterStandardizedEventHandle_sec002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, g_telephoneHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleTelephoneTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleTelephoneTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleTelephoneTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_,
        telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleTelephoneTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto telephoneHandleTmp = StandardizedEventHandler::Create<TelephoneEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, telephoneHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleTelephoneTest, OnAnswer, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandler;
    MultimodalEvent multiModalEvent;

    bool retResult = telephoneEventHandler.OnAnswer(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleTelephoneTest, OnRefuse, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandler;
    MultimodalEvent multiModalEvent;

    bool retResult = telephoneEventHandler.OnRefuse(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleTelephoneTest, OnHangup, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandler;
    MultimodalEvent multiModalEvent;

    bool retResult = telephoneEventHandler.OnHangup(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleTelephoneTest, OnTelephoneControl, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandler;
    MultimodalEvent multiModalEvent;

    bool retResult = telephoneEventHandler.OnTelephoneControl(multiModalEvent);
    EXPECT_FALSE(retResult);
}
} // namespace
