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

#include "system_event_handler.h"
#include <codecvt>
#include <locale>
#include <gtest/gtest.h>
#include "error_multimodal.h"
#include "log.h"
#include "mmi_token.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "string_ex.h"
#include "util_ex.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;


class EventHandleSystemTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int g_surFaceId = 10;
};

class SystemEventHandleUnitTest : public SystemEventHandler {
public:
    SystemEventHandleUnitTest() {}
    ~SystemEventHandleUnitTest() {}

    virtual bool OnClosePageUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnClosePage(multiModalEvent);
    }

    virtual bool OnLaunchVoiceAssistantUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnLaunchVoiceAssistant(multiModalEvent);
    }

    virtual bool OnMuteUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnMute(multiModalEvent);
    }

    virtual bool OnScreenShotUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnScreenShot(multiModalEvent);
    }

    virtual bool OnScreenSplitUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnScreenSplit(multiModalEvent);
    }

    virtual bool OnStartScreenRecordUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnStartScreenRecord(multiModalEvent);
    }

    virtual bool OnStopScreenRecordUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnStopScreenRecord(multiModalEvent);
    }

    virtual bool OnGotoDesktopUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnGotoDesktop(multiModalEvent);
    }

    virtual bool OnRecentUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnRecent(multiModalEvent);
    }

    virtual bool OnShowNotificationUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnShowNotification(multiModalEvent);
    }

    virtual bool OnLockScreenUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnLockScreen(multiModalEvent);
    }

    virtual bool OnSearchUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnSearch(multiModalEvent);
    }
};

HWTEST_F(EventHandleSystemTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();
    systemHandleTmp->SetType(EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleSystemTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();

    MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult);
}

HWTEST_F(EventHandleSystemTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();
    systemHandleTmp->SetType(EnumAdd(MmiMessageId::SYSTEM_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

// ?1?7?1?7?0?0?1?7?1?7?1?7
HWTEST_F(EventHandleSystemTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

auto g_systemHandle = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();
HWTEST_F(EventHandleSystemTest, RegisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_systemHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleSystemTest, RegisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_systemHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleSystemTest, UnregisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_systemHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleSystemTest, UnregisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_systemHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleSystemTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleSystemTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleSystemTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleSystemTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto systemHandleTmp = StandardizedEventHandler::Create<SystemEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, systemHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}
} // namespace
