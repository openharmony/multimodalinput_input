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

#include <locale>
#include <codecvt>
#include <gtest/gtest.h>
#include "string_ex.h"
#include "proto.h"
#include "util_ex.h"
#include "log.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"
#include "common_event_handler.h"
#include "mmi_token.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventHandleCommonTest" };

class EventHandleCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int g_surFaceId = 10;
};

class CommonEventHandleUnitTest : public CommonEventHandler {
public:
    CommonEventHandleUnitTest() {}
    ~CommonEventHandleUnitTest() {}

    virtual bool OnShowMenu(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnShowMenu\n");
        return true;
    }

    virtual bool OnSend(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnSend\n");
        return true;
    }

    virtual bool OnCopy(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnCopy\n");
        return true;
    }

    virtual bool OnPaste(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnPaste\n");
        return true;
    }

    virtual bool OnCut(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnCut\n");
        return true;
    }

    virtual bool OnUndo(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnUndo\n");
        return true;
    }

    virtual bool OnRefresh(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnRefresh\n");
        return true;
    }

    virtual bool OnStartDrag(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnStartDrag\n");
        return true;
    }

    virtual bool OnCancel(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnCancel\n");
        return true;
    }

    virtual bool OnEnter(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnEnter\n");
        return true;
    }

    virtual bool OnPrevious(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnPrevious\n");
        return true;
    }

    virtual bool OnNext(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnNext\n");
        return true;
    }

    virtual bool OnBack(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnBack\n");
        return true;
    }

    virtual bool OnPrint(const MultimodalEvent& multiModalEvent)
    {
        MMI_LOGI("\nCommonEventHandle::OnPrint\n");
        return true;
    }
};

HWTEST_F(EventHandleCommonTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    commonHandleTmp->SetType(EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleCommonTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    commonHandleTmp->SetType(MmiMessageId::MEDIA_EVENT_BEGIN);
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
            commonHandleTmp);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult);
}

HWTEST_F(EventHandleCommonTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    commonHandleTmp->SetType(EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

// ?1?7?1?7?0?0?1?7?1?7?1?7
HWTEST_F(EventHandleCommonTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

auto g_commonHandle = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
HWTEST_F(EventHandleCommonTest, RegisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_commonHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleCommonTest, RegisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_commonHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleCommonTest, UnregisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_commonHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleCommonTest, UnregisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_commonHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleCommonTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleCommonTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleCommonTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleCommonTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto commonHandleTmp = StandardizedEventHandler::Create<CommonEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, commonHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}
} // namespace
