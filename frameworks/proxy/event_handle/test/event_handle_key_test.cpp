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
#include "key_event_handler.h"
#include "mmi_token.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;


static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventHandleKeyTest" };

class EventHandleKeyTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int g_surFaceId = 10;
};

class KeyEventHandlerUnitTest : public KeyEventHandler {
public:
    KeyEventHandlerUnitTest() {}
    ~KeyEventHandlerUnitTest() {}

    virtual bool OnKey(const KeyEvent& event) override
    {
        MMI_LOGI("\nKeyEventHandle::Onkey\n");
        return true;
    }
};

HWTEST_F(EventHandleKeyTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    keyHandleTmp->SetType(EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleKeyTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                 keyHandleTmp);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult);
}

HWTEST_F(EventHandleKeyTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    keyHandleTmp->SetType(EnumAdd(MmiMessageId::KEY_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

// ?1?7?1?7?0?0?1?7?1?7?1?7
HWTEST_F(EventHandleKeyTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

auto g_keyHandle = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
HWTEST_F(EventHandleKeyTest, RegisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_keyHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleKeyTest, RegisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_keyHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleKeyTest, UnregisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_keyHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleKeyTest, UnregisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_keyHandle);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleKeyTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleKeyTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleKeyTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleKeyTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyHandleTmp = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyHandleTmp);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleKeyTest, OnKey_001, TestSize.Level1)
{
    KeyEventHandlerUnitTest keyHandleTmp;
    KeyEvent eventObj;
    bool retResult = keyHandleTmp.OnKey(eventObj);
    EXPECT_TRUE(retResult);
}

HWTEST_F(EventHandleKeyTest, OnKey_002, TestSize.Level1)
{
    KeyEventHandlerUnitTest keyHandleTmp;
    KeyEvent eventObj;
    bool retResult = keyHandleTmp.OnKey(eventObj);
    EXPECT_TRUE(retResult);
}

HWTEST_F(EventHandleKeyTest, construction, TestSize.Level1)
{
    KeyEventHandler keyEventHandler;
}

HWTEST_F(EventHandleKeyTest, OnKey, TestSize.Level1)
{
    KeyEventHandler keyEventHandler;
    KeyEvent eventObj;
    bool retResult = keyEventHandler.OnKey(eventObj);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleKeyTest, key_event_handler_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyEventHandleTest = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleKeyTest, key_event_handler_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyEventHandleTest = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
    int32_t regResultAgaint = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_EXIST, regResultAgaint);
}

HWTEST_F(EventHandleKeyTest, key_event_handler_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyEventHandleTest = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, regResult);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleKeyTest, key_event_handler_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyEventHandleTest = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                 keyEventHandleTest);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleKeyTest, key_event_handler_005, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto keyEventHandleTest = StandardizedEventHandler::Create<KeyEventHandlerUnitTest>();
    int32_t unregResultAgain = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, keyEventHandleTest);
    EXPECT_EQ(MMI_STANDARD_EVENT_NOT_EXIST, unregResultAgain);
}
} // namespace
