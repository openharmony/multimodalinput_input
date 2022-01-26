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

#include "touch_event_handler.h"
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

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MMI;

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventHandleTouchTest" };
    }
}

namespace {
class EventHandleTouchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int g_surFaceId = 10;
};

class TouchEventHandleUnitTest : public TouchEventHandler {
public:
    TouchEventHandleUnitTest() {}
    ~TouchEventHandleUnitTest() {}

    virtual bool OnTouch(const TouchEvent& event)
    {
        MMI_LOGI("TouchEventHandle::OnTouch");
        return true;
    }
protected:
    const unsigned int g_surFaceId = 10;
};

HWTEST_F(EventHandleTouchTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();
    touchHandleTmp->SetType(EnumAdd(MmiMessageId::TOUCH_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleTouchTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();

    MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

HWTEST_F(EventHandleTouchTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();
    touchHandleTmp->SetType(EnumAdd(MmiMessageId::TOUCH_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

// ?1?7?1?7?0?0?1?7?1?7?1?7
HWTEST_F(EventHandleTouchTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

auto g_touchHandle = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();
HWTEST_F(EventHandleTouchTest, RegisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_touchHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleTouchTest, RegisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_touchHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleTouchTest, UnregisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_touchHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleTouchTest, UnregisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, g_touchHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleTouchTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleTouchTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleTouchTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleTouchTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto touchHandleTmp = StandardizedEventHandler::Create<TouchEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, g_surFaceId, touchHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleTouchTest, Construction, TestSize.Level1)
{
    TouchEventHandler touchHandlerTmp;
}

HWTEST_F(EventHandleTouchTest, OnTouch_001, TestSize.Level1)
{
    TouchEvent event;
    TouchEventHandler touchHandlerTmp;
    bool retResult = touchHandlerTmp.OnTouch(event);
    EXPECT_FALSE(retResult);
}
} // namespace
