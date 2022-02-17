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
#include "error_multimodal.h"
#include "log.h"
#include "mmi_token.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "string_ex.h"
#include "util_ex.h"
#include "media_event_handler.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;


class EventHandleMediaTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const uint32_t surFaceId_ = 10;
};

class MediaEventHandleUnitTest : public MediaEventHandler {
public:
    MediaEventHandleUnitTest() {}
    ~MediaEventHandleUnitTest() {}

    virtual bool OnPlayUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnPlay(multiModalEvent);
    }

    virtual bool OnPauseUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnPause(multiModalEvent);
    }

    virtual bool OnMediaControlUnitTest(const MultimodalEvent& multiModalEvent)
    {
        return OnMediaControl(multiModalEvent);
    }
};

HWTEST_F(EventHandleMediaTest, RegisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();
    mediaHandleTmp->SetType(EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleMediaTest, RegisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();
    MMIEventHdl.RegisterStandardizedEventHandle(iRemote, surFaceId_, mediaHandleTmp);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

HWTEST_F(EventHandleMediaTest, UnregisterStandardizedEventHandle_tmp_err001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();
    mediaHandleTmp->SetType(EnumAdd(MmiMessageId::MEDIA_EVENT_BEGIN, 1));
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

// ?1?7?1?7?0?0?1?7?1?7?1?7
HWTEST_F(EventHandleMediaTest, UnregisterStandardizedEventHandle_tmp_err002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();
    int32_t regResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult);
}

auto g_mediaHandle = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();
HWTEST_F(EventHandleMediaTest, RegisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, g_mediaHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);
}

HWTEST_F(EventHandleMediaTest, RegisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, g_mediaHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, unregResult);
}

HWTEST_F(EventHandleMediaTest, UnregisterStandardizedEventHandle_suc001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, g_mediaHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleMediaTest, UnregisterStandardizedEventHandle_suc002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, g_mediaHandle);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult);
}

HWTEST_F(EventHandleMediaTest, RegisterAndUnregister_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);
}

HWTEST_F(EventHandleMediaTest, RegisterAndUnregister_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);
}

HWTEST_F(EventHandleMediaTest, RegisterAndUnregister_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleMediaTest, RegisterAndUnregister_004, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto mediaHandleTmp = StandardizedEventHandler::Create<MediaEventHandleUnitTest>();

    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, regResult);

    int32_t regResult2 = MMIEventHdl.RegisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_EXIST, regResult2);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_SUCCESS, unregResult);

    int32_t unregResult2 = MMIEventHdl.UnregisterStandardizedEventHandle(
        iRemote, surFaceId_, mediaHandleTmp);
    EXPECT_NE(MMI_STANDARD_EVENT_NOT_EXIST, unregResult2);
}

HWTEST_F(EventHandleMediaTest, Construction, TestSize.Level1)
{
    MediaEventHandler eventHandlerTmp;
}

HWTEST_F(EventHandleMediaTest, OnPlay, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnPlay(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleMediaTest, OnPause, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnPause(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleMediaTest, OnMediaControl, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnMediaControl(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleMediaTest, OnPlay_L, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnPlay(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleMediaTest, OnPause_L, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;
    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnPause(multiModalEvent);
    EXPECT_FALSE(retResult);
}

HWTEST_F(EventHandleMediaTest, OnMediaControl_L, TestSize.Level1)
{
    MultimodalEvent multiModalEvent;

    MediaEventHandler eventHandlerTmp;
    bool retResult = eventHandlerTmp.OnMediaControl(multiModalEvent);
    EXPECT_FALSE(retResult);
}
} // namespace
