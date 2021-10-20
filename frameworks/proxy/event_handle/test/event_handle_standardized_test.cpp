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
#include "log.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"
#include "mmi_token.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;


class EventHandleStandardizedTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const unsigned int g_surFaceId = 10;
};

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_NORMAL_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                     standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_NORMAL_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                     standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_NORMAL_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_nullptr_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote,
                                                                     g_surFaceId, nullptr);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_nullptr_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote,
                                                                     g_surFaceId, nullptr);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);

    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         nullptr);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_nullptr_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         nullptr);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_VALIDPARAM_001, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                     standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_VALIDPARAM_002, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t regResult = MMIEventHdl.RegisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                     standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, regResult);
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}

HWTEST_F(EventHandleStandardizedTest, RegisterStandardizedEventHandle_VALIDPARAM_003, TestSize.Level1)
{
    const std::string strDesc = "hello world!";
    const std::u16string u16Desc = Str8ToStr16(strDesc);
    auto iRemote = MMIToken::Create(u16Desc);
    auto standHandler = StandardizedEventHandler::Create<StandardizedEventHandler>();
    int32_t unregResult = MMIEventHdl.UnregisterStandardizedEventHandle(iRemote, g_surFaceId,
                                                                         standHandler);
    EXPECT_EQ(OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER, unregResult);
}
} // namespace
