/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cinttypes>

#include <gtest/gtest.h>
#include "libinput.h"
#include "pixel_map.h"
#include "sec_comp_enhance_kit.h"

#include "define_multimodal.h"
#include "server_msg_handler.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDoen() {}
};

/**
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    int32_t infoId = -1;
    void* pixelMap = nullptr;
    int32_t result = servermsghandler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetShieldStatus_01
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetShieldStatus_01, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = -1;
    bool isShield = false;
    int32_t result = servermsghandler.SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetShieldStatus_02
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetShieldStatus_02, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = 1;
    bool isShield = true;
    int32_t result = servermsghandler.SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_GetShieldStatus_01
 * @tc.desc: Test GetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_GetShieldStatus_01, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = -1;
    bool isShield = false;
    int32_t result = servermsghandler.GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_GetShieldStatus_02
 * @tc.desc: Test GetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_GetShieldStatus_02, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = 1;
    bool isShield = true;
    int32_t result = servermsghandler.GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent
 * @tc.desc: Test OnInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 1;
    bool isNativeInject = false;
    int32_t result = servermsghandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_01
 * @tc.desc: Test OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_01, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    bool isAuthorize = true;
    int32_t result = servermsghandler.OnAuthorize(isAuthorize);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_02
 * @tc.desc: Test OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_02, TestSize.Level1)
{
    ServerMsgHandler servermsghandler;
    bool isAuthorize = false;
    int32_t result = servermsghandler.OnAuthorize(isAuthorize);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace MMI
} // namespace OHOS