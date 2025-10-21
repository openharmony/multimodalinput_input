/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "key_loop_closure_checker.h"
#include "event_dispatch_handler.h"
#include "event_loop_closure_checker.h"
#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyLoopClosureCheckerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class KeyLoopClosureCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyLoopClosureCheckerTest_001
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyLoopClosureCheckerTest, KeyLoopClosureCheckerTest_001, TestSize.Level0)
{
    KeyLoopClosureChecker closureChecker;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    ASSERT_NE(keyEvent, nullptr);
    int32_t ret = closureChecker.CheckAndUpdateEventLoopClosure(keyEvent);
    EXPECT_EQ(ret, RET_ERR);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ret = closureChecker.CheckAndUpdateEventLoopClosure(keyEvent);
    EXPECT_EQ(ret, RET_OK);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ret = closureChecker.CheckAndUpdateEventLoopClosure(keyEvent);
    EXPECT_EQ(ret, RET_OK);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ret = closureChecker.CheckAndUpdateEventLoopClosure(keyEvent);
    EXPECT_EQ(ret, RET_OK);
}
/**
 * @tc.name: KeyLoopClosureCheckerTest_002
 * @tc.desc: Test the function HandleEventLoopClosureKeyUpOrCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyLoopClosureCheckerTest, KeyLoopClosureCheckerTest_002, TestSize.Level0)
{
    KeyLoopClosureChecker closureChecker;
    int32_t keyCode = 10;
    int32_t ret = closureChecker.HandleEventLoopClosureKeyUpOrCancel(keyCode);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyLoopClosureCheckerTest_003
 * @tc.desc: Test the function HandleEventLoopClosureKeyUpOrCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyLoopClosureCheckerTest, KeyLoopClosureCheckerTest_003, TestSize.Level0)
{
    KeyLoopClosureChecker closureChecker;
    int32_t keyCode = 10;
    int32_t ret = closureChecker.CheckLoopClosure(keyCode);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: KeyLoopClosureCheckerTest_004
 * @tc.desc: Test the function HandleEventLoopClosureKeyUpOrCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyLoopClosureCheckerTest, KeyLoopClosureCheckerTest_004, TestSize.Level0)
{
    KeyLoopClosureChecker closureChecker;
    int32_t keyCode = 10;
    int32_t ret = closureChecker.UpdatePendingDownKeys(keyCode);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: KeyLoopClosureCheckerTest_005
 * @tc.desc: Test the function HandleEventLoopClosureKeyUpOrCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyLoopClosureCheckerTest, KeyLoopClosureCheckerTest_005, TestSize.Level0)
{
    KeyLoopClosureChecker closureChecker;
    int32_t keyCode = 10;
    int32_t ret = closureChecker.UpdatePendingDownKeys(keyCode);
    EXPECT_EQ(ret, RET_OK);
    ret = closureChecker.RemovePendingDownKeys(keyCode);
    EXPECT_EQ(ret, RET_OK);
    keyCode = 9;
    ret = closureChecker.RemovePendingDownKeys(keyCode);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS