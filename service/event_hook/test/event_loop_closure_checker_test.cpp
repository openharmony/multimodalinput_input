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
 
#include "event_loop_closure_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
 
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventLoopClosureCheckerTest"
 
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}  // namespace
 
class EventLoopClosureCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
 
/**
 * @tc.name: EventLoopClosureCheckerTest_CheckLoopClosure001
 * @tc.desc: Test CheckLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventLoopClosureCheckerTest, EventLoopClosureCheckerTest_CheckLoopClosure001, TestSize.Level0)
{
    int32_t hookId = 1;
    int32_t keyCode = 101;
    int32_t result = EventLoopClosureChecker::GetInstance().CheckLoopClosure(hookId, keyCode);
    EXPECT_EQ(result, RET_ERR);
    EventLoopClosureChecker::GetInstance().pendingDownKeys_[hookId] = {{102, true}};
    result = EventLoopClosureChecker::GetInstance().CheckLoopClosure(hookId, keyCode);
    EXPECT_EQ(result, RET_ERR);
    EventLoopClosureChecker::GetInstance().pendingDownKeys_[hookId] = {{keyCode, true}};
    result = EventLoopClosureChecker::GetInstance().CheckLoopClosure(hookId, keyCode);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: EventLoopClosureCheckerTest_RemovePendingDownKeys001
 * @tc.desc: Test RemovePendingDownKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventLoopClosureCheckerTest, EventLoopClosureCheckerTest_RemovePendingDownKeys001, TestSize.Level0)
{
    int32_t hookId = 1;
    int32_t keyCode = 101;
    int32_t result = EventLoopClosureChecker::GetInstance().RemovePendingDownKeys(hookId, keyCode);
    EXPECT_EQ(result, RET_OK);
    EventLoopClosureChecker::GetInstance().pendingDownKeys_[hookId].insert(keyCode);
    result = EventLoopClosureChecker::GetInstance().RemovePendingDownKeys(hookId, keyCode);
    EXPECT_EQ(result, RET_OK);
    EventLoopClosureChecker::GetInstance().pendingDownKeys_[hookId].insert(keyCode);
    result = EventLoopClosureChecker::GetInstance().RemovePendingDownKeys(hookId, keyCode);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: EventLoopClosureCheckerTest_UpdatePendingDownKeys001
 * @tc.desc: Test UpdatePendingDownKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventLoopClosureCheckerTest, EventLoopClosureCheckerTest_UpdatePendingDownKeys001, TestSize.Level0)
{
    int32_t hookId = 2;
    int32_t keyCode = 10;
    EventLoopClosureChecker::GetInstance().UpdatePendingDownKeys(hookId, keyCode);
    auto it = EventLoopClosureChecker::GetInstance().pendingDownKeys_.find(hookId);
    EXPECT_NE(it, EventLoopClosureChecker::GetInstance().pendingDownKeys_.end());
    EXPECT_TRUE(it->second.count(keyCode) > 0);
    hookId = 3;
    int32_t result = EventLoopClosureChecker::GetInstance().UpdatePendingDownKeys(hookId, keyCode);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: EventLoopClosureCheckerTest_RemoveChecker001
 * @tc.desc: Test RemoveChecker
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventLoopClosureCheckerTest, EventLoopClosureCheckerTest_RemoveChecker001, TestSize.Level0)
{
    int32_t hookId = 1;
    EventLoopClosureChecker::GetInstance().pendingDownKeys_[hookId].insert(hookId);
    int32_t result = EventLoopClosureChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(EventLoopClosureChecker::GetInstance().pendingDownKeys_.find(hookId),
        EventLoopClosureChecker::GetInstance().pendingDownKeys_.end());
    result = EventLoopClosureChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_ERR);
}
}  // namespace MMI
}  // namespace OHOS