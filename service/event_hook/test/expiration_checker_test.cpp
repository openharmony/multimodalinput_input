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

#include "expiration_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "key_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ExpirationCheckerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}  // namespace

class ExpirationCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: ExpirationCheckerTest_CheckExpiration001
 * @tc.desc: Test CheckExpiration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExpirationCheckerTest, ExpirationCheckerTest_CheckExpiration001, TestSize.Level0)
{
    ExpirationChecker checker;
    int32_t eventId = 1;

    bool result = checker.CheckExpiration(eventId);
    EXPECT_FALSE(result);

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetId(eventId);
    checker.UpdateInputEvent(keyEvent);

    result = checker.CheckExpiration(eventId);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ExpirationCheckerTest_CheckValid001
 * @tc.desc: Test CheckValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExpirationCheckerTest, ExpirationCheckerTest_CheckValid001, TestSize.Level0)
{
    ExpirationChecker checker;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetId(1);

    bool result = checker.CheckValid(keyEvent);
    EXPECT_FALSE(result);

    checker.UpdateInputEvent(keyEvent);
    result = checker.CheckValid(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ExpirationCheckerTest_UpdateInputEvent001
 * @tc.desc: Test UpdateInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExpirationCheckerTest, ExpirationCheckerTest_UpdateInputEvent001, TestSize.Level0)
{
    ExpirationChecker checker;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetId(1);

    checker.UpdateInputEvent(keyEvent);

    bool result = checker.CheckExpiration(keyEvent->GetId());
    EXPECT_TRUE(result);

    result = checker.CheckValid(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ExpirationCheckerTest_RemoveExpiredEvent001
 * @tc.desc: Test RemoveExpiredEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExpirationCheckerTest, ExpirationCheckerTest_RemoveExpiredEvent001, TestSize.Level0)
{
    ExpirationChecker checker;
    auto keyEvent1 = KeyEvent::Create();
    ASSERT_NE(keyEvent1, nullptr);
    keyEvent1->SetId(1);
    checker.UpdateInputEvent(keyEvent1);

    bool result = checker.CheckExpiration(1);
    EXPECT_TRUE(result);

    {
        std::unique_lock<std::shared_mutex> lock(checker.rwMutex_);
        checker.stashEvents_.clear();

        auto now = std::chrono::steady_clock::now();
        auto past_time = now - std::chrono::milliseconds(5000);
        auto timeStampRcvd = std::chrono::duration_cast<std::chrono::milliseconds>(
            past_time.time_since_epoch()).count();
            
        ExpirationChecker::StashEvent expiredEvent {
            .timeStampRcvd = timeStampRcvd,
            .eventId = 1,
            .hashCode = keyEvent1->Hash()
        };
        checker.stashEvents_.push_back(expiredEvent);
    }

    checker.RemoveExpiredEvent();

    result = checker.CheckExpiration(1);
    EXPECT_FALSE(result);

    auto keyEvent2 = KeyEvent::Create();
    ASSERT_NE(keyEvent2, nullptr);
    keyEvent2->SetId(2);
    checker.UpdateInputEvent(keyEvent2);

    result = checker.CheckExpiration(1);
    EXPECT_FALSE(result);

    result = checker.CheckExpiration(2);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ExpirationCheckerTest_BoundaryConditions
 * @tc.desc: Test boundary conditions and error scenarios
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ExpirationCheckerTest, ExpirationCheckerTest_BoundaryConditions, TestSize.Level1)
{
    ExpirationChecker checker;

    EXPECT_FALSE(checker.CheckExpiration(0));
    EXPECT_FALSE(checker.CheckExpiration(-1));
    EXPECT_FALSE(checker.CheckExpiration(INT32_MAX));

    EXPECT_FALSE(checker.CheckValid(nullptr));

    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetId(1);
    checker.UpdateInputEvent(keyEvent);
    checker.UpdateInputEvent(keyEvent);
    EXPECT_TRUE(checker.CheckValid(keyEvent));
    EXPECT_TRUE(checker.CheckExpiration(1));
}
}  // namespace MMI
}  // namespace OHOS