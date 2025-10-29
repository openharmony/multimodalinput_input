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

#include "event_expiration_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventExpirationCheckerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}  // namespace

class EventExpirationCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventExpirationCheckerTest_CheckExpiration001
 * @tc.desc: Test CheckExpiration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventExpirationCheckerTest, EventExpirationCheckerTest_CheckExpiration001, TestSize.Level0)
{
    int32_t hookId = 1;
    int32_t eventId = 1;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetId(eventId);
    int32_t result = EventExpirationChecker::GetInstance().CheckExpiration(hookId, eventId);
    EXPECT_EQ(result, RET_ERR);
    result = EventExpirationChecker::GetInstance().UpdateStashEvent(hookId, keyEvent);
    EXPECT_EQ(result, RET_OK);
    result = EventExpirationChecker::GetInstance().CheckExpiration(hookId, eventId);
    EXPECT_EQ(result, RET_OK);
    result = EventExpirationChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_OK);
    result = EventExpirationChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: EventExpirationCheckerTest_UpdateStashEvent001
 * @tc.desc: Test UpdateStashEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventExpirationCheckerTest, EventExpirationCheckerTest_UpdateStashEvent001, TestSize.Level0)
{
    int32_t hookId = 1;
    int32_t eventId = 1;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetId(eventId);
    int32_t result = EventExpirationChecker::GetInstance().UpdateStashEvent(hookId, keyEvent);
    EXPECT_EQ(result, RET_OK);
    result = EventExpirationChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: EventExpirationCheckerTest_GetKeyEvent001
 * @tc.desc: Test GetKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventExpirationCheckerTest, EventExpirationCheckerTest_GetKeyEvent001, TestSize.Level0)
{
    int32_t hookId = 1;
    int32_t eventId = 1;
    auto keyEvent = KeyEvent::Create();
    keyEvent->SetId(eventId);
    auto key = EventExpirationChecker::GetInstance().GetKeyEvent(hookId, eventId);
    EXPECT_EQ(key, nullptr);
    int32_t result = EventExpirationChecker::GetInstance().UpdateStashEvent(hookId, keyEvent);
    EXPECT_EQ(result, RET_OK);
    key = EventExpirationChecker::GetInstance().GetKeyEvent(hookId, 0);
    EXPECT_EQ(key, nullptr);
    key = EventExpirationChecker::GetInstance().GetKeyEvent(hookId, eventId);
    EXPECT_NE(key, nullptr);
    EventExpirationChecker::GetInstance().RemoveExpiredStashEventLocked(hookId);
    result = EventExpirationChecker::GetInstance().RemoveChecker(hookId);
    EXPECT_EQ(result, RET_OK);
    EventExpirationChecker::GetInstance().RemoveExpiredStashEventLocked(hookId);
}
}  // namespace MMI
}  // namespace OHOS