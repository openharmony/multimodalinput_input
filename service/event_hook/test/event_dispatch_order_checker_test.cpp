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

#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDispatchOrderCheckerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventDispatchOrderCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventDispatchOrderCheckerTest_CheckDispatchOrder001
 * @tc.desc: Test the function CheckDispatchOrder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventDispatchOrderCheckerTest, EventDispatchOrderCheckerTest_CheckDispatchOrder001, TestSize.Level0)
{
    int32_t hookId = 10;
    int32_t eventId = 1;
    EVENT_DISPATCH_ORDER_CHECKER.dispatchedEventIds_[0] = 1;
    EVENT_DISPATCH_ORDER_CHECKER.dispatchedEventIds_[1] = 1;
    int32_t ret = EVENT_DISPATCH_ORDER_CHECKER.CheckDispatchOrder(hookId, eventId);
    EXPECT_EQ(ret, RET_OK);
    hookId = 1;
    ret = EVENT_DISPATCH_ORDER_CHECKER.CheckDispatchOrder(hookId, eventId);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS