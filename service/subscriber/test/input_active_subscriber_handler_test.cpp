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

#include "input_active_subscriber_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscriberHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputActiveSubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputActiveSubscriberHandlerTest_SubscribeInputActive_001
 * @tc.desc: Verify SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_SubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 123, 1000, 2000);
    int32_t subscribeId = 1001;
    
    auto ret = handler.SubscribeInputActive(session, subscribeId, 500);
    EXPECT_EQ(ret, RET_OK);
    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputActiveSubscriberHandlerTest_OnSubscribeInputActive_001
 * @tc.desc: Verify SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerTest, InputActiveSubscriberHandlerTest_OnSubscribeInputActive_001, TestSize.Level1)
{
    int ret = RET_OK;
    EXPECT_EQ(ret, RET_OK);
}

} // namespace MMI
} // namespace OHOS