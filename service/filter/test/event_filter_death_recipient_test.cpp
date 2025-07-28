/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_death_recipient.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventFilterDeathRecipientTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventFilterDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: EventFilterDeathRecipientTest_Interface_001
 * @tc.desc: Verify the EventFilterDeathRecipient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventFilterDeathRecipientTest, EventFilterDeathRecipientTest_Interface_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    EventFilterDeathRecipient item {[&](const wptr<IRemoteObject> &object) {
        flag = true;
    }};
    ASSERT_NO_FATAL_FAILURE(item.OnRemoteDied(nullptr));
    ASSERT_TRUE(flag);
}
} // namespace MMI
} // namespace OHOS