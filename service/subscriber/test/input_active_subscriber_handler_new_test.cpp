/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "input_active_subscriber_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputActiveSubscriberHandlerNewTest"

namespace OHOS {
namespace MMI {
namespace {

using namespace testing;
using namespace testing::ext;

constexpr int32_t TEST_SUBSCRIBE_ID_DEFAULT = 1001;
constexpr int32_t TEST_SUBSCRIBE_ID_SECOND = 1002;
constexpr int32_t TEST_PID_DEFAULT = 1234;
constexpr int32_t TEST_UID_DEFAULT = 5678;
constexpr int32_t TEST_FD_DEFAULT = 100;
constexpr int64_t TEST_INTERVAL_ZERO = 0;
constexpr int64_t TEST_INTERVAL_POSITIVE = 500;
constexpr int64_t TEST_INTERVAL_LARGE = 10000;
constexpr int32_t INVALID_SUBSCRIBE_ID = -1;
} // namespace

class InputActiveSubscriberHandlerNewTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: SubscribeInputActive_001
 * @tc.desc: Verify SubscribeInputActive with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_002
 * @tc.desc: Verify SubscribeInputActive with invalid subscribeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = INVALID_SUBSCRIBE_ID;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_003
 * @tc.desc: Verify SubscribeInputActive with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    SessionPtr session = nullptr;
    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_004
 * @tc.desc: Verify SubscribeInputActive with zero interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_ZERO;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_005
 * @tc.desc: Verify SubscribeInputActive with large interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_LARGE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_001
 * @tc.desc: Verify UnsubscribeInputActive with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_002
 * @tc.desc: Verify UnsubscribeInputActive with non-existent subscribeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;

    int32_t ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_003
 * @tc.desc: Verify UnsubscribeInputActive multiple subscriptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_004
 * @tc.desc: Verify UnsubscribeInputActive with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    SessionPtr session = nullptr;
    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;

    int32_t ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Verify Dump with no subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    int32_t fd = 0;
    std::vector<std::string> args;

    handler.Dump(fd, args);
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Verify Dump with one subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    int32_t fd = 0;
    std::vector<std::string> args;
    handler.Dump(fd, args);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Dump_003
 * @tc.desc: Verify Dump with multiple args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    int32_t fd = 0;
    std::vector<std::string> args = {"arg1", "arg2", "arg3"};
    handler.Dump(fd, args);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_006
 * @tc.desc: Verify SubscribeInputActive with subscribeId zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_006, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = 0;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_007
 * @tc.desc: Verify SubscribeInputActive with large subscribeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_007, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = 9999;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_008
 * @tc.desc: Verify SubscribeInputActive with minimum positive interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_008, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = 1;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_009
 * @tc.desc: Verify SubscribeInputActive with maximum interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_009, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = INT64_MAX;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_010
 * @tc.desc: Verify SubscribeInputActive with multiple sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_010, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeInputActive_012
 * @tc.desc: Verify SubscribeInputActive with empty program name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeInputActive_012, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_005
 * @tc.desc: Verify UnsubscribeInputActive in reverse order
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_006
 * @tc.desc: Verify UnsubscribeInputActive twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_006, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_007
 * @tc.desc: Verify UnsubscribeInputActive with mismatched session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_007, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId2);
    EXPECT_NE(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: UnsubscribeInputActive_008
 * @tc.desc: Verify UnsubscribeInputActive with subscribeId zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, UnsubscribeInputActive_008, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = 0;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Dump_004
 * @tc.desc: Verify Dump with negative fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    int32_t fd = -1;
    std::vector<std::string> args;

    handler.Dump(fd, args);
}

/**
 * @tc.name: Dump_005
 * @tc.desc: Verify Dump with fd one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    int32_t fd = 1;
    std::vector<std::string> args;
    handler.Dump(fd, args);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Dump_006
 * @tc.desc: Verify Dump with multiple subscribers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, Dump_006, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    int32_t fd = 0;
    std::vector<std::string> args;
    handler.Dump(fd, args);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultiSession_001
 * @tc.desc: Verify multiple sessions subscribe and unsubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, MultiSession_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    auto session3 = std::make_shared<UDSSession>("test_program3", 1, TEST_PID_DEFAULT + 2,
        TEST_FD_DEFAULT + 2, TEST_UID_DEFAULT + 2);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);
    ASSERT_NE(session3, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int32_t subscribeId3 = 1003;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session3, subscribeId3, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session3, subscribeId3);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultiSession_002
 * @tc.desc: Verify session deletion clears subscriptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, MultiSession_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session1);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_NE(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultiSession_003
 * @tc.desc: Verify partial session deletion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, MultiSession_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session2);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SubscribeUnsubscribeSequence_001
 * @tc.desc: Verify repeat subscribe and unsubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeUnsubscribeSequence_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    for (int i = 0; i < 3; ++i) {
        int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
        EXPECT_EQ(ret, RET_OK);

        ret = handler.UnsubscribeInputActive(session, subscribeId);
        EXPECT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: SubscribeUnsubscribeSequence_002
 * @tc.desc: Verify subscribe different Id after unsubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeUnsubscribeSequence_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeUnsubscribeSequence_005
 * @tc.desc: Verify unsubscribe non-existent subscribeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SubscribeUnsubscribeSequence_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_NE(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EdgeCases_001
 * @tc.desc: Verify with zero pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EdgeCases_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 0,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EdgeCases_002
 * @tc.desc: Verify with zero fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EdgeCases_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        0, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EdgeCases_003
 * @tc.desc: Verify with zero uid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EdgeCases_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, 0);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EdgeCases_004
 * @tc.desc: Verify with maximum pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EdgeCases_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, INT32_MAX,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EdgeCases_005
 * @tc.desc: Verify with maximum uid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EdgeCases_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, INT32_MAX);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ErrorHandling_001
 * @tc.desc: Verify unsubscribe after session deleted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ErrorHandling_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: ErrorHandling_002
 * @tc.desc: Verify subscribe after session deleted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ErrorHandling_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    handler.OnSessionDelete(session);

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ErrorHandling_003
 * @tc.desc: Verify unsubscribe wrong Id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ErrorHandling_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_NE(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ErrorHandling_004
 * @tc.desc: Verify unsubscribe with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ErrorHandling_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    SessionPtr session = nullptr;
    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;

    int32_t ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: ErrorHandling_005
 * @tc.desc: Verify subscribe with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ErrorHandling_005, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    SessionPtr session = nullptr;
    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_NE(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: RepeatSubscribe_001
 * @tc.desc: Verify repeat subscribe same Id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, RepeatSubscribe_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    for (int i = 0; i < 5; ++i) {
        int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
        EXPECT_EQ(ret, RET_OK);

        ret = handler.UnsubscribeInputActive(session, subscribeId);
        EXPECT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: DifferentIntervals_001
 * @tc.desc: Verify with different interval values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DifferentIntervals_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval1 = 100;
    int64_t interval2 = 200;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval2);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DifferentIntervals_002
 * @tc.desc: Verify with minimum interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DifferentIntervals_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = 50;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DifferentIntervals_003
 * @tc.desc: Verify with large interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DifferentIntervals_003, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = 1000;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DifferentIntervals_004
 * @tc.desc: Verify with very large interval
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DifferentIntervals_004, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = 5000;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LargeSessionCount_001
 * @tc.desc: Verify with 5 sessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, LargeSessionCount_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    std::vector<std::shared_ptr<UDSSession>> sessions;
    std::vector<int32_t> subscribeIds;

    for (int i = 0; i < 5; ++i) {
        auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT + i,
            TEST_FD_DEFAULT + i, TEST_UID_DEFAULT + i);
        ASSERT_NE(session, nullptr);
        sessions.push_back(session);
        subscribeIds.push_back(TEST_SUBSCRIBE_ID_DEFAULT + i);
    }

    int64_t interval = TEST_INTERVAL_POSITIVE;

    for (size_t i = 0; i < sessions.size(); ++i) {
        int32_t ret = handler.SubscribeInputActive(sessions[i], subscribeIds[i], interval);
        EXPECT_EQ(ret, RET_OK);
    }

    for (size_t i = 0; i < sessions.size(); ++i) {
        int32_t ret = handler.UnsubscribeInputActive(sessions[i], subscribeIds[i]);
        EXPECT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: MixedOperations_001
 * @tc.desc: Verify subscribe then delete session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, MixedOperations_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session1);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_NE(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session2);
}

/**
 * @tc.name: MixedOperations_002
 * @tc.desc: Verify unsubscribe then delete session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, MixedOperations_002, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session1);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    handler.OnSessionDelete(session2);
}

/**
 * @tc.name: DumpWithEmptyArgs_001
 * @tc.desc: Verify Dump with empty args no subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DumpWithEmptyArgs_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    int32_t fd = 0;
    std::vector<std::string> args;

    handler.Dump(fd, args);
}

/**
 * @tc.name: DumpWithMultipleArgs_001
 * @tc.desc: Verify Dump with multiple args one subscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DumpWithMultipleArgs_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    int32_t fd = 0;
    std::vector<std::string> args = {"-h", "--help", "-v"};
    handler.Dump(fd, args);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LongSessionName_001
 * @tc.desc: Verify with 256 length session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, LongSessionName_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    std::string longName(256, 'a');
    auto session = std::make_shared<UDSSession>(longName, 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SpecialCharsInSessionName_001
 * @tc.desc: Verify with special characters in session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SpecialCharsInSessionName_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test@#$%^&*()", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SessionWithDifferentPid_001
 * @tc.desc: Verify with pid 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SessionWithDifferentPid_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, 1,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SessionWithNegativePid_001
 * @tc.desc: Verify with negative pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, SessionWithNegativePid_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, -1,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: VerifySubscribeOrder_001
 * @tc.desc: Verify subscribe order handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, VerifySubscribeOrder_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    auto session3 = std::make_shared<UDSSession>("test_program3", 1, TEST_PID_DEFAULT + 2,
        TEST_FD_DEFAULT + 2, TEST_UID_DEFAULT + 2);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);
    ASSERT_NE(session3, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int32_t subscribeId3 = 1003;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session3, subscribeId3, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session3, subscribeId3);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: VerifyUnsubscribeOrder_001
 * @tc.desc: Verify unsubscribe order handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, VerifyUnsubscribeOrder_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session1 = std::make_shared<UDSSession>("test_program1", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    auto session2 = std::make_shared<UDSSession>("test_program2", 1, TEST_PID_DEFAULT + 1,
        TEST_FD_DEFAULT + 1, TEST_UID_DEFAULT + 1);
    auto session3 = std::make_shared<UDSSession>("test_program3", 1, TEST_PID_DEFAULT + 2,
        TEST_FD_DEFAULT + 2, TEST_UID_DEFAULT + 2);
    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);
    ASSERT_NE(session3, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int32_t subscribeId3 = 1003;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session1, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session2, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session3, subscribeId3, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session1, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session2, subscribeId2);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session3, subscribeId3);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ConcurrentSubscribe_001
 * @tc.desc: Verify concurrent subscribe operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ConcurrentSubscribe_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId1 = TEST_SUBSCRIBE_ID_DEFAULT;
    int32_t subscribeId2 = TEST_SUBSCRIBE_ID_SECOND;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId1, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId2, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId1);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId2);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ReuseSubscribeId_001
 * @tc.desc: Verify reuse subscribe Id after unsubscribe
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, ReuseSubscribeId_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EmptySessionName_001
 * @tc.desc: Verify with empty session name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, EmptySessionName_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("", 1, TEST_PID_DEFAULT,
        TEST_FD_DEFAULT, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DifferentFd_001
 * @tc.desc: Verify with fd 200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputActiveSubscriberHandlerNewTest, DifferentFd_001, TestSize.Level1)
{
    InputActiveSubscriberHandler handler;
    auto session = std::make_shared<UDSSession>("test_program", 1, TEST_PID_DEFAULT,
        200, TEST_UID_DEFAULT);
    ASSERT_NE(session, nullptr);

    int32_t subscribeId = TEST_SUBSCRIBE_ID_DEFAULT;
    int64_t interval = TEST_INTERVAL_POSITIVE;

    int32_t ret = handler.SubscribeInputActive(session, subscribeId, interval);
    EXPECT_EQ(ret, RET_OK);

    ret = handler.UnsubscribeInputActive(session, subscribeId);
    EXPECT_EQ(ret, RET_OK);
}

} // namespace MMI
} // namespace OHOS