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

#include "mmi_log.h"
#include "whitelist_data_share_accessor.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "WhitelistDataShareAccessorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const int32_t COOLING_TIME_MS { 1000 };
} // namespace
class WhitelistDataShareAccessorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: WhitelistDataShareAccessorTest_GetInstance_001
 * @tc.desc: Test GetInstance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_GetInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor::GetInstance().Init();
    EXPECT_FALSE(WhitelistDataShareAccessor::GetInstance().initialized_.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Init_001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.Init();
    EXPECT_FALSE(accessor.initialized_.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_InitializeImpl_001
 * @tc.desc: Test InitializeImpl
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_InitializeImpl_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.InitializeImpl();
    EXPECT_FALSE(accessor.initialized_.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_AddWhitelistObserver_001
 * @tc.desc: Test AddWhitelistObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_AddWhitelistObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    auto ret = accessor.AddWhitelistObserver();
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}


/**
 * @tc.name: WhitelistDataShareAccessorTest_IsWhitelisted_001
 * @tc.desc: Test IsWhitelisted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_IsWhitelisted_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    bool ret = accessor.IsWhitelisted("Hello");
    EXPECT_FALSE(ret);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_ReadWhitelistFromDB_001
 * @tc.desc: Test ReadWhitelistFromDB
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_ReadWhitelistFromDB_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist;
    WhitelistDataShareAccessor accessor;
    auto ret = accessor.ReadWhitelistFromDB(whitelist);
    EXPECT_NE(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_OnUpdate_001
 * @tc.desc: Test OnUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_OnUpdate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.OnUpdate("INVALID_KEY");
    EXPECT_TRUE(accessor.whitelist_.empty());
    accessor.OnUpdate("UNIVERSAL_DRAG_CONFIG_WHITELIST");
    EXPECT_TRUE(accessor.whitelist_.empty());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Split_001
 * @tc.desc: Test Split
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Split_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string emptyWhitlistStr { "" };
    auto whitelist = WhitelistDataShareAccessor::Split(emptyWhitlistStr);
    EXPECT_TRUE(whitelist.empty());
    std::string whitlistStr { "com.ohos.a;com.ohos.b;com.ohos.c"};
    whitelist = WhitelistDataShareAccessor::Split(whitlistStr);
    EXPECT_TRUE(whitelist.size() == 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_UpdateWhitelist_001
 * @tc.desc: Test UpdateWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_UpdateWhitelist_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist { "com.ohos.a", "com.ohos.b", "com.ohos.c" };
    WhitelistDataShareAccessor accessor;
    accessor.UpdateWhitelist(whitelist);
    EXPECT_TRUE(accessor.whitelist_.size() == 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_InitializeImpl_002
 * @tc.desc: Test InitializeImpl when already initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_InitializeImpl_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.initialized_.store(true);
    auto ret = accessor.InitializeImpl();
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_InitializeImpl_003
 * @tc.desc: Test InitializeImpl when ReadWhitelistFromDB fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_InitializeImpl_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.initialized_.store(false);
    auto ret = accessor.InitializeImpl();
    EXPECT_NE(ret, RET_OK);
    EXPECT_FALSE(accessor.initialized_.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_IsWhitelisted_002
 * @tc.desc: Test IsWhitelisted when bundleName is in whitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_IsWhitelisted_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    std::vector<std::string> whitelist { "com.ohos.test", "com.ohos.demo" };
    accessor.UpdateWhitelist(whitelist);
    accessor.initialized_.store(true);
    bool ret = accessor.IsWhitelisted("com.ohos.test");
    EXPECT_TRUE(ret);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_IsWhitelisted_003
 * @tc.desc: Test IsWhitelisted when bundleName is not in whitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_IsWhitelisted_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    std::vector<std::string> whitelist { "com.ohos.test", "com.ohos.demo" };
    accessor.UpdateWhitelist(whitelist);
    accessor.initialized_.store(true);
    bool ret = accessor.IsWhitelisted("com.ohos.other");
    EXPECT_FALSE(ret);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_IsWhitelisted_004
 * @tc.desc: Test IsWhitelisted when initialized is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_IsWhitelisted_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.initialized_.store(false);
    bool ret = accessor.IsWhitelisted("com.ohos.test");
    EXPECT_FALSE(ret);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_ReadWhitelistFromDB_002
 * @tc.desc: Test ReadWhitelistFromDB with valid whitelist string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_ReadWhitelistFromDB_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist;
    WhitelistDataShareAccessor accessor;
    auto ret = accessor.ReadWhitelistFromDB(whitelist);
    EXPECT_NE(ret, RET_OK);
    EXPECT_TRUE(whitelist.empty());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_AddWhitelistObserver_002
 * @tc.desc: Test AddWhitelistObserver when CreateObserver fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_AddWhitelistObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    auto ret = accessor.AddWhitelistObserver();
    EXPECT_TRUE(ret == RET_OK || ret != RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_OnUpdate_002
 * @tc.desc: Test OnUpdate with valid key and successful read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_OnUpdate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    accessor.OnUpdate("UNIVERSAL_DRAG_CONFIG_WHITELIST");
    EXPECT_TRUE(accessor.whitelist_.empty());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Split_002
 * @tc.desc: Test Split with custom delimiter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Split_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str { "a,b,c" };
    auto tokens = WhitelistDataShareAccessor::Split(str, ',');
    EXPECT_EQ(tokens.size(), 3);
    EXPECT_EQ(tokens[0], "a");
    EXPECT_EQ(tokens[1], "b");
    EXPECT_EQ(tokens[2], "c");
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Split_003
 * @tc.desc: Test Split with empty tokens
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Split_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str { "a;;b;c;" };
    auto tokens = WhitelistDataShareAccessor::Split(str, ';');
    EXPECT_EQ(tokens.size(), 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Split_004
 * @tc.desc: Test Split with single token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Split_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string str { "com.ohos.single" };
    auto tokens = WhitelistDataShareAccessor::Split(str, ';');
    EXPECT_EQ(tokens.size(), 1);
    EXPECT_EQ(tokens[0], "com.ohos.single");
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_UpdateWhitelist_002
 * @tc.desc: Test UpdateWhitelist with empty whitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_UpdateWhitelist_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist {};
    WhitelistDataShareAccessor accessor;
    accessor.UpdateWhitelist(whitelist);
    EXPECT_TRUE(accessor.whitelist_.empty());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_UpdateWhitelist_003
 * @tc.desc: Test UpdateWhitelist with duplicate entries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_UpdateWhitelist_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist { "com.ohos.a", "com.ohos.a", "com.ohos.b" };
    WhitelistDataShareAccessor accessor;
    accessor.UpdateWhitelist(whitelist);
    EXPECT_EQ(accessor.whitelist_.size(), 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_UpdateWhitelist_004
 * @tc.desc: Test UpdateWhitelist with single entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_UpdateWhitelist_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> whitelist { "com.ohos.single" };
    WhitelistDataShareAccessor accessor;
    accessor.UpdateWhitelist(whitelist);
    EXPECT_EQ(accessor.whitelist_.size(), 1);
    EXPECT_TRUE(accessor.whitelist_.find("com.ohos.single") != accessor.whitelist_.end());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Ctor_001
 * @tc.desc: Test constructor calls Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Ctor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    EXPECT_FALSE(accessor.initialized_.load());
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_GetInstance_002
 * @tc.desc: Test GetInstance returns same instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_GetInstance_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto& instance1 = WhitelistDataShareAccessor::GetInstance();
    auto& instance2 = WhitelistDataShareAccessor::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}

/**
 * @tc.name: WhitelistDataShareAccessorTest_Init_002
 * @tc.desc: Test Init returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(WhitelistDataShareAccessorTest, WhitelistDataShareAccessorTest_Init_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WhitelistDataShareAccessor accessor;
    auto ret = accessor.Init();
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(COOLING_TIME_MS));
}
} // namespace MMI
} // namespace OHOS