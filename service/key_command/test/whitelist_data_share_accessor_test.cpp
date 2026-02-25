/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

} // namespace MMI
} // namespace OHOS