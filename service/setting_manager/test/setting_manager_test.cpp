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
#include <gmock/gmock.h>
#include "mock_setting_manager.h"
#include "setting_types.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::MMI;

namespace OHOS {
namespace MMI {

class SettingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<MockSettingManager> mockManager_;
};

void SettingManagerTest::SetUpTestCase(void)
{
    // Input testsuit setup step, setup invoked before all testcases
}

void SettingManagerTest::TearDownTestCase(void)
{
    // Input testsuit teardown step, teardown invoked after all testcases
}

void SettingManagerTest::SetUp(void)
{
    mockManager_ = std::make_shared<MockSettingManager>();
}

void SettingManagerTest::TearDown(void)
{
    mockManager_.reset();
}

/**
 * @tc.name: SetIntValue_Success_001
 * @tc.desc: Verify SetIntValue function success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, SetIntValue_Success_001, TestSize.Level1)
{
    EXPECT_CALL(*mockManager_, SetIntValue(_, _, _, _))
        .Times(1)
        .WillOnce(Return(true));

    bool result = mockManager_->SetIntValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, 15);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SetIntValue_Failure_001
 * @tc.desc: Verify SetIntValue function failure.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, SetIntValue_Failure_001, TestSize.Level1)
{
    EXPECT_CALL(*mockManager_, SetIntValue(_, _, _, _))
        .Times(1)
        .WillOnce(Return(false));

    bool result = mockManager_->SetIntValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, 15);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: GetIntValue_Success_001
 * @tc.desc: Verify GetIntValue function success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, GetIntValue_Success_001, TestSize.Level1)
{
    int32_t expectedValue = 10;

    EXPECT_CALL(*mockManager_, GetIntValue(_, _, _, _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgReferee<3>(expectedValue),
            Return(true)
        ));

    int32_t value = 0;
    bool result = mockManager_->GetIntValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, value);

    EXPECT_TRUE(result);
    EXPECT_EQ(value, expectedValue);
}

/**
 * @tc.name: SetBoolValue_Success_001
 * @tc.desc: Verify SetBoolValue function success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, SetBoolValue_Success_001, TestSize.Level1)
{
    EXPECT_CALL(*mockManager_, SetBoolValue(_, _, _, _))
        .Times(1)
        .WillOnce(Return(true));

    bool result = mockManager_->SetBoolValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: GetBoolValue_Success_001
 * @tc.desc: Verify GetBoolValue function success.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, GetBoolValue_Success_001, TestSize.Level1)
{
    bool expectedValue = true;

    EXPECT_CALL(*mockManager_, GetBoolValue(_, _, _, _))
        .Times(1)
        .WillOnce(DoAll(
            SetArgReferee<3>(expectedValue),
            Return(true)
        ));

    bool value = false;
    bool result = mockManager_->GetBoolValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, value);

    EXPECT_TRUE(result);
    EXPECT_EQ(value, expectedValue);
}

/**
 * @tc.name: OnDataShareReady_001
 * @tc.desc: Verify OnDataShareReady function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, OnDataShareReady_001, TestSize.Level1)
{
    EXPECT_CALL(*mockManager_, OnDataShareReady())
        .Times(1);

    mockManager_->OnDataShareReady();
}

/**
 * @tc.name: OnSwitchUser_001
 * @tc.desc: Verify OnSwitchUser function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, OnSwitchUser_001, TestSize.Level1)
{
    const int32_t testUserId = 100;

    EXPECT_CALL(*mockManager_, OnSwitchUser(testUserId))
        .Times(1);

    mockManager_->OnSwitchUser(testUserId);
}

/**
 * @tc.name: OnAddUser_001
 * @tc.desc: Verify OnAddUser function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, OnAddUser_001, TestSize.Level1)
{
    const int32_t testUserId = 101;

    EXPECT_CALL(*mockManager_, OnAddUser(testUserId))
        .Times(1);

    mockManager_->OnAddUser(testUserId);
}

/**
 * @tc.name: OnRemoveUser_001
 * @tc.desc: Verify OnRemoveUser function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, OnRemoveUser_001, TestSize.Level1)
{
    const int32_t testUserId = 100;

    EXPECT_CALL(*mockManager_, OnRemoveUser(testUserId))
        .Times(1);

    mockManager_->OnRemoveUser(testUserId);
}

/**
 * @tc.name: MultipleOperations_001
 * @tc.desc: Verify multiple sequential operations.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingManagerTest, MultipleOperations_001, TestSize.Level1)
{
    int32_t intValue = 20;
    bool boolValue = false;

    {
        InSequence seq;
        EXPECT_CALL(*mockManager_, SetIntValue(100, _, _, _))
            .WillOnce(Return(true));
        EXPECT_CALL(*mockManager_, SetBoolValue(100, _, _, _))
            .WillOnce(Return(true));
        EXPECT_CALL(*mockManager_, GetIntValue(100, _, _, _))
            .WillOnce(DoAll(SetArgReferee<3>(intValue), Return(true)));
        EXPECT_CALL(*mockManager_, GetBoolValue(100, _, _, _))
            .WillOnce(DoAll(SetArgReferee<3>(boolValue), Return(true)));
    }

    bool result1 = mockManager_->SetIntValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, 15);
    EXPECT_TRUE(result1);

    bool result2 = mockManager_->SetBoolValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, false);
    EXPECT_TRUE(result2);

    int32_t value1 = 0;
    bool result3 = mockManager_->GetIntValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, value1);
    EXPECT_TRUE(result3);
    EXPECT_EQ(value1, intValue);

    bool value2 = true;
    bool result4 = mockManager_->GetBoolValue(100, MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, value2);
    EXPECT_TRUE(result4);
    EXPECT_EQ(value2, boolValue);
}

}  // namespace MMI
}  // namespace OHOS
