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
#define private public
#define protected public

#include <gtest/gtest.h>

#include "touchpad_settings_handler.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class TouchpadSettingsHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TouchpadSettingsHandlerTest::SetUpTestCase(void)
{
}

void TouchpadSettingsHandlerTest::TearDownTestCase(void)
{
}

void TouchpadSettingsHandlerTest::SetUp()
{
}

void TouchpadSettingsHandlerTest::TearDown()
{
}

/**
 * @tc.name: RegisterTpObserver_001
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    EXPECT_FALSE(observer.RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_002
 * @tc.desc: Test when the account id is negative, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_002, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    EXPECT_FALSE(observer.RegisterTpObserver(-1));
}

/**
 * @tc.name: RegisterTpObserver_003
 * @tc.desc: Test when the update function is null, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_003, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.updateFunc_ = nullptr;
    EXPECT_FALSE(observer.RegisterTpObserver(-1));
}

/**
 * @tc.name: UnregisterTpObserver_001
 * @tc.desc: Test when the observer is not registered, UnregisterTpObserver should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = false;
    observer.currentAccountId_ = 1;
    EXPECT_FALSE(observer.UnregisterTpObserver(2));
}

/**
 * @tc.name: UnregisterTpObserver_002
 * @tc.desc: Test when the observer is registered with the same accountId, UnregisterTpObserver should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_002, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    observer.currentAccountId_ = 1;
    EXPECT_FALSE(observer.UnregisterTpObserver(1));
}

/**
 * @tc.name: UnregisterTpObserver_003
 * @tc.desc: Test when the observer is registered with a different accountId, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_003, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    observer.currentAccountId_ = 1;
    EXPECT_TRUE(observer.UnregisterTpObserver(2));
}

/**
 * @tc.name: UnregisterTpObserver_004
 * @tc.desc: Test when the observer is null, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_004, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    observer.currentAccountId_ = 1;
    observer.pressureObserver_ = nullptr;
    observer.vibrationObserver_ = nullptr;
    observer.touchpadSwitchesObserver_ = nullptr;
    observer.knuckleSwitchesObserver_ = nullptr;
    EXPECT_TRUE(observer.UnregisterTpObserver(2));
}

/**
 * @tc.name: RegisterUpdateFunc_001
 * @tc.desc: Test if RegisterUpdateFunc sets the updateFunc_ to a non-null value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterUpdateFunc_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.RegisterUpdateFunc();
    EXPECT_NE(observer.updateFunc_, nullptr);
}

/**
 * @tc.name: SyncTouchpadSettingsData_001
 * @tc.desc: Test when the updateFunc_ is null, SyncTouchpadSettingsData should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    observer.updateFunc_ = nullptr;
    observer.SyncTouchpadSettingsData();
    EXPECT_EQ(observer.hasRegistered_, true);
}
}
} // namespace OHOS::MMI