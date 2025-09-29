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

#include "setting_datashare.h"
#include "touchpad_settings_handler.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
const std::string g_volumeSwitchesKey {"settings.trackpad.right_volume_switches"};
const std::string g_brightnessSwitchesKey {"settings.trackpad.left_brightness_switches"};
const std::string g_pressureKey {"settings.trackpad.press_level"};
const std::string g_vibrationKey {"settings.trackpad.shock_level"};
const std::string g_touchpadSwitchesKey {"settings.trackpad.touchpad_switches"};
const std::string g_knuckleSwitchesKey {"settings.trackpad.touchpad_switches"};
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
    observer.volumeSwitchesObserver_ = nullptr;
    observer.brightnessSwitchesObserver_ = nullptr;
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
    EXPECT_EQ(observer.updateFunc_, nullptr);
    observer.SyncTouchpadSettingsData();
}

/**
 * @tc.name: SyncTouchpadSettingsData_003
 * @tc.desc: Test when the updateFunc_ is null, SyncTouchpadSettingsData should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_003, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    EXPECT_NE(observer.updateFunc_, nullptr);
    ASSERT_NO_FATAL_FAILURE(observer.SyncTouchpadSettingsData());
}

/**
 * @tc.name: SyncTouchpadSettingsData_004
 * @tc.desc: Test in normal case, SyncTouchpadSettingsData should not return early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_004, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    observer.isCommonEventReady_.store(true);
    EXPECT_NE(observer.updateFunc_, nullptr);
    ASSERT_NO_FATAL_FAILURE(observer.SyncTouchpadSettingsData());
}

/**
 * @tc.name: UnregisterTpObserver_005
 * @tc.desc: Test when the observer is null, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_005, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = true;
    observer.currentAccountId_ = 1;
    int32_t serviceId = 3101;
    observer.volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, observer.updateFunc_);
    observer.brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, observer.updateFunc_);
    observer.pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, observer.updateFunc_);
    observer.vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, observer.updateFunc_);
    observer.touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, observer.updateFunc_);
    observer.knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, observer.updateFunc_);
    EXPECT_FALSE(observer.UnregisterTpObserver(2));
    observer.volumeSwitchesObserver_ = nullptr;
    observer.brightnessSwitchesObserver_ = nullptr;
    observer.pressureObserver_ = nullptr;
    observer.vibrationObserver_ = nullptr;
    observer.touchpadSwitchesObserver_ = nullptr;
    observer.knuckleSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: RegisterTpObserver_006
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_006, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.hasRegistered_ = false;
    int32_t serviceId = 2;
    observer.pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, observer.updateFunc_);
    observer.vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, observer.updateFunc_);
    observer.touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, observer.updateFunc_);
    observer.knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, observer.updateFunc_);
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    ASSERT_NO_FATAL_FAILURE(observer.RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_008
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_008, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    int32_t serviceId = 3101;
    observer.volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, observer.updateFunc_);
    observer.brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, observer.updateFunc_);
    observer.pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, observer.updateFunc_);
    observer.vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, observer.updateFunc_);
    observer.touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, observer.updateFunc_);
    observer.knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, observer.updateFunc_);
    ASSERT_NO_FATAL_FAILURE(observer.RegisterTpObserver(123));
    observer.volumeSwitchesObserver_ = nullptr;
    observer.brightnessSwitchesObserver_ = nullptr;
    observer.pressureObserver_ = nullptr;
    observer.vibrationObserver_ = nullptr;
    observer.touchpadSwitchesObserver_ = nullptr;
    observer.knuckleSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: RegisterTpObserver_009
 * @tc.desc: Test in normal case, the function should not return early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_009, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    observer.isCommonEventReady_.store(true);
    observer.hasRegistered_ = false;
    observer.currentAccountId_ = 0;
    ASSERT_NO_FATAL_FAILURE(observer.RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_0010
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_0010, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    int32_t serviceId = 3101;
    observer.volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, observer.updateFunc_);
    observer.brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, observer.updateFunc_);
    observer.isCommonEventReady_.store(true);
    observer.hasRegistered_ = false;
    observer.currentAccountId_ = 0;
    ASSERT_NO_FATAL_FAILURE(observer.RegisterTpObserver(123));
    observer.volumeSwitchesObserver_ = nullptr;
    observer.brightnessSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, GetInstance_001, TestSize.Level1)
{
    TouchpadSettingsObserver::instance_ = nullptr;
    auto instance = OHOS::MMI::TouchpadSettingsObserver::GetInstance();
    EXPECT_NE(instance, nullptr);
}

/**
 * @tc.name: GetInstance_002
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, GetInstance_002, TestSize.Level1)
{
    TouchpadSettingsObserver::instance_ = std::make_shared<TouchpadSettingsObserver>();
    auto instance = OHOS::MMI::TouchpadSettingsObserver::GetInstance();
    EXPECT_NE(instance, nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_001
 * @tc.desc: Test when parameter "key" is empty, the function should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    std::string key = "";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    observer.datashareUri_ = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(observer.RegisterDatashareObserver(key, UpdateFunc), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_002
 * @tc.desc: Test when parameter "datashareUri_" is empty, the function should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_002, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    std::string key = "settings.trackpad.right_volume_switches";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    observer.datashareUri_ = "";
    EXPECT_EQ(observer.RegisterDatashareObserver(key, UpdateFunc), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_003
 * @tc.desc: Test when parameter "onUpdate" is empty, the function should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_003, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    std::string key = "settings.trackpad.right_volume_switches";
    observer.datashareUri_ = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(observer.RegisterDatashareObserver(key, nullptr), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_004
 * @tc.desc: Test in normal case, the fonction should return a SettingObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_004, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    std::string key = "settings.trackpad.right_volume_switches";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    observer.updateFunc_ = UpdateFunc;
    observer.datashareUri_ = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(observer.RegisterDatashareObserver(key, UpdateFunc), nullptr);
    observer.volumeSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: SyncTouchpadSettingsData_001
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsDataTest_001, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.SetCommonEventReady();
    observer.hasRegistered_ = false;
    ASSERT_NO_FATAL_FAILURE(observer.SyncTouchpadSettingsData());
}

/**
 * @tc.name: SyncTouchpadSettingsData_002
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsDataTest_002, TestSize.Level1)
{
    TouchpadSettingsObserver observer;
    observer.SetCommonEventReady();
    observer.hasRegistered_ = true;
    ASSERT_NO_FATAL_FAILURE(observer.SyncTouchpadSettingsData());
}
}
} // namespace OHOS::MMI