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
const std::string g_touchpadMasterSwitchesKey {"settings.trackpad.touchpad_master_switches"};
const std::string g_keepTouchpadEnableSwitchesKey {"settings.trackpad.keep_touchpad_enable_switches"};
const int32_t RET_ERR { -1 };

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
 * @tc.desc: Test when the observer has already been registered or not ready, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_001, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    EXPECT_FALSE(TOUCHPAD_MGR->RegisterTpObserver(123));
    TOUCHPAD_MGR->isCommonEventReady_.store(false);
    EXPECT_FALSE(TOUCHPAD_MGR->RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_002
 * @tc.desc: Test when the account id is negative, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_002, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    EXPECT_FALSE(TOUCHPAD_MGR->RegisterTpObserver(-1));
}

/**
 * @tc.name: RegisterTpObserver_003
 * @tc.desc: Test when the update function is null, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_003, TestSize.Level1)
{
    TOUCHPAD_MGR->updateFunc_ = nullptr;
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    EXPECT_FALSE(TOUCHPAD_MGR->RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_004
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_004, TestSize.Level1)
{
    bool ret = true;
    SettingObserver::UpdateFunc updateTouchpadSwitchFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateTouchpadSwitchFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateTouchpadSwitchFunc_ = updateTouchpadSwitchFunc;
    EXPECT_NE(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
    int32_t serviceId = 3101;
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadMasterSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_keepTouchpadEnableSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->currentAccountId_ = 0;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->RegisterTpObserver(123));
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: UnregisterTpObserver_001
 * @tc.desc: Test when the observer is not registered, UnregisterTpObserver should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_001, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    EXPECT_FALSE(TOUCHPAD_MGR->UnregisterTpObserver(2));
}

/**
 * @tc.name: UnregisterTpObserver_002
 * @tc.desc: Test when the observer is registered with the same accountId, UnregisterTpObserver should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_002, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    EXPECT_FALSE(TOUCHPAD_MGR->UnregisterTpObserver(1));
}

/**
 * @tc.name: UnregisterTpObserver_003
 * @tc.desc: Test when the observer is registered with a different accountId, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_003, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    EXPECT_TRUE(TOUCHPAD_MGR->UnregisterTpObserver(2));
}

/**
 * @tc.name: UnregisterTpObserver_004
 * @tc.desc: Test when the observer is null, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_004, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->pressureObserver_ = nullptr;
    TOUCHPAD_MGR->vibrationObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_= nullptr;
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = nullptr;
    EXPECT_TRUE(TOUCHPAD_MGR->UnregisterTpObserver(2));
}

/**
 * @tc.name: RegisterUpdateFunc_001
 * @tc.desc: Test if RegisterUpdateFunc sets the updateFunc_ to a non-null value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterUpdateFunc_001, TestSize.Level1)
{
    TOUCHPAD_MGR->RegisterUpdateFunc();
    EXPECT_NE(TOUCHPAD_MGR->updateFunc_, nullptr);
}

/**
 * @tc.name: RegisterTouchpadSwitchUpdateFunc_001
 * @tc.desc: Test if RegisterTouchpadSwitchUpdateFunc sets the updateTouchpadSwitchFunc_ to a non-null value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTouchpadSwitchUpdateFunc_001, TestSize.Level1)
{
    TOUCHPAD_MGR->RegisterUpdateFunc();
    EXPECT_NE(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
}

/**
 * @tc.name: SyncTouchpadSettingsData_001
 * @tc.desc: Test when two updateFunc is null, SyncTouchpadSettingsData should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_001, TestSize.Level1)
{
    TOUCHPAD_MGR->isCommonEventReady_.store(false);
    EXPECT_FALSE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_FALSE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);

    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    TOUCHPAD_MGR->updateFunc_ = nullptr;
    EXPECT_EQ(TOUCHPAD_MGR->updateFunc_, nullptr);
    TOUCHPAD_MGR->updateTouchpadSwitchFunc_ = nullptr;
    EXPECT_EQ(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
    TOUCHPAD_MGR->SyncTouchpadSettingsData();
    EXPECT_FALSE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_FALSE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);
}

/**
 * @tc.name: SyncTouchpadSettingsData_002
 * @tc.desc: Test when the updateFunc_ or updateTouchpadSwitchFunc_ is null, SyncTouchpadSettingsData should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_002, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    bool ret = true;
    SettingObserver::UpdateFunc updateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = updateFunc;
    EXPECT_NE(TOUCHPAD_MGR->updateFunc_, nullptr);
    TOUCHPAD_MGR->updateTouchpadSwitchFunc_ = nullptr;
    EXPECT_EQ(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
    TOUCHPAD_MGR->SyncTouchpadSettingsData();
    EXPECT_FALSE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_FALSE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);

    SettingObserver::UpdateFunc updateTouchpadSwitchFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateTouchpadSwitchFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = nullptr;
    EXPECT_EQ(TOUCHPAD_MGR->updateFunc_, nullptr);
    TOUCHPAD_MGR->updateTouchpadSwitchFunc_ = updateTouchpadSwitchFunc;
    EXPECT_NE(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
    TOUCHPAD_MGR->SyncTouchpadSettingsData();
    EXPECT_FALSE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_FALSE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);
}

/**
 * @tc.name: SyncTouchpadSettingsData_003
 * @tc.desc: Test when the updateFunc_ is null, SyncTouchpadSettingsData should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_003, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    SettingObserver::UpdateFunc updateTouchpadSwitchFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateTouchpadSwitchFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    EXPECT_NE(TOUCHPAD_MGR->updateFunc_, nullptr);
    TOUCHPAD_MGR->updateTouchpadSwitchFunc_ = updateTouchpadSwitchFunc;
    EXPECT_NE(TOUCHPAD_MGR->updateTouchpadSwitchFunc_, nullptr);
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SyncTouchpadSettingsData());
    EXPECT_TRUE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_TRUE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);
}

/**
 * @tc.name: SyncTouchpadSettingsData_004
 * @tc.desc: Test in normal case, SyncTouchpadSettingsData should not return early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsData_004, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    EXPECT_NE(TOUCHPAD_MGR->updateFunc_, nullptr);
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SyncTouchpadSettingsData());
}

/**
 * @tc.name: UnregisterTpObserver_005
 * @tc.desc: Test when the observer is null, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_005, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    int32_t serviceId = 3101;
    TOUCHPAD_MGR->volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadMasterSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_keepTouchpadEnableSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    EXPECT_FALSE(TOUCHPAD_MGR->UnregisterTpObserver(2));
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->pressureObserver_ = nullptr;
    TOUCHPAD_MGR->vibrationObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_= nullptr;
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: UnregisterTpObserver_006
 * @tc.desc: Test when the observer is null, UnregisterTpObserver should return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, UnregisterTpObserver_006, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    int32_t serviceId = 3101;
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->pressureObserver_ = nullptr;
    TOUCHPAD_MGR->vibrationObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadMasterSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = nullptr;
    EXPECT_FALSE(TOUCHPAD_MGR->UnregisterTpObserver(2));

    TOUCHPAD_MGR->hasRegistered_ = true;
    TOUCHPAD_MGR->currentAccountId_ = 1;
    TOUCHPAD_MGR->touchpadMasterSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_keepTouchpadEnableSwitchesKey, TOUCHPAD_MGR->updateTouchpadSwitchFunc_);
    EXPECT_FALSE(TOUCHPAD_MGR->UnregisterTpObserver(2));
    TOUCHPAD_MGR->keepTouchpadEnableSwitchesObserver_= nullptr;
}

/**
 * @tc.name: RegisterTpObserver_006
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_006, TestSize.Level1)
{
    TOUCHPAD_MGR->hasRegistered_ = false;
    int32_t serviceId = 2;
    TOUCHPAD_MGR->pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_008
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_008, TestSize.Level1)
{
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    int32_t serviceId = 3101;
    TOUCHPAD_MGR->volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->pressureObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_pressureKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->vibrationObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_vibrationKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_touchpadSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_knuckleSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->RegisterTpObserver(123));
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->pressureObserver_ = nullptr;
    TOUCHPAD_MGR->vibrationObserver_ = nullptr;
    TOUCHPAD_MGR->touchpadSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->knuckleSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: RegisterTpObserver_009
 * @tc.desc: Test in normal case, the function should not return early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_009, TestSize.Level1)
{
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->currentAccountId_ = 0;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->RegisterTpObserver(123));
}

/**
 * @tc.name: RegisterTpObserver_0010
 * @tc.desc: Test when the observer has already been registered, the function should return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterTpObserver_0010, TestSize.Level1)
{
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    int32_t serviceId = 3101;
    TOUCHPAD_MGR->volumeSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_volumeSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = SettingDataShare::GetInstance(serviceId)
            .CreateObserver(g_brightnessSwitchesKey, TOUCHPAD_MGR->updateFunc_);
    TOUCHPAD_MGR->isCommonEventReady_.store(true);
    TOUCHPAD_MGR->hasRegistered_ = false;
    TOUCHPAD_MGR->currentAccountId_ = 0;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->RegisterTpObserver(123));
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
    TOUCHPAD_MGR->brightnessSwitchesObserver_ = nullptr;
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
    std::string key = "";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    TOUCHPAD_MGR->datashareUri_ =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(TOUCHPAD_MGR->RegisterDatashareObserver(key, UpdateFunc), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_002
 * @tc.desc: Test when parameter "datashareUri_" is empty, the function should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_002, TestSize.Level1)
{
    std::string key = "settings.trackpad.right_volume_switches";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    TOUCHPAD_MGR->datashareUri_ = "";
    EXPECT_EQ(TOUCHPAD_MGR->RegisterDatashareObserver(key, UpdateFunc), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_003
 * @tc.desc: Test when parameter "onUpdate" is empty, the function should return nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_003, TestSize.Level1)
{
    std::string key = "settings.trackpad.right_volume_switches";
    TOUCHPAD_MGR->datashareUri_ =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(TOUCHPAD_MGR->RegisterDatashareObserver(key, nullptr), nullptr);
}

/**
 * @tc.name: RegisterDatashareObserver_004
 * @tc.desc: Test in normal case, the fonction should return a SettingObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, RegisterDatashareObserverTest_004, TestSize.Level1)
{
    std::string key = "settings.trackpad.right_volume_switches";
    bool ret = true;
    SettingObserver::UpdateFunc UpdateFunc = [&ret](const std::string& key) {
        std::cout <<"Test UpdateFunc" << std::endl;
    };
    TOUCHPAD_MGR->updateFunc_ = UpdateFunc;
    TOUCHPAD_MGR->datashareUri_ =
        "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100?Proxy=true";
    EXPECT_EQ(TOUCHPAD_MGR->RegisterDatashareObserver(key, UpdateFunc), nullptr);
    TOUCHPAD_MGR->volumeSwitchesObserver_ = nullptr;
}

/**
 * @tc.name: SyncTouchpadSettingsData_001
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsDataTest_001, TestSize.Level1)
{
    TOUCHPAD_MGR->SetCommonEventReady();
    TOUCHPAD_MGR->hasRegistered_ = false;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SyncTouchpadSettingsData());
}

/**
 * @tc.name: SyncTouchpadSettingsData_002
 * @tc.desc: Test if GetInstance method returns the same singleton instance when called multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SyncTouchpadSettingsDataTest_002, TestSize.Level1)
{
    TOUCHPAD_MGR->SetCommonEventReady();
    TOUCHPAD_MGR->hasRegistered_ = true;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SyncTouchpadSettingsData());
}

/**
 * @tc.name: SetDefaultState_001
 * @tc.desc: Test input different key to SetDefaultState Func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SetDefaultState_001, TestSize.Level1)
{
    std::string key = g_touchpadMasterSwitchesKey;
    std::string value;
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SetDefaultState(key, value));
    EXPECT_TRUE(value == "1");

    key = g_keepTouchpadEnableSwitchesKey;
    value = "";
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SetDefaultState(key, value));
    EXPECT_TRUE(value == "1");

    key = "TEST_KEY";
    value = "TEST_VALUE";
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->SetDefaultState(key, value));
    EXPECT_TRUE(value == "TEST_VALUE");
}

/**
 * @tc.name: LoadSwitchState_001
 * @tc.desc: Test LoadSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, LoadSwitchState_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->LoadSwitchState());
    EXPECT_TRUE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_TRUE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);
}

/**
 * @tc.name: SetTouchpadState_001
 * @tc.desc: Test SetTouchpadState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, SetTouchpadState_001, TestSize.Level1)
{
    TOUCHPAD_MGR->touchpadMasterSwitches_ = false;
    TOUCHPAD_MGR->keepTouchpadEnableSwitches_ = false;
    auto ret = TOUCHPAD_MGR->SetTouchpadState();
    EXPECT_EQ(ret, RET_ERR);
    
    TOUCHPAD_MGR->touchpadMasterSwitches_ = true;
    TOUCHPAD_MGR->keepTouchpadEnableSwitches_ = false;
    ret = TOUCHPAD_MGR->SetTouchpadState();
    EXPECT_EQ(ret, RET_ERR);

    TOUCHPAD_MGR->touchpadMasterSwitches_ = false;
    TOUCHPAD_MGR->keepTouchpadEnableSwitches_ = true;
    ret = TOUCHPAD_MGR->SetTouchpadState();
    EXPECT_EQ(ret, RET_ERR);

    TOUCHPAD_MGR->touchpadMasterSwitches_ = true;
    TOUCHPAD_MGR->keepTouchpadEnableSwitches_ = true;
    ret = TOUCHPAD_MGR->SetTouchpadState();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: OnUpdateTouchpadSwitch_001
 * @tc.desc: Test OnUpdateTouchpadSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchpadSettingsHandlerTest, OnUpdateTouchpadSwitch_001, TestSize.Level1)
{
    ASSERT_NO_FATAL_FAILURE(TOUCHPAD_MGR->OnUpdateTouchpadSwitch());
    EXPECT_TRUE(TOUCHPAD_MGR->touchpadMasterSwitches_);
    EXPECT_TRUE(TOUCHPAD_MGR->keepTouchpadEnableSwitches_);
}
}
} // namespace OHOS::MMI