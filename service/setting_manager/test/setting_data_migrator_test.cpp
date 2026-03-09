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
#include <memory>
#include <string>
#include <vector>
#include <set>

#include "setting_data_migrator.h"
#include "setting_data.h"
#include "setting_types.h"
#include "setting_constants.h"

namespace OHOS {
namespace MMI {
namespace {

using namespace testing;
using namespace testing::ext;

constexpr int32_t TEST_USER_ID_DEFAULT = 100;
constexpr int32_t TEST_USER_ID_SECONDARY = 101;
constexpr int32_t TEST_USER_ID_EMPTY = 0;
constexpr int32_t DEFAULT_MOUSE_SPEED = 5;
constexpr int32_t DEFAULT_SCROLL_ROWS = 3;
constexpr int32_t DEFAULT_TOUCHPAD_SPEED = 5;
constexpr int32_t DEFAULT_KEYBOARD_REPEAT_RATE = 50;
constexpr int32_t DEFAULT_KEYBOARD_REPEAT_DELAY = 500;
constexpr int32_t DEFAULT_POINTER_COLOR = -1;
constexpr int32_t DEFAULT_POINTER_SIZE = 1;
constexpr int32_t DEFAULT_POINTER_STYLE = 0;
constexpr int32_t TOUCHPAD_RIGHT_BUTTON_VALUE = 0;
constexpr int32_t TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT = 1;
constexpr int32_t PRIMARY_BUTTON_DEFAULT = 0;
constexpr int32_t PRIMARY_BUTTON_NON_DEFAULT = 1;

class SettingDataMigratorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void SettingDataMigratorTest::SetUpTestCase(void)
{
}

void SettingDataMigratorTest::TearDownTestCase(void)
{
}

void SettingDataMigratorTest::SetUp(void)
{
}

void SettingDataMigratorTest::TearDown(void)
{
}

} // namespace

/**
 * @tc.name: SettingDataMigrator_Initialize_001
 * @tc.desc: Test Initialize method with valid SettingData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_001, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsSetting(MOUSE_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_002
 * @tc.desc: Test Initialize with empty SettingData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_002, TestSize.Level1)
{
    SettingData data;

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_FALSE(data.ContainsSetting(MOUSE_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_003
 * @tc.desc: Test Initialize with multiple SettingItems
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_003, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(mouseItem);

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    data.AddSettingItem(touchpadItem);

    SettingItem keyboardItem;
    keyboardItem.settingKey = KEYBOARD_KEY_SETTING;
    keyboardItem.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE, DEFAULT_KEYBOARD_REPEAT_RATE);
    data.AddSettingItem(keyboardItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsSetting(MOUSE_KEY_SETTING));
    EXPECT_TRUE(data.ContainsSetting(TOUCHPAD_KEY_SETTING));
    EXPECT_TRUE(data.ContainsSetting(KEYBOARD_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_004
 * @tc.desc: Test Initialize with SettingData containing bool fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_004, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_SCROLL_DIRECTION, false);
    data.AddSettingItem(mouseItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE));
    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_DIRECTION));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_005
 * @tc.desc: Test Initialize with SettingData containing touchpad settings
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_005, TestSize.Level1)
{
    SettingData data;

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_TAP_SWITCH, true);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_SWITCH, true);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_PINCH_SWITCH, true);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_SWIPE_SWITCH, true);
    data.AddSettingItem(touchpadItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_TAP_SWITCH));
    EXPECT_TRUE(data.ContainsField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_SWITCH));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_006
 * @tc.desc: Test Initialize with SettingData containing all mouse fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_006, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_PRIMARY_BUTTON, PRIMARY_BUTTON_DEFAULT);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_COLOR, DEFAULT_POINTER_COLOR);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_SIZE, DEFAULT_POINTER_SIZE);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_STYLE, DEFAULT_POINTER_STYLE);
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_SCROLL_DIRECTION, false);
    data.AddSettingItem(mouseItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t value = 0;
    EXPECT_TRUE(data.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_ROWS, value));
    EXPECT_EQ(value, DEFAULT_SCROLL_ROWS);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_007
 * @tc.desc: Test Initialize twice should replace previous data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_007, TestSize.Level1)
{
    SettingData data1;
    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    item1.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 1);
    data1.AddSettingItem(item1);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data1);

    SettingData data2;
    SettingItem item2;
    item2.settingKey = MOUSE_KEY_SETTING;
    item2.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 10);
    data2.AddSettingItem(item2);

    migrator.Initialize(data2);

    int32_t value = 0;
    EXPECT_TRUE(data2.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, value));
    EXPECT_EQ(value, 10);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_008
 * @tc.desc: Test Initialize with SettingData containing keyboard fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_008, TestSize.Level1)
{
    SettingData data;

    SettingItem keyboardItem;
    keyboardItem.settingKey = KEYBOARD_KEY_SETTING;
    keyboardItem.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE, DEFAULT_KEYBOARD_REPEAT_RATE);
    keyboardItem.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE_DELAY, DEFAULT_KEYBOARD_REPEAT_DELAY);
    data.AddSettingItem(keyboardItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t repeatRate = 0;
    EXPECT_TRUE(data.GetField(KEYBOARD_KEY_SETTING, FIELD_KEYBOARD_REPEAT_RATE, repeatRate));
    EXPECT_EQ(repeatRate, DEFAULT_KEYBOARD_REPEAT_RATE);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_009
 * @tc.desc: Test Initialize with SettingData containing touchpad scroll rows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_009, TestSize.Level1)
{
    SettingData data;

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH, true);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG, true);
    data.AddSettingItem(touchpadItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_ROWS));
    EXPECT_TRUE(data.ContainsField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH));
}

/**
 * @tc.name: SettingDataMigrator_Initialize_010
 * @tc.desc: Test Initialize with SettingData containing touchpad right click type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_010, TestSize.Level1)
{
    SettingData data;

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, TOUCHPAD_RIGHT_BUTTON_VALUE);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_DIRECTION, false);
    data.AddSettingItem(touchpadItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t rightClickType = -1;
    EXPECT_TRUE(data.GetField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, rightClickType));
    EXPECT_EQ(rightClickType, TOUCHPAD_RIGHT_BUTTON_VALUE);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_011
 * @tc.desc: Test Initialize with SettingData containing magic pointer fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_011, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MAGIC_POINTER_COLOR, DEFAULT_POINTER_COLOR);
    mouseItem.fieldPairs.emplace(FIELD_MAGIC_POINTER_SIZE, DEFAULT_POINTER_SIZE);
    data.AddSettingItem(mouseItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t magicColor = 0;
    EXPECT_TRUE(data.GetField(MOUSE_KEY_SETTING, FIELD_MAGIC_POINTER_COLOR, magicColor));
    EXPECT_EQ(magicColor, DEFAULT_POINTER_COLOR);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_012
 * @tc.desc: Test Initialize with SettingData containing touchpad rotate switch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_012, TestSize.Level1)
{
    SettingData data;

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_ROTATE_SWITCH, true);
    data.AddSettingItem(touchpadItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_ROTATE_SWITCH));
}

/**
 * @tc.name: SettingDataMigrator_Migrator_001
 * @tc.desc: Test Migrator method returns false when account list is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Migrator_001, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Migrator_002
 * @tc.desc: Test Migrator method returns false for general case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Migrator_002, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Migrator_003
 * @tc.desc: Test Migrator method with default user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Migrator_003, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Migrator_004
 * @tc.desc: Test Migrator method after Initialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Migrator_004, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Migrator_005
 * @tc.desc: Test Migrator method with all settings initialized
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Migrator_005, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(mouseItem);

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    data.AddSettingItem(touchpadItem);

    SettingItem keyboardItem;
    keyboardItem.settingKey = KEYBOARD_KEY_SETTING;
    keyboardItem.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE, DEFAULT_KEYBOARD_REPEAT_RATE);
    data.AddSettingItem(keyboardItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_001
 * @tc.desc: Test MigratorUserData with valid user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_001, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(TEST_USER_ID_DEFAULT);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_002
 * @tc.desc: Test MigratorUserData with default user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_002, TestSize.Level1)
{
    constexpr int32_t defaultUserId = 100;
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(defaultUserId);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_003
 * @tc.desc: Test MigratorUserData with secondary user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_003, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(TEST_USER_ID_SECONDARY);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_004
 * @tc.desc: Test MigratorUserData with zero user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_004, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(TEST_USER_ID_EMPTY);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_005
 * @tc.desc: Test MigratorUserData with negative user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_005, TestSize.Level1)
{
    constexpr int32_t negativeUserId = -1;
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(negativeUserId);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SettingDataMigrator_Integration_001
 * @tc.desc: Test integration of Initialize and Migrator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Integration_001, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Integration_002
 * @tc.desc: Test integration with all three setting types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Integration_002, TestSize.Level1)
{
    SettingData data;

    SettingItem mouseItem;
    mouseItem.settingKey = MOUSE_KEY_SETTING;
    mouseItem.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(mouseItem);

    SettingItem touchpadItem;
    touchpadItem.settingKey = TOUCHPAD_KEY_SETTING;
    touchpadItem.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    data.AddSettingItem(touchpadItem);

    SettingItem keyboardItem;
    keyboardItem.settingKey = KEYBOARD_KEY_SETTING;
    keyboardItem.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE, DEFAULT_KEYBOARD_REPEAT_RATE);
    data.AddSettingItem(keyboardItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Integration_003
 * @tc.desc: Test integration with multiple user IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Integration_003, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    migrator.MigratorUserData(TEST_USER_ID_DEFAULT);
    migrator.MigratorUserData(TEST_USER_ID_SECONDARY);
    migrator.MigratorUserData(TEST_USER_ID_DEFAULT + 2);
}

/**
 * @tc.name: SettingDataMigrator_Integration_004
 * @tc.desc: Test integration with touchpad settings only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Integration_004, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = TOUCHPAD_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_TAP_SWITCH, true);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_SWITCH, true);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Integration_005
 * @tc.desc: Test integration with keyboard settings only
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Integration_005, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = KEYBOARD_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE, DEFAULT_KEYBOARD_REPEAT_RATE);
    item.fieldPairs.emplace(FIELD_KEYBOARD_REPEAT_RATE_DELAY, DEFAULT_KEYBOARD_REPEAT_DELAY);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.Migrator();

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_SetFields_001
 * @tc.desc: Test SettingData SetField for different types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_001, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(item);

    EXPECT_TRUE(data.SetField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED));
    EXPECT_TRUE(data.SetField(MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, true));

    int32_t speed = 0;
    bool hoverScroll = false;
    EXPECT_TRUE(data.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, speed));
    EXPECT_EQ(speed, DEFAULT_MOUSE_SPEED);
    EXPECT_TRUE(data.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_HOVER_SCROLL_STATE, hoverScroll));
    EXPECT_TRUE(hoverScroll);
}

/**
 * @tc.name: SettingDataMigrator_SetFields_002
 * @tc.desc: Test SettingData ContainsField
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_002, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED));
    EXPECT_FALSE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_TOUCHPAD_POINTER_SPEED));
}

/**
 * @tc.name: SettingDataMigrator_SetFields_003
 * @tc.desc: Test SettingData GetAddFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_003, TestSize.Level1)
{
    SettingData data;
    EXPECT_FALSE(data.GetAddFlag());

    data.SetAddFlag(true);
    EXPECT_TRUE(data.GetAddFlag());

    data.SetAddFlag(false);
    EXPECT_FALSE(data.GetAddFlag());
}

/**
 * @tc.name: SettingDataMigrator_SetFields_004
 * @tc.desc: Test SettingItem Contains method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_004, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);

    EXPECT_TRUE(item.Contains(FIELD_MOUSE_POINTER_SPEED));
    EXPECT_TRUE(item.Contains(FIELD_VERSION));
    EXPECT_FALSE(item.Contains(FIELD_TOUCHPAD_POINTER_SPEED));
}

/**
 * @tc.name: SettingDataMigrator_SetFields_005
 * @tc.desc: Test SettingData GetSettingItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_005, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingItem retrieved = data.GetSettingItem(MOUSE_KEY_SETTING);
    EXPECT_EQ(retrieved.settingKey, MOUSE_KEY_SETTING);
    EXPECT_TRUE(retrieved.Contains(FIELD_MOUSE_POINTER_SPEED));
}

/**
 * @tc.name: SettingDataMigrator_SetFields_006
 * @tc.desc: Test SettingItem ToJson and FromJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_006, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);

    std::string jsonStr = item.ToJson();
    EXPECT_FALSE(jsonStr.empty());

    SettingItem newItem;
    bool parseResult = newItem.FromJson(MOUSE_KEY_SETTING, jsonStr);
    EXPECT_TRUE(parseResult);
    EXPECT_EQ(newItem.settingKey, MOUSE_KEY_SETTING);
}

/**
 * @tc.name: SettingDataMigrator_SetFields_007
 * @tc.desc: Test SettingData ContainsSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_007, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(item);

    EXPECT_TRUE(data.ContainsSetting(MOUSE_KEY_SETTING));
    EXPECT_FALSE(data.ContainsSetting(TOUCHPAD_KEY_SETTING));
    EXPECT_FALSE(data.ContainsSetting(KEYBOARD_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_SetFields_008
 * @tc.desc: Test SettingData GetVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_008, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);
    data.AddSettingItem(item);

    std::string version = data.GetVersion();
    EXPECT_NE(version, VERSION_NUMBERS_LATEST);
}

/**
 * @tc.name: SettingDataMigrator_SetFields_009
 * @tc.desc: Test SettingData MergeFrom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_009, TestSize.Level1)
{
    SettingData data1;
    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    item1.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data1.AddSettingItem(item1);

    SettingData data2;
    SettingItem item2;
    item2.settingKey = TOUCHPAD_KEY_SETTING;
    item2.fieldPairs.emplace(FIELD_TOUCHPAD_POINTER_SPEED, DEFAULT_TOUCHPAD_SPEED);
    data2.AddSettingItem(item2);

    bool result = data1.MergeFrom(data2);
    EXPECT_TRUE(result);
    EXPECT_TRUE(data1.ContainsSetting(TOUCHPAD_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_SetFields_010
 * @tc.desc: Test SettingData MergeExistingItemFrom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SetFields_010, TestSize.Level1)
{
    SettingData data1;
    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    item1.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item1.fieldPairs.emplace(FIELD_MOUSE_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);
    data1.AddSettingItem(item1);

    SettingData data2;
    SettingItem item2;
    item2.settingKey = MOUSE_KEY_SETTING;
    item2.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 10);
    data2.AddSettingItem(item2);

    data1.MergeExistingItemFrom(data2);

    int32_t speed = 0;
    int32_t rows = 0;
    EXPECT_TRUE(data1.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED, speed));
    EXPECT_TRUE(data1.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_ROWS, rows));
}

/**
 * @tc.name: SettingDataMigrator_Constants_001
 * @tc.desc: Test constant values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Constants_001, TestSize.Level1)
{
    EXPECT_EQ(VERSION_NUMBERS_LATEST, "1.0");
    EXPECT_EQ(VERSION_NUMBERS_INITIAL, "0.0");
    EXPECT_EQ(FIELD_VERSION, "version");
}

/**
 * @tc.name: SettingDataMigrator_Constants_002
 * @tc.desc: Test field type sets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Constants_002, TestSize.Level1)
{
    EXPECT_FALSE(SETTING_FIELDS_BOOL.empty());
    EXPECT_FALSE(SETTING_FIELDS_NUM.empty());

    bool foundBoolField = false;
    for (const auto& field : SETTING_FIELDS_BOOL) {
        if (field == FIELD_MOUSE_HOVER_SCROLL_STATE) {
            foundBoolField = true;
            break;
        }
    }
    EXPECT_TRUE(foundBoolField);

    bool foundNumField = false;
    for (const auto& field : SETTING_FIELDS_NUM) {
        if (field == FIELD_MOUSE_POINTER_SPEED) {
            foundNumField = true;
            break;
        }
    }
    EXPECT_TRUE(foundNumField);
}

/**
 * @tc.name: SettingDataMigrator_Constants_003
 * @tc.desc: Test setting keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Constants_003, TestSize.Level1)
{
    EXPECT_TRUE(SETTING_KEYS.find(MOUSE_KEY_SETTING) != SETTING_KEYS.end());
    EXPECT_TRUE(SETTING_KEYS.find(TOUCHPAD_KEY_SETTING) != SETTING_KEYS.end());
    EXPECT_TRUE(SETTING_KEYS.find(KEYBOARD_KEY_SETTING) != SETTING_KEYS.end());
}

/**
 * @tc.name: SettingDataMigrator_Constants_004
 * @tc.desc: Test setting field sets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Constants_004, TestSize.Level1)
{
    EXPECT_FALSE(MOUSE_SETTING_FIELDS.empty());
    EXPECT_FALSE(TOUCHPAD_SETTING_FIELDS.empty());
    EXPECT_FALSE(KEYBOARD_SETTING_FIELDS.empty());

    EXPECT_TRUE(MOUSE_SETTING_FIELDS.find(FIELD_MOUSE_POINTER_SPEED) != MOUSE_SETTING_FIELDS.end());
    EXPECT_TRUE(TOUCHPAD_SETTING_FIELDS.find(FIELD_TOUCHPAD_POINTER_SPEED) != TOUCHPAD_SETTING_FIELDS.end());
    EXPECT_TRUE(KEYBOARD_SETTING_FIELDS.find(FIELD_KEYBOARD_REPEAT_RATE) != KEYBOARD_SETTING_FIELDS.end());
}

/**
 * @tc.name: SettingDataMigrator_Constants_005
 * @tc.desc: Test default user ID constant
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Constants_005, TestSize.Level1)
{
    constexpr int32_t expectedDefaultUserId = 100;
    EXPECT_EQ(SettingConstants::DEFAULT_USER_ID, expectedDefaultUserId);
}

/**
 * @tc.name: SettingDataMigrator_Fields_001
 * @tc.desc: Test mouse field constants
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Fields_001, TestSize.Level1)
{
    EXPECT_EQ(FIELD_MOUSE_SCROLL_ROWS, "rows");
    EXPECT_EQ(FIELD_MOUSE_PRIMARY_BUTTON, "primaryButton");
    EXPECT_EQ(FIELD_MOUSE_POINTER_SPEED, "speed");
    EXPECT_EQ(FIELD_MOUSE_HOVER_SCROLL_STATE, "isEnableHoverScroll");
    EXPECT_EQ(FIELD_MOUSE_POINTER_COLOR, "pointerColor");
    EXPECT_EQ(FIELD_MOUSE_POINTER_SIZE, "pointerSize");
    EXPECT_EQ(FIELD_MOUSE_POINTER_STYLE, "pointerStyle");
    EXPECT_EQ(FIELD_MOUSE_SCROLL_DIRECTION, "scrollDirection");
}

/**
 * @tc.name: SettingDataMigrator_Fields_002
 * @tc.desc: Test touchpad field constants
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Fields_002, TestSize.Level1)
{
    EXPECT_EQ(FIELD_TOUCHPAD_SCROLL_ROWS, "touchpadScrollRows");
    EXPECT_EQ(FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH, "touchpadThreeFingerTap");
    EXPECT_EQ(FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG, "touchpadDoubleTapAndDrag");
    EXPECT_EQ(FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, "rightMenuSwitch");
    EXPECT_EQ(FIELD_TOUCHPAD_POINTER_SPEED, "touchPadPointerSpeed");
    EXPECT_EQ(FIELD_TOUCHPAD_TAP_SWITCH, "touchpadTap");
    EXPECT_EQ(FIELD_TOUCHPAD_SCROLL_DIRECTION, "scrollDirection");
    EXPECT_EQ(FIELD_TOUCHPAD_SCROLL_SWITCH, "scrollSwitch");
    EXPECT_EQ(FIELD_TOUCHPAD_PINCH_SWITCH, "touchpadPinch");
    EXPECT_EQ(FIELD_TOUCHPAD_SWIPE_SWITCH, "touchpadSwipe");
    EXPECT_EQ(FIELD_TOUCHPAD_ROTATE_SWITCH, "touchpadRotate");
}

/**
 * @tc.name: SettingDataMigrator_Fields_003
 * @tc.desc: Test keyboard field constants
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Fields_003, TestSize.Level1)
{
    EXPECT_EQ(FIELD_KEYBOARD_REPEAT_RATE, "keyboardRepeatRate");
    EXPECT_EQ(FIELD_KEYBOARD_REPEAT_RATE_DELAY, "keyboardRepeatDelay");
}

/**
 * @tc.name: SettingDataMigrator_Fields_004
 * @tc.desc: Test magic pointer field constants
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Fields_004, TestSize.Level1)
{
    EXPECT_EQ(FIELD_MAGIC_POINTER_COLOR, "magicPointerColor");
    EXPECT_EQ(FIELD_MAGIC_POINTER_SIZE, "magicPointerSize");
}

/**
 * @tc.name: SettingDataMigrator_FilePaths_001
 * @tc.desc: Test file path constants
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_FilePaths_001, TestSize.Level1)
{
    std::string expectedMousePath = GLOBAL_CONFIG_PATH + "mouse_settings.xml";
    std::string expectedKeyboardPath = GLOBAL_CONFIG_PATH + "keyboard_settings.xml";
    std::string expectedTouchpadPath = GLOBAL_CONFIG_PATH + "touchpad_settings.xml";

    EXPECT_EQ(GLOBAL_MOUSE_FILE_PATH, expectedMousePath);
    EXPECT_EQ(GLOBAL_KEYBOARD_FILE_PATH, expectedKeyboardPath);
    EXPECT_EQ(GLOBAL_TOUCHPAD_FILE_PATH, expectedTouchpadPath);
}

/**
 * @tc.name: SettingDataMigrator_Singleton_001
 * @tc.desc: Test singleton pattern
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Singleton_001, TestSize.Level1)
{
    SettingDataMigrator& instance1 = SettingDataMigrator::GetInstance();
    SettingDataMigrator& instance2 = SettingDataMigrator::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: SettingDataMigrator_ItemMerge_001
 * @tc.desc: Test SettingItem MergeFrom
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_ItemMerge_001, TestSize.Level1)
{
    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    item1.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item1.fieldPairs.emplace(FIELD_MOUSE_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);

    SettingItem item2;
    item2.settingKey = MOUSE_KEY_SETTING;
    item2.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 10);
    item2.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);

    item1.MergeFrom(item2);

    EXPECT_TRUE(item1.Contains(FIELD_MOUSE_POINTER_SPEED));
    EXPECT_TRUE(item1.Contains(FIELD_MOUSE_SCROLL_ROWS));
    EXPECT_TRUE(item1.Contains(FIELD_MOUSE_HOVER_SCROLL_STATE));
}

/**
 * @tc.name: SettingDataMigrator_Serialize_001
 * @tc.desc: Test SettingData SerializeToJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Serialize_001, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);
    data.AddSettingItem(item);

    std::string jsonOutput;
    bool result = data.SerializeToJson(MOUSE_KEY_SETTING, jsonOutput);

    EXPECT_TRUE(result);
    EXPECT_FALSE(jsonOutput.empty());
}

/**
 * @tc.name: SettingDataMigrator_Serialize_002
 * @tc.desc: Test SettingData SerializeToJson for non-existent key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Serialize_002, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(item);

    std::string jsonOutput;
    bool result = data.SerializeToJson(TOUCHPAD_KEY_SETTING, jsonOutput);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SettingDataMigrator_GetItems_001
 * @tc.desc: Test SettingData GetSettingItems
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_GetItems_001, TestSize.Level1)
{
    SettingData data;

    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(item1);

    SettingItem item2;
    item2.settingKey = TOUCHPAD_KEY_SETTING;
    data.AddSettingItem(item2);

    auto items = data.GetSettingItems();
    EXPECT_EQ(items.size(), 2);
}

/**
 * @tc.name: SettingDataMigrator_GetItems_002
 * @tc.desc: Test SettingData GetSettingItems with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_GetItems_002, TestSize.Level1)
{
    SettingData data;
    auto items = data.GetSettingItems();
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: SettingDataMigrator_FieldTypes_001
 * @tc.desc: Test different field value types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_FieldTypes_001, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);

    EXPECT_TRUE(item.Contains(FIELD_MOUSE_POINTER_SPEED));
    EXPECT_TRUE(item.Contains(FIELD_MOUSE_HOVER_SCROLL_STATE));
    EXPECT_TRUE(item.Contains(FIELD_VERSION));
}

/**
 * @tc.name: SettingDataMigrator_MaxUserId_001
 * @tc.desc: Test with maximum user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MaxUserId_001, TestSize.Level1)
{
    constexpr int32_t maxUserId = SettingConstants::MAX_USER_ID;
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(maxUserId);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_SequentialCalls_001
 * @tc.desc: Test sequential MigratorUserData calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SequentialCalls_001, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();

    bool result1 = migrator.MigratorUserData(TEST_USER_ID_DEFAULT);
    EXPECT_TRUE(result1);

    bool result2 = migrator.MigratorUserData(TEST_USER_ID_SECONDARY);
    EXPECT_TRUE(result2);

    bool result3 = migrator.MigratorUserData(TEST_USER_ID_DEFAULT + 2);
    EXPECT_TRUE(result3);
}

/**
 * @tc.name: SettingDataMigrator_ConcurrentInitialize_001
 * @tc.desc: Test multiple Initialize calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_ConcurrentInitialize_001, TestSize.Level1)
{
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();

    SettingData data1;
    SettingItem item1;
    item1.settingKey = MOUSE_KEY_SETTING;
    item1.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 1);
    data1.AddSettingItem(item1);
    migrator.Initialize(data1);

    SettingData data2;
    SettingItem item2;
    item2.settingKey = MOUSE_KEY_SETTING;
    item2.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 2);
    data2.AddSettingItem(item2);
    migrator.Initialize(data2);

    SettingData data3;
    SettingItem item3;
    item3.settingKey = MOUSE_KEY_SETTING;
    item3.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, 3);
    data3.AddSettingItem(item3);
    migrator.Initialize(data3);

    EXPECT_TRUE(data3.ContainsSetting(MOUSE_KEY_SETTING));
}

/**
 * @tc.name: SettingDataMigrator_ComplexFields_001
 * @tc.desc: Test with all touchpad boolean fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_ComplexFields_001, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = TOUCHPAD_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_TOUCHPAD_TAP_SWITCH, true);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_SWITCH, false);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_PINCH_SWITCH, true);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_SWIPE_SWITCH, false);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH, true);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG, true);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_SCROLL_DIRECTION, false);
    item.fieldPairs.emplace(FIELD_TOUCHPAD_ROTATE_SWITCH, true);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool tapSwitch = false;
    bool scrollSwitch = true;
    EXPECT_TRUE(data.GetField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_TAP_SWITCH, tapSwitch));
    EXPECT_TRUE(tapSwitch);
    EXPECT_TRUE(data.GetField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_SCROLL_SWITCH, scrollSwitch));
    EXPECT_FALSE(scrollSwitch);
}

/**
 * @tc.name: SettingDataMigrator_ComplexFields_002
 * @tc.desc: Test with all mouse fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_ComplexFields_002, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);
    item.fieldPairs.emplace(FIELD_MOUSE_PRIMARY_BUTTON, PRIMARY_BUTTON_DEFAULT);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_COLOR, DEFAULT_POINTER_COLOR);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SIZE, DEFAULT_POINTER_SIZE);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_STYLE, DEFAULT_POINTER_STYLE);
    item.fieldPairs.emplace(FIELD_MOUSE_SCROLL_DIRECTION, false);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_SCROLL_ROWS));
    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_PRIMARY_BUTTON));
    EXPECT_TRUE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED));
}

/**
 * @tc.name: SettingDataMigrator_Variant_001
 * @tc.desc: Test FieldValue variant type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Variant_001, TestSize.Level1)
{
    FieldValue intVal = DEFAULT_MOUSE_SPEED;
    FieldValue boolVal = true;
    FieldValue strVal = VERSION_NUMBERS_LATEST;

    int32_t retrievedInt = std::get<int32_t>(intVal);
    EXPECT_EQ(retrievedInt, DEFAULT_MOUSE_SPEED);

    bool retrievedBool = std::get<bool>(boolVal);
    EXPECT_TRUE(retrievedBool);

    std::string retrievedStr = std::get<std::string>(strVal);
    EXPECT_EQ(retrievedStr, VERSION_NUMBERS_LATEST);
}

/**
 * @tc.name: SettingDataMigrator_EmptyItems_001
 * @tc.desc: Test SettingData with empty SettingItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_EmptyItems_001, TestSize.Level1)
{
    SettingData data;
    SettingItem emptyItem;
    emptyItem.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(emptyItem);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    EXPECT_TRUE(data.ContainsSetting(MOUSE_KEY_SETTING));
    EXPECT_FALSE(data.ContainsField(MOUSE_KEY_SETTING, FIELD_MOUSE_POINTER_SPEED));
}

/**
 * @tc.name: SettingDataMigrator_EmptyItems_002
 * @tc.desc: Test GetSettingItem with non-existent key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_EmptyItems_002, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    data.AddSettingItem(item);

    SettingItem retrieved = data.GetSettingItem(TOUCHPAD_KEY_SETTING);
    EXPECT_TRUE(retrieved.fieldPairs.empty());
}

/**
 * @tc.name: SettingDataMigrator_Version_001
 * @tc.desc: Test version field handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Version_001, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_INITIAL);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);

    EXPECT_TRUE(item.Contains(FIELD_VERSION));

    std::string version = std::get<std::string>(item.fieldPairs.at(FIELD_VERSION));
    EXPECT_EQ(version, VERSION_NUMBERS_INITIAL);
}

/**
 * @tc.name: SettingDataMigrator_Version_002
 * @tc.desc: Test version field update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Version_002, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_INITIAL);

    item.fieldPairs[FIELD_VERSION] = VERSION_NUMBERS_LATEST;

    std::string version = std::get<std::string>(item.fieldPairs.at(FIELD_VERSION));
    EXPECT_EQ(version, VERSION_NUMBERS_LATEST);
}

/**
 * @tc.name: SettingDataMigrator_MultipleFields_001
 * @tc.desc: Test SettingItem with many fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MultipleFields_001, TestSize.Level1)
{
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_SCROLL_ROWS, DEFAULT_SCROLL_ROWS);
    item.fieldPairs.emplace(FIELD_MOUSE_PRIMARY_BUTTON, PRIMARY_BUTTON_DEFAULT);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    item.fieldPairs.emplace(FIELD_MOUSE_HOVER_SCROLL_STATE, true);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_COLOR, DEFAULT_POINTER_COLOR);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SIZE, DEFAULT_POINTER_SIZE);
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_STYLE, DEFAULT_POINTER_STYLE);
    item.fieldPairs.emplace(FIELD_MOUSE_SCROLL_DIRECTION, false);
    item.fieldPairs.emplace(FIELD_MAGIC_POINTER_COLOR, DEFAULT_POINTER_COLOR);
    item.fieldPairs.emplace(FIELD_MAGIC_POINTER_SIZE, DEFAULT_POINTER_SIZE);

    EXPECT_EQ(item.fieldPairs.size(), 10);
}

/**
 * @tc.name: SettingDataMigrator_SettingKeys_001
 * @tc.desc: Test SETTING_KEYS constant
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_SettingKeys_001, TestSize.Level1)
{
    EXPECT_EQ(SETTING_KEYS.size(), 3);
    EXPECT_TRUE(SETTING_KEYS.count(MOUSE_KEY_SETTING) > 0);
    EXPECT_TRUE(SETTING_KEYS.count(TOUCHPAD_KEY_SETTING) > 0);
    EXPECT_TRUE(SETTING_KEYS.count(KEYBOARD_KEY_SETTING) > 0);
}

/**
 * @tc.name: SettingDataMigrator_TouchpadFields_001
 * @tc.desc: Test TOUCHPAD_SETTING_FIELDS completeness
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_TouchpadFields_001, TestSize.Level1)
{
    EXPECT_GE(TOUCHPAD_SETTING_FIELDS.size(), 8);

    EXPECT_TRUE(TOUCHPAD_SETTING_FIELDS.count(FIELD_TOUCHPAD_SCROLL_ROWS));
    EXPECT_TRUE(TOUCHPAD_SETTING_FIELDS.count(FIELD_TOUCHPAD_POINTER_SPEED));
    EXPECT_TRUE(TOUCHPAD_SETTING_FIELDS.count(FIELD_TOUCHPAD_RIGHT_CLICK_TYPE));
    EXPECT_TRUE(TOUCHPAD_SETTING_FIELDS.count(FIELD_TOUCHPAD_TAP_SWITCH));
}

/**
 * @tc.name: SettingDataMigrator_MouseFields_001
 * @tc.desc: Test MOUSE_SETTING_FIELDS completeness
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MouseFields_001, TestSize.Level1)
{
    EXPECT_GE(MOUSE_SETTING_FIELDS.size(), 7);

    EXPECT_TRUE(MOUSE_SETTING_FIELDS.count(FIELD_MOUSE_SCROLL_ROWS));
    EXPECT_TRUE(MOUSE_SETTING_FIELDS.count(FIELD_MOUSE_PRIMARY_BUTTON));
    EXPECT_TRUE(MOUSE_SETTING_FIELDS.count(FIELD_MOUSE_POINTER_SPEED));
    EXPECT_TRUE(MOUSE_SETTING_FIELDS.count(FIELD_MOUSE_HOVER_SCROLL_STATE));
}

/**
 * @tc.name: SettingDataMigrator_KeyboardFields_001
 * @tc.desc: Test KEYBOARD_SETTING_FIELDS completeness
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_KeyboardFields_001, TestSize.Level1)
{
    EXPECT_EQ(KEYBOARD_SETTING_FIELDS.size(), 2);

    EXPECT_TRUE(KEYBOARD_SETTING_FIELDS.count(FIELD_KEYBOARD_REPEAT_RATE));
    EXPECT_TRUE(KEYBOARD_SETTING_FIELDS.count(FIELD_KEYBOARD_REPEAT_RATE_DELAY));
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_006
 * @tc.desc: Test MigratorUserData with large user ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_006, TestSize.Level1)
{
    constexpr int32_t largeUserId = 9999;
    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    bool result = migrator.MigratorUserData(largeUserId);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_MigratorUserData_007
 * @tc.desc: Test MigratorUserData after Initialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_MigratorUserData_007, TestSize.Level1)
{
    SettingData data;
    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_POINTER_SPEED, DEFAULT_MOUSE_SPEED);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    bool result = migrator.MigratorUserData(TEST_USER_ID_DEFAULT);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_013
 * @tc.desc: Test Initialize with SettingData containing primary button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_013, TestSize.Level1)
{
    SettingData data;

    SettingItem item;
    item.settingKey = MOUSE_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_MOUSE_PRIMARY_BUTTON, PRIMARY_BUTTON_NON_DEFAULT);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t primaryButton = -1;
    EXPECT_TRUE(data.GetField(MOUSE_KEY_SETTING, FIELD_MOUSE_PRIMARY_BUTTON, primaryButton));
    EXPECT_EQ(primaryButton, PRIMARY_BUTTON_NON_DEFAULT);
}

/**
 * @tc.name: SettingDataMigrator_Initialize_014
 * @tc.desc: Test Initialize with touchpad right click type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SettingDataMigratorTest, SettingDataMigrator_Initialize_014, TestSize.Level1)
{
    SettingData data;

    SettingItem item;
    item.settingKey = TOUCHPAD_KEY_SETTING;
    item.fieldPairs.emplace(FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT);
    data.AddSettingItem(item);

    SettingDataMigrator& migrator = SettingDataMigrator::GetInstance();
    migrator.Initialize(data);

    int32_t rightClickType = -1;
    EXPECT_TRUE(data.GetField(TOUCHPAD_KEY_SETTING, FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, rightClickType));
    EXPECT_EQ(rightClickType, TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT);
}

} // namespace MMI
} // namespace OHOS
