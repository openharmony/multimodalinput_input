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

#include <fstream>
#include <linux/input.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "joystick_event_processor.h"
#include "joystick_layout_map_builder.h"
#include "libinput_mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickLayoutMapTest"

namespace OHOS {
namespace MMI {
namespace {
char g_cfgName[] { "/data/test/joystick_layout_map_test.json" };
constexpr char CONFIG_BASE_PATH[] {
    "/system/etc/multimodalinput/joystick/layout"
};
constexpr char CONFIG_NAME[] {
    "/system/etc/multimodalinput/joystick/layout/Vendor_054c_Product_05c4.json"
};
constexpr char CONFIG_NAME_VERSION[] {
    "/system/etc/multimodalinput/joystick/layout/Vendor_054c_Product_05c4_Version_8100.json"
};
constexpr char CONFIG_NAME_DEVICE[] {
    "/system/etc/multimodalinput/joystick/layout/BTP-A2P3A_NearLink.json"
};
constexpr std::uintmax_t MAX_SIZE_OF_CONFIG { 4096 };
} // namespace

using namespace testing::ext;
using namespace testing;

class JoystickLayoutMapTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void BuildJoystickLayoutMap103();
    void BuildJoystickLayoutMap104();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildKeyMap001();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildKeyMap002();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildKeyMap003();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildAxisMap001();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildAxisMap002();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildAxisMap003();
    std::unique_ptr<cJSON, std::function<void(cJSON *)>> BuildAxisMap004();
};

void JoystickLayoutMapTest::SetUpTestCase()
{
    std::filesystem::path configPath { "/data/test" };
    if (!std::filesystem::exists(configPath)) {
        std::error_code ec {};
        std::filesystem::create_directory(configPath, ec);
    }
    JoystickLayoutMap::AddConfigBasePath(CONFIG_BASE_PATH);
}

void JoystickLayoutMapTest::TearDownTestCase()
{}

void JoystickLayoutMapTest::SetUp()
{}

void JoystickLayoutMapTest::TearDown()
{
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: Load_001
 * @tc.desc: Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    struct libinput_device device {
        .vendor = 0x54c,
        .product = 0x5c4,
    };
    auto layout = JoystickLayoutMap::Load(&device);

    if (::access(CONFIG_NAME, F_OK) == 0) {
        EXPECT_NE(layout, nullptr);
        if (layout != nullptr) {
            const int32_t rawAxisCode { 5 };
            auto axisInfo = layout->MapAxis(rawAxisCode);
            EXPECT_TRUE(axisInfo);
            if (axisInfo) {
                EXPECT_EQ(axisInfo->mode_, JoystickLayoutMap::AxisMode::AXIS_MODE_NORMAL);
                EXPECT_EQ(axisInfo->axis_, PointerEvent::AXIS_TYPE_ABS_RZ);
            }

            const int32_t rawKeyCode { 312 };
            auto keyInfo = layout->MapKey(rawKeyCode);
            EXPECT_TRUE(keyInfo);
            if (keyInfo) {
                EXPECT_EQ(keyInfo->keyCode_, KeyEvent::KEYCODE_BUTTON_SELECT);
            }
        }
    } else {
        EXPECT_EQ(layout, nullptr);
    }
}

/**
 * @tc.name: Load_002
 * @tc.desc: Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_EQ(layout, nullptr);
}

void JoystickLayoutMapTest::BuildJoystickLayoutMap103()
{
    const std::ofstream::pos_type tailPos { MAX_SIZE_OF_CONFIG };
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs.seekp(tailPos);
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: Load_003
 * @tc.desc: Test Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BuildJoystickLayoutMap103();
    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_EQ(layout, nullptr);
}

void JoystickLayoutMapTest::BuildJoystickLayoutMap104()
{
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: Load_004
 * @tc.desc: Test Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BuildJoystickLayoutMap104();
    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_EQ(layout, nullptr);
}

/**
 * @tc.name: Load_005
 * @tc.desc: Test Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t rawCode { 5 };
    JoystickLayoutMap::AxisInfo axisInfo {
        .axis_ = PointerEvent::AXIS_TYPE_ABS_GAS,
        .flatOverride_ = 4096,
    };
    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.axes_.emplace(rawCode, axisInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_NE(layout, nullptr);
    if (layout != nullptr) {
        auto tAxisInfo = layout->MapAxis(rawCode);
        EXPECT_TRUE(tAxisInfo);
        if (tAxisInfo) {
            EXPECT_EQ(tAxisInfo->mode_, JoystickLayoutMap::AxisMode::AXIS_MODE_NORMAL);
            EXPECT_EQ(tAxisInfo->axis_, PointerEvent::AXIS_TYPE_ABS_GAS);
        }
    }
}

/**
 * @tc.name: Load_006
 * @tc.desc: Test Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t rawCode { 5 };
    constexpr int32_t splitValue { 1024 };
    constexpr int32_t flatOverride { 4096 };

    JoystickLayoutMap::AxisInfo axisInfo {
        .mode_ = JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT,
        .axis_ = PointerEvent::AXIS_TYPE_ABS_GAS,
        .highAxis_ = PointerEvent::AXIS_TYPE_ABS_BRAKE,
        .splitValue_ = splitValue,
        .flatOverride_ = flatOverride,
    };
    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.axes_.emplace(rawCode, axisInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_NE(layout, nullptr);
    if (layout != nullptr) {
        auto tAxisInfo = layout->MapAxis(rawCode);
        EXPECT_TRUE(tAxisInfo);
        if (tAxisInfo) {
            EXPECT_EQ(tAxisInfo->mode_, JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT);
            EXPECT_EQ(tAxisInfo->axis_, PointerEvent::AXIS_TYPE_ABS_GAS);
            EXPECT_EQ(tAxisInfo->highAxis_, PointerEvent::AXIS_TYPE_ABS_BRAKE);
            EXPECT_EQ(tAxisInfo->splitValue_, splitValue);
            EXPECT_EQ(tAxisInfo->flatOverride_, flatOverride);
        }
    }
}

/**
 * @tc.name: Load_007
 * @tc.desc: Test Test JoystickLayoutMap::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, Load_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t rawCode { BTN_THUMBL };

    JoystickLayoutMap::Key keyInfo {
        .keyCode_ = KeyEvent::KEYCODE_BUTTON_THUMBL,
    };
    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.keys_.emplace(rawCode, keyInfo);
    JoystickLayoutMapBuilder::BuildJoystickLayoutMap(layoutMap, g_cfgName);

    auto layout = JoystickLayoutMap::Load(g_cfgName);
    EXPECT_NE(layout, nullptr);
    if (layout != nullptr) {
        auto tKeyInfo = layout->MapKey(rawCode);
        EXPECT_TRUE(tKeyInfo);
        if (tKeyInfo) {
            EXPECT_EQ(tKeyInfo->keyCode_, KeyEvent::KEYCODE_BUTTON_THUMBL);
        }
    }
}

/**
 * @tc.name: MapAxisModeName_001
 * @tc.desc: Test Test JoystickLayoutMap::MapAxisModeName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, MapAxisModeName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t mode { 666 };
    auto sMode = JoystickLayoutMap::MapAxisModeName(static_cast<JoystickLayoutMap::AxisMode>(mode));
    EXPECT_TRUE(sMode.empty());
}

/**
 * @tc.name: FormatConfigName_001
 * @tc.desc: Test Test JoystickLayoutMap::FormatConfigName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, FormatConfigName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    struct libinput_device device {
        .vendor = 0x54c,
        .product = 0x5c4,
        .version = 0x8100,
    };
    auto configName = JoystickLayoutMap::FormatConfigName(&device);

    if (::access(CONFIG_NAME_VERSION, F_OK) == 0) {
        EXPECT_EQ(configName, std::string(CONFIG_NAME_VERSION));
    } else {
        EXPECT_TRUE(configName.empty());
    }
}

/**
 * @tc.name: FormatConfigName_002
 * @tc.desc: Test Test JoystickLayoutMap::FormatConfigName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, FormatConfigName_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(nullptr));

    const std::string expected {
        "/system/etc/multimodalinput/joystick/layout/Vendor_045e_Product_02e0.json" };
    struct libinput_device device {
        .vendor = 0x54c,
        .product = 0x5c4,
        .version = 0xf10f,
    };
    auto configName = JoystickLayoutMap::FormatConfigName(&device);

    if (::access(CONFIG_NAME, F_OK) == 0) {
        EXPECT_EQ(configName, std::string(CONFIG_NAME));
    } else {
        EXPECT_TRUE(configName.empty());
    }
}

/**
 * @tc.name: FormatConfigName_003
 * @tc.desc: Test Test JoystickLayoutMap::FormatConfigName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, FormatConfigName_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    char devName[] { "BTP-A2P3A NearLink" };
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(Return(devName));

    struct libinput_device device {
        .vendor = 0xf45e,
        .product = 0xf2e0,
    };
    auto configName = JoystickLayoutMap::FormatConfigName(&device);

    if (::access(CONFIG_NAME_DEVICE, F_OK) == 0) {
        EXPECT_EQ(configName, std::string(CONFIG_NAME_DEVICE));
    } else {
        EXPECT_TRUE(configName.empty());
    }
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildKeyMap001()
{
    auto jsonKey = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    return jsonKey;
}

/**
 * @tc.name: LoadKeyItem_001
 * @tc.desc: Test Test JoystickLayoutMap::LoadKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadKeyItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonKey = JoystickLayoutMapTest::BuildKeyMap001();
    ASSERT_NE(jsonKey, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadKeyItem(jsonKey.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.keys_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildKeyMap002()
{
    auto jsonKey = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPP(jsonKey);
    auto jsonRawCode = cJSON_CreateNumber(BTN_THUMBL);
    CHKPP(jsonRawCode);
    const char sRawCodeName[] { "RAWCODE" };
    if (!cJSON_AddItemToObject(jsonKey.get(), sRawCodeName, jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return nullptr;
    }
    return jsonKey;
}

/**
 * @tc.name: LoadKeyItem_002
 * @tc.desc: Test Test JoystickLayoutMap::LoadKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadKeyItem_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonKey = JoystickLayoutMapTest::BuildKeyMap002();
    ASSERT_NE(jsonKey, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadKeyItem(jsonKey.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.keys_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildKeyMap003()
{
    auto jsonKey = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPP(jsonKey);
    auto jsonRawCode = cJSON_CreateNumber(BTN_THUMBL);
    CHKPP(jsonRawCode);
    const char sRawCodeName[] { "RAWCODE" };
    if (!cJSON_AddItemToObject(jsonKey.get(), sRawCodeName, jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return nullptr;
    }
    const char sKeyCode[] { "DUMMY" };
    auto jsonKeyCode = cJSON_CreateString(sKeyCode);
    CHKPP(jsonKeyCode);
    const char sKeyCodeName[] { "KEYCODE" };
    if (!cJSON_AddItemToObject(jsonKey.get(), sKeyCodeName, jsonKeyCode)) {
        cJSON_Delete(jsonKeyCode);
        return nullptr;
    }
    return jsonKey;
}

/**
 * @tc.name: LoadKeyItem_003
 * @tc.desc: Test Test JoystickLayoutMap::LoadKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadKeyItem_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonKey = JoystickLayoutMapTest::BuildKeyMap003();
    ASSERT_NE(jsonKey, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadKeyItem(jsonKey.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.keys_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildAxisMap001()
{
    auto jsonAxisItem = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    return jsonAxisItem;
}

/**
 * @tc.name: LoadAxisItem_001
 * @tc.desc: Test Test JoystickLayoutMap::LoadAxisItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadAxisItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonAxisItem = JoystickLayoutMapTest::BuildAxisMap001();
    ASSERT_NE(jsonAxisItem, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadAxisItem(jsonAxisItem.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.axes_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildAxisMap002()
{
    auto jsonAxisItem = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPP(jsonAxisItem);
    auto jsonRawCode = cJSON_CreateNumber(ABS_X);
    CHKPP(jsonRawCode);
    const char sRawCodeName[] { "RAWCODE" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sRawCodeName, jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return nullptr;
    }
    return jsonAxisItem;
}

/**
 * @tc.name: LoadAxisItem_002
 * @tc.desc: Test Test JoystickLayoutMap::LoadAxisItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadAxisItem_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonAxisItem = JoystickLayoutMapTest::BuildAxisMap002();
    ASSERT_NE(jsonAxisItem, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadAxisItem(jsonAxisItem.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.axes_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildAxisMap003()
{
    auto jsonAxisItem = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPP(jsonAxisItem);
    auto jsonRawCode = cJSON_CreateNumber(ABS_X);
    CHKPP(jsonRawCode);
    const char sRawCodeName[] { "RAWCODE" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sRawCodeName, jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return nullptr;
    }
    const char sAxis[] { "X" };
    auto jsonAxis = cJSON_CreateString(sAxis);
    CHKPP(jsonAxis);
    const char sAxisName[] { "AXIS" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sAxisName, jsonAxis)) {
        cJSON_Delete(jsonAxis);
        return nullptr;
    }
    const char sMode[] { "INVERT_SPLIT" };
    auto jsonMode = cJSON_CreateString(sMode);
    CHKPP(jsonMode);
    const char sModeName[] { "MODE" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sModeName, jsonMode)) {
        cJSON_Delete(jsonMode);
        return nullptr;
    }
    return jsonAxisItem;
}

/**
 * @tc.name: LoadAxisItem_003
 * @tc.desc: Test Test JoystickLayoutMap::LoadAxisItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadAxisItem_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonAxisItem = JoystickLayoutMapTest::BuildAxisMap003();
    ASSERT_NE(jsonAxisItem, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadAxisItem(jsonAxisItem.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.axes_.empty());
}

std::unique_ptr<cJSON, std::function<void(cJSON *)>> JoystickLayoutMapTest::BuildAxisMap004()
{
    auto jsonAxisItem = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPP(jsonAxisItem);
    auto jsonRawCode = cJSON_CreateNumber(ABS_X);
    CHKPP(jsonRawCode);
    const char sRawCodeName[] { "RAWCODE" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sRawCodeName, jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return nullptr;
    }
    const char sAxis[] { "X" };
    auto jsonAxis = cJSON_CreateString(sAxis);
    CHKPP(jsonAxis);
    const char sAxisName[] { "AXIS" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sAxisName, jsonAxis)) {
        cJSON_Delete(jsonAxis);
        return nullptr;
    }
    const char sMode[] { "SPLIT" };
    auto jsonMode = cJSON_CreateString(sMode);
    CHKPP(jsonMode);
    const char sModeName[] { "MODE" };
    if (!cJSON_AddItemToObject(jsonAxisItem.get(), sModeName, jsonMode)) {
        cJSON_Delete(jsonAxis);
        return nullptr;
    }
    return jsonAxisItem;
}

/**
 * @tc.name: LoadAxisItem_004
 * @tc.desc: Test Test JoystickLayoutMap::LoadAxisItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickLayoutMapTest, LoadAxisItem_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto jsonAxisItem = JoystickLayoutMapTest::BuildAxisMap004();
    ASSERT_NE(jsonAxisItem, nullptr);

    JoystickLayoutMap layoutMap { g_cfgName };
    layoutMap.OnLoading();
    int32_t index { 66 };
    layoutMap.LoadAxisItem(jsonAxisItem.get(), index);
    layoutMap.OnLoaded();
    EXPECT_TRUE(layoutMap.axes_.empty());
}
} // namespace MMI
} // namespace OHOS
