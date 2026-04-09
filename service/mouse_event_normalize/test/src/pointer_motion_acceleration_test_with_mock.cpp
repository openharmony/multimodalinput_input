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

#include <fcntl.h>
#include <fstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "define_multimodal.h"
#include "ffrt.h"
#include "pointer_motion_acceleration.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerMotionAccelerationTestWithMock"

namespace OHOS {
namespace MMI {
namespace {
char g_cfgName[] { "/system/etc/multimodalinput/pointer_motion_acceleration_config.json" };
char g_testName[] { "pointer_motion_acceleration_test_config.json" };
char g_dumpName[] { "pointer_motion_acceleration_dump.txt" };
} // namespace
using namespace testing;
using namespace testing::ext;

class PointerMotionAccelerationTestWithMock : public testing::Test {
public:
    void SetUp();
    void TearDown() {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

private:
    void DumpPointerMotionAccelerationConfig();
};

void PointerMotionAccelerationTestWithMock::SetUp()
{
    PointerMotionAcceleration::dynamicMouseCurve_.reset();
    PointerMotionAcceleration::dynamicTouchpadCurve_.reset();
    PointerMotionAcceleration::curves_.clear();
}

void PointerMotionAccelerationTestWithMock::DumpPointerMotionAccelerationConfig()
{
    auto fd = ::open(g_dumpName, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        std::vector<std::string> args;
        PointerMotionAcceleration::Dump(fd, args);
        ::close(fd);
    }
}

/**
 * @tc.name: DynamicAccelerateMouse_001
 * @tc.desc: Test PointerMotionAcceleration::DynamicAccelerateMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateMouse_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { true };
    size_t speed { 5 };
    uint64_t deltaTime { 5 };
    double displayPPI { 2.0 };
    double factor { 1.0 };
    double absX {};
    double absY {};

    auto ret = PointerMotionAcceleration::DynamicAccelerateMouse(
        offset, mode, speed, deltaTime, displayPPI, factor, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateMouse_002
 * @tc.desc: Test PointerMotionAcceleration::DynamicAccelerateMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateMouse_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { false };
    size_t speed { 5 };
    uint64_t deltaTime { 5 };
    double displayPPI { 2.0 };
    double factor { 1.0 };
    double absX {};
    double absY {};

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadDynamicMouseCurve);
    auto ret = PointerMotionAcceleration::DynamicAccelerateMouse(
        offset, mode, speed, deltaTime, displayPPI, factor, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpad_001
 * @tc.desc: Test PointerMotionAcceleration::DynamicAccelerateTouchpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpad_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { true };
    int32_t frequency { 1 };
    size_t speed { 5 };
    double displaySize { 2.0 };
    double touchpadSize { 2.0 };
    double touchpadPPI { 1.0 };
    double absX {};
    double absY {};

    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpad(
        offset, mode, speed, displaySize, touchpadSize, touchpadPPI, frequency, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpad_002
 * @tc.desc: Test PointerMotionAcceleration::DynamicAccelerateMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpad_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { false };
    int32_t frequency { 1 };
    size_t speed { 5 };
    double displaySize { 2.0 };
    double touchpadSize { 2.0 };
    double touchpadPPI { 1.0 };
    double absX {};
    double absY {};

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadDynamicTouchpadCurve);
    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpad(
        offset, mode, speed, displaySize, touchpadSize, touchpadPPI, frequency, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AccelerateMouse_001
 * @tc.desc: Test PointerMotionAcceleration::AccelerateMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AccelerateMouse_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { true };
    size_t speed { 5 };
    DeviceType deviceType { DeviceType::DEVICE_PC };
    double absX {};
    double absY {};

    auto ret = PointerMotionAcceleration::AccelerateMouse(offset, mode, speed, deviceType, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AccelerateMouse_002
 * @tc.desc: Test PointerMotionAcceleration::AccelerateMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AccelerateMouse_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { false };
    size_t speed { 5 };
    DeviceType deviceType { DeviceType::DEVICE_PC };
    double absX {};
    double absY {};

    auto name = PointerMotionAcceleration::GetMouseConfigName(deviceType);
    PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
        return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
    });
    auto ret = PointerMotionAcceleration::AccelerateMouse(offset, mode, speed, deviceType, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AccelerateTouchpad_001
 * @tc.desc: Test PointerMotionAcceleration::AccelerateTouchpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AccelerateTouchpad_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { true };
    size_t speed { 5 };
    DeviceType deviceType { DeviceType::DEVICE_PC };
    double absX {};
    double absY {};

    auto ret = PointerMotionAcceleration::AccelerateTouchpad(offset, mode, speed, deviceType, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: AccelerateTouchpad_002
 * @tc.desc: Test PointerMotionAcceleration::AccelerateTouchpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AccelerateTouchpad_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    const Offset offset { 10, 10 };
    bool mode { false };
    size_t speed { 5 };
    DeviceType deviceType { DeviceType::DEVICE_PC };
    double absX {};
    double absY {};

    auto name = PointerMotionAcceleration::GetTouchpadConfigName(deviceType);
    PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
        return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
    });
    auto ret = PointerMotionAcceleration::AccelerateTouchpad(offset, mode, speed, deviceType, absX, absY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test PointerMotionAcceleration::Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, Dump_001, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadDynamicMouseCurve);
    DumpPointerMotionAccelerationConfig();

    std::vector<std::string> expected {
        "Pointer acceleration curves:",
        "\tPointer acceleration curves (MouseDynamic) {",
        "\t\tDynamic mouse acceleration curve {",
        "\t\t\tspeeds: [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8,1.9,2.0]",
    };
    std::ifstream fs(g_dumpName);
    EXPECT_TRUE(fs.is_open());
    if (fs.is_open()) {
        std::string line;
        for (const auto &str : expected) {
            EXPECT_TRUE(std::getline(fs, line));
        }
    }
}

/**
 * @tc.name: LoadAccelerationConfig_001
 * @tc.desc: Test PointerMotionAcceleration::LoadAccelerationConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, LoadAccelerationConfig_001, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_testName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    auto name = PointerMotionAcceleration::GetMouseConfigName(DeviceType::DEVICE_PC);
    PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
        return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
    });
    EXPECT_TRUE(PointerMotionAcceleration::curves_.empty());
}

/**
 * @tc.name: LoadAccelerationConfig_002
 * @tc.desc: Test PointerMotionAcceleration::LoadAccelerationConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, LoadAccelerationConfig_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    const std::string name { "Unknown" };
    PointerMotionAcceleration::LoadAccelerationConfig([name](const char *cfgPath, cJSON *jsonCfg) {
        return PointerMotionAcceleration::LoadAccelerationCurve(cfgPath, jsonCfg, name);
    });
    EXPECT_TRUE(PointerMotionAcceleration::curves_.empty());
}

/**
 * @tc.name: AxisCurve_IsValid_001
 * @tc.desc: Test AxisCurve::IsValid with valid curve
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AxisCurve_IsValid_001, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 2.0, 3.0};
    curve.slopes = {1.0, 2.0, 3.0};
    curve.diffNums = {0.0, 0.1, 0.2};
    EXPECT_TRUE(curve.IsValid());
}

/**
 * @tc.name: AxisCurve_IsValid_002
 * @tc.desc: Test AxisCurve::IsValid with empty speeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AxisCurve_IsValid_002, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {};
    curve.slopes = {1.0, 2.0};
    curve.diffNums = {0.0, 0.1};
    EXPECT_FALSE(curve.IsValid());
}

/**
 * @tc.name: AxisCurve_IsValid_003
 * @tc.desc: Test AxisCurve::IsValid with empty slopes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AxisCurve_IsValid_003, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 2.0};
    curve.slopes = {};
    curve.diffNums = {0.0, 0.1};
    EXPECT_FALSE(curve.IsValid());
}

/**
 * @tc.name: AxisCurve_IsValid_004
 * @tc.desc: Test AxisCurve::IsValid with empty diffNums
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, AxisCurve_IsValid_004, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 2.0};
    curve.slopes = {1.0, 2.0};
    curve.diffNums = {};
    EXPECT_FALSE(curve.IsValid());
}

/**
 * @tc.name: DynamicAccelerateTouchpadAxis_001
 * @tc.desc: Test DynamicAccelerateTouchpadAxis with empty axisCurves_
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpadAxis_001, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    double axisSpeed = 5.0;
    bool mode = true;
    DeviceType deviceType = DeviceType::DEVICE_PC;

    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, deviceType);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpadAxis_002
 * @tc.desc: Test DynamicAccelerateTouchpadAxis with loaded curves, mode=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpadAxis_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);

    double axisSpeed = 5.0;
    bool mode = true;
    DeviceType deviceType = DeviceType::DEVICE_PC;

    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, deviceType);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpadAxis_003
 * @tc.desc: Test DynamicAccelerateTouchpadAxis with mode=false (negative axisSpeed)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpadAxis_003, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);

    double axisSpeed = -5.0;
    bool mode = false;
    DeviceType deviceType = DeviceType::DEVICE_PC;

    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, deviceType);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpadAxis_004
 * @tc.desc: Test DynamicAccelerateTouchpadAxis with different device types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpadAxis_004, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);

    double axisSpeed = 5.0;
    bool mode = true;

    auto ret1 = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, DeviceType::DEVICE_PC);
    EXPECT_EQ(ret1, RET_OK);

    auto ret2 = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, static_cast<DeviceType>(99));
    EXPECT_EQ(ret2, RET_OK);

    auto ret3 = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, DeviceType::DEVICE_FOLD_PC);
    EXPECT_EQ(ret3, RET_OK);

    auto ret4 = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode,
        DeviceType::DEVICE_FOLD_PC_VIRT);
    EXPECT_EQ(ret4, RET_OK);
}

/**
 * @tc.name: DynamicAccelerateTouchpadAxis_005
 * @tc.desc: Test DynamicAccelerateTouchpadAxis with zero axisSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, DynamicAccelerateTouchpadAxis_005, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);

    double axisSpeed = 0.0;
    bool mode = true;
    DeviceType deviceType = DeviceType::DEVICE_PC;

    auto ret = PointerMotionAcceleration::DynamicAccelerateTouchpadAxis(axisSpeed, mode, deviceType);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MatchAxisCurve_001
 * @tc.desc: Test MatchAxisCurve with valid device types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_001, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);

    PointerMotionAcceleration::AxisCurveCollection curves;
    PointerMotionAcceleration::AxisCurve curve1, curve2, curve3;
    curve1.speeds = {1.0}; curve1.slopes = {1.0}; curve1.diffNums = {0.0};
    curve2.speeds = {2.0}; curve2.slopes = {2.0}; curve2.diffNums = {0.0};
    curve3.speeds = {3.0}; curve3.slopes = {3.0}; curve3.diffNums = {0.0};
    curves.push_back(curve1);
    curves.push_back(curve2);
    curves.push_back(curve3);

    auto result1 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_PC);
    EXPECT_NE(result1, nullptr);

    auto result2 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_FOLD_PC);
    EXPECT_NE(result2, nullptr);

    auto result3 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_FOLD_PC_VIRT);
    EXPECT_NE(result3, nullptr);
}

/**
 * @tc.name: MatchAxisCurve_002
 * @tc.desc: Test MatchAxisCurve with invalid device type (fallback to last)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_002, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurveCollection curves;
    PointerMotionAcceleration::AxisCurve curve1, curve2;
    curve1.speeds = {1.0}; curve1.slopes = {1.0}; curve1.diffNums = {0.0};
    curve2.speeds = {2.0}; curve2.slopes = {2.0}; curve2.diffNums = {0.0};
    curves.push_back(curve1);
    curves.push_back(curve2);

    auto result = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_UNKNOWN);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: MatchAxisCurve_003
 * @tc.desc: Test MatchAxisCurve with DEVICE_SOFT_PC_PRO and DEVICE_HARD_PC_PRO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_003, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurveCollection curves;
    for (int i = 0; i < 10; ++i) {
        PointerMotionAcceleration::AxisCurve curve;
        curve.speeds = {static_cast<double>(i + 1)};
        curve.slopes = {static_cast<double>(i + 1)};
        curve.diffNums = {0.0};
        curves.push_back(curve);
    }

    auto result1 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_SOFT_PC_PRO);
    EXPECT_NE(result1, nullptr);

    auto result2 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_HARD_PC_PRO);
    EXPECT_NE(result2, nullptr);
}

/**
 * @tc.name: MatchAxisCurve_004
 * @tc.desc: Test MatchAxisCurve with DEVICE_TABLET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_004, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurveCollection curves;
    for (int i = 0; i < 10; ++i) {
        PointerMotionAcceleration::AxisCurve curve;
        curve.speeds = {static_cast<double>(i + 1)};
        curve.slopes = {static_cast<double>(i + 1)};
        curve.diffNums = {0.0};
        curves.push_back(curve);
    }

    auto result = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_TABLET);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: MatchAxisCurve_005
 * @tc.desc: Test MatchAxisCurve with DEVICE_M_TABLET, DEVICE_Q_TABLET, DEVICE_G_TABLET
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_005, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurveCollection curves;
    for (int i = 0; i < 10; ++i) {
        PointerMotionAcceleration::AxisCurve curve;
        curve.speeds = {static_cast<double>(i + 1)};
        curve.slopes = {static_cast<double>(i + 1)};
        curve.diffNums = {0.0};
        curves.push_back(curve);
    }

    auto result1 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_M_TABLET);
    EXPECT_NE(result1, nullptr);

    auto result2 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_Q_TABLET);
    EXPECT_NE(result2, nullptr);

    auto result3 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_G_TABLET);
    EXPECT_NE(result3, nullptr);
}

/**
 * @tc.name: MatchAxisCurve_006
 * @tc.desc: Test MatchAxisCurve with DEVICE_M_PC and DEVICE_M_PC_PRO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, MatchAxisCurve_006, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurveCollection curves;
    for (int i = 0; i < 10; ++i) {
        PointerMotionAcceleration::AxisCurve curve;
        curve.speeds = {static_cast<double>(i + 1)};
        curve.slopes = {static_cast<double>(i + 1)};
        curve.diffNums = {0.0};
        curves.push_back(curve);
    }

    auto result1 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_M_PC);
    EXPECT_NE(result1, nullptr);

    auto result2 = PointerMotionAcceleration::MatchAxisCurve(curves, DeviceType::DEVICE_M_PC_PRO);
    EXPECT_NE(result2, nullptr);
}

/**
 * @tc.name: LoadAxisCurve_001
 * @tc.desc: Test LoadAxisCurve with valid config
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, LoadAxisCurve_001, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);
    EXPECT_TRUE(PointerMotionAcceleration::axisCurves_.has_value());
}

/**
 * @tc.name: LoadAxisCurve_002
 * @tc.desc: Test LoadAxisCurve with invalid config path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, LoadAxisCurve_002, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::axisCurves_.reset();
    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);
    EXPECT_FALSE(PointerMotionAcceleration::axisCurves_.has_value());
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Test Dump with axisCurves_ loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, Dump_002, TestSize.Level1)
{
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);
    DumpPointerMotionAccelerationConfig();

    std::ifstream fs(g_dumpName);
    EXPECT_TRUE(fs.is_open());
    if (fs.is_open()) {
        std::string line;
        bool foundAxis = false;
        while (std::getline(fs, line)) {
            if (line.find("Axis accelerate curves") != std::string::npos) {
                foundAxis = true;
                break;
            }
        }
        EXPECT_TRUE(foundAxis);
    }
}

/**
 * @tc.name: Dump_003
 * @tc.desc: Test Dump with only axisCurves_ (no other curves)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, Dump_003, TestSize.Level1)
{
    PointerMotionAcceleration::dynamicMouseCurve_.reset();
    PointerMotionAcceleration::dynamicTouchpadCurve_.reset();
    PointerMotionAcceleration::curves_.clear();
    PointerMotionAcceleration::axisCurves_.reset();

    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(Return(&cfgFiles)).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);
    DumpPointerMotionAccelerationConfig();

    std::ifstream fs(g_dumpName);
    EXPECT_TRUE(fs.is_open());
    if (fs.is_open()) {
        std::string line;
        bool foundAxis = false;
        while (std::getline(fs, line)) {
            if (line.find("Axis accelerate curves") != std::string::npos) {
                foundAxis = true;
                break;
            }
        }
        EXPECT_TRUE(foundAxis);
    }
}

/**
 * @tc.name: CalcAxisGainTouchpad_001
 * @tc.desc: Test CalcAxisGainTouchpad with valid curve and speed within range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_001, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 5.0, 10.0};
    curve.slopes = {1.0, 0.8, 0.5};
    curve.diffNums = {0.0, 0.2, 0.5};

    double axisSpeed = 3.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_TRUE(ret);
    EXPECT_GT(gain, 0.0);
}

/**
 * @tc.name: CalcAxisGainTouchpad_002
 * @tc.desc: Test CalcAxisGainTouchpad with speed exceeding all speeds (fallback to last)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_002, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 5.0, 10.0};
    curve.slopes = {1.0, 0.8, 0.5};
    curve.diffNums = {0.0, 0.2, 0.5};

    double axisSpeed = 100.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CalcAxisGainTouchpad_003
 * @tc.desc: Test CalcAxisGainTouchpad with empty speeds (error path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_003, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {};
    curve.slopes = {1.0, 2.0};
    curve.diffNums = {0.0, 0.1};

    double axisSpeed = 5.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalcAxisGainTouchpad_004
 * @tc.desc: Test CalcAxisGainTouchpad with empty slopes (error path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_004, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 2.0};
    curve.slopes = {};
    curve.diffNums = {0.0, 0.1};

    double axisSpeed = 5.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalcAxisGainTouchpad_005
 * @tc.desc: Test CalcAxisGainTouchpad with empty diffNums (error path)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_005, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 2.0};
    curve.slopes = {1.0, 2.0};
    curve.diffNums = {};

    double axisSpeed = 5.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CalcAxisGainTouchpad_006
 * @tc.desc: Test CalcAxisGainTouchpad with negative axisSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, CalcAxisGainTouchpad_006, TestSize.Level1)
{
    PointerMotionAcceleration::AxisCurve curve;
    curve.speeds = {1.0, 5.0, 10.0};
    curve.slopes = {1.0, 0.8, 0.5};
    curve.diffNums = {0.0, 0.2, 0.5};

    double axisSpeed = -3.0;
    double gain = 0.0;

    auto ret = PointerMotionAcceleration::CalcAxisGainTouchpad(curve, axisSpeed, gain);
    EXPECT_TRUE(ret);
    EXPECT_GT(gain, 0.0);
}

/**
 * @tc.name: LoadAxisCurve_003
 * @tc.desc: Test LoadAxisCurve with config missing AxisAccelerateCurvesTouchpad key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerMotionAccelerationTestWithMock, LoadAxisCurve_003, TestSize.Level1)
{
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillRepeatedly(Return(nullptr));

    PointerMotionAcceleration::axisCurves_.reset();
    PointerMotionAcceleration::LoadAccelerationConfig(&PointerMotionAcceleration::LoadAxisCurve);
    EXPECT_FALSE(PointerMotionAcceleration::axisCurves_.has_value());
}
} // namespace MMI
} // namespace OHOS
