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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
    ffrt::wait();
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
} // namespace MMI
} // namespace OHOS
