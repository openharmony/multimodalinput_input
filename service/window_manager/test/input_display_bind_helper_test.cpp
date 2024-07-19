/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <filesystem>
#include <fstream>
#include <iostream>

#include "input_display_bind_helper.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDisplayBindHelperTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
const std::string INPUT_NODE_PATH = "/data/input0_test";
const std::string INPUT_DEVICE_NAME_FILE = "/data/input0_test/name";
const std::string INPUT_DEVICE_NAME_CONFIG = "/data/input_device_name.cfg";
const std::string DISPLAY_MAPPING = "0<=>wrapper";
const std::string INPUT_NODE_NAME = "wrapper";
} // namespace
namespace fs = std::filesystem;
class InputDisplayBindHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static bool WriteConfigFile(const std::string &content);
    static bool InitInputNode();
    static bool InitConfigFile();
    static inline const std::string bindCfgFile_ = "input_display_bind_helper.cfg";
    static std::string GetCfgFileName()
    {
        return bindCfgFile_;
    }
};

bool InputDisplayBindHelperTest::WriteConfigFile(const std::string &content)
{
    const std::string &fileName = InputDisplayBindHelperTest::bindCfgFile_;
    std::ofstream ofs(fileName.c_str());
    if (!ofs) {
        MMI_HILOGE("Open file fail.%s\n", fileName.c_str());
        return false;
    }
    ofs << content;
    ofs.close();
    return true;
}

bool InputDisplayBindHelperTest::InitInputNode()
{
    if (fs::exists(INPUT_NODE_PATH) && fs::is_directory(INPUT_NODE_PATH)) {
        if (fs::remove_all(INPUT_NODE_PATH) == 0) {
            MMI_HILOGI("Clear success, path:%{public}s", INPUT_NODE_PATH.c_str());
        } else {
            MMI_HILOGE("Clear fail, path:%{public}s", INPUT_NODE_PATH.c_str());
        }
    }
    if (fs::create_directory(INPUT_NODE_PATH)) {
        MMI_HILOGI("Create success, path:%{public}s", INPUT_NODE_PATH.c_str());
    } else {
        MMI_HILOGE("Create fail, path:%{public}s", INPUT_NODE_PATH.c_str());
        return false;
    }
    std::ofstream file(INPUT_DEVICE_NAME_FILE);
    if (!file.is_open()) {
        MMI_HILOGE("Write fail, path:%{public}s", INPUT_DEVICE_NAME_FILE.c_str());
        return false;
    }
    file << INPUT_NODE_NAME;
    file.close();
    MMI_HILOGI("Write success, path:%{public}s", INPUT_DEVICE_NAME_FILE.c_str());
    return true;
}

bool InputDisplayBindHelperTest::InitConfigFile()
{
    if (fs::exists(INPUT_DEVICE_NAME_CONFIG)) {
        if (std::remove(INPUT_DEVICE_NAME_CONFIG.c_str()) == 0) {
            MMI_HILOGI("Clear success, path:%{public}s", INPUT_DEVICE_NAME_CONFIG.c_str());
        } else {
            MMI_HILOGE("Clear fail, path:%{public}s", INPUT_DEVICE_NAME_CONFIG.c_str());
            return false;
        }
    }
    std::ofstream file(INPUT_DEVICE_NAME_CONFIG);
    if (!file.is_open()) {
        MMI_HILOGE("Write fail, path:%{public}s", INPUT_DEVICE_NAME_CONFIG.c_str());
        return false;
    }
    file << DISPLAY_MAPPING;
    file.close();
    MMI_HILOGI("Write success, path:%{public}s", INPUT_DEVICE_NAME_CONFIG.c_str());
    return true;
}

/**
 * @tc.name: InputDisplayBindHelperTest_001
 * @tc.desc: No bind info in disk
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "hp 223");
    bindInfo.AddDisplay(2, "think 123");
    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>hp 223\nkeyboard<=>think 123\n"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_002
 * @tc.desc: Has info with adding order in disk
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "hp 223");
    bindInfo.AddDisplay(2, "think 123");
    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>hp 223\nkeyboard<=>think 123\n"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_003
 * @tc.desc: Has info without adding order in disk
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>think 123\nkeyboard<=>hp 223\n");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "think 123");
    bindInfo.AddDisplay(2, "hp 223");
    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>think 123\nkeyboard<=>hp 223\n"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_004
 * @tc.desc: Bind and remove test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "hp 223");
    bindInfo.AddDisplay(2, "think 123");
    // 显示屏移除
    bindInfo.RemoveDisplay(2);
    bindInfo.RemoveDisplay(0);
    // 输入设备移除
    bindInfo.RemoveInputDevice(1);
    bindInfo.RemoveInputDevice(2);
    bindInfo.RemoveInputDevice(3);
    // 窗口同步信息
    bindInfo.AddDisplay(0, "hp 223");
    bindInfo.AddDisplay(2, "think 123");
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    bindInfo.AddInputDevice(3, "keyboard88");

    bindInfo.Store();
    bindInfo.Load();
    bindInfo.Dumps();
    // 输入设备移除
    bindInfo.RemoveInputDevice(1);
    bindInfo.RemoveInputDevice(2);
    // 触摸板设备移除
    bindInfo.RemoveDisplay(2);
    bindInfo.RemoveDisplay(0);
    ASSERT_EQ(bindInfo.Dumps(), std::string(""));
}

/**
 * @tc.name: InputDisplayBindHelperTest_005
 * @tc.desc: Test GetBindDisplayNameByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetBindDisplayNameByInputDevice_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>think 123\nkeyboard<=>hp 223\n");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "think 123");
    bindInfo.AddDisplay(2, "hp 223");
    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>think 123\nkeyboard<=>hp 223\n"));
    // 获取
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(1), std::string("think 123"));
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(2), std::string("hp 223"));
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(3), std::string());
    // 删除display
    bindInfo.RemoveDisplay(0);
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(1), std::string());
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(2), std::string("hp 223"));
    bindInfo.RemoveDisplay(2);
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(1), std::string());
    ASSERT_EQ(bindInfo.GetBindDisplayNameByInputDevice(2), std::string());
}

/**
 * @tc.name: InputDisplayBindHelperTest_IsDisplayAdd_006
 * @tc.desc: Test GetBindDisplayNameByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_IsDisplayAdd_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>think 123\nkeyboard<=>hp 223\n");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    ASSERT_FALSE(bindInfo.IsDisplayAdd(0, "hp 223"));
    ASSERT_FALSE(bindInfo.IsDisplayAdd(2, "think 123"));
    ASSERT_FALSE(bindInfo.IsDisplayAdd(1, "think 123"));
    ASSERT_EQ(bindInfo.Dumps(), std::string());
    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");
    // 窗口同步信息
    bindInfo.AddDisplay(0, "think 123");
    bindInfo.AddDisplay(2, "hp 223");
    ASSERT_TRUE(bindInfo.IsDisplayAdd(0, "think 123"));
    ASSERT_TRUE(bindInfo.IsDisplayAdd(2, "hp 223"));
    ASSERT_FALSE(bindInfo.IsDisplayAdd(1, "think 123"));

    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>think 123\nkeyboard<=>hp 223\n"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetDisplayIdNames_007
 * @tc.desc: Test GetBindDisplayNameByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetDisplayIdNames_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    using IdNames = std::set<std::pair<int32_t, std::string>>;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>think 123\nkeyboard<=>hp 223\n");
    InputDisplayBindHelper bindInfo(InputDisplayBindHelperTest::GetCfgFileName());
    // 多模初始化
    bindInfo.Load();
    IdNames idNames;
    ASSERT_EQ(bindInfo.GetDisplayIdNames(), idNames);
    bindInfo.AddDisplay(2, "hp 223");
    idNames.insert(std::make_pair(2, "hp 223"));
    ASSERT_EQ(bindInfo.GetDisplayIdNames(), idNames);

    // 检测到触摸板设备
    bindInfo.AddInputDevice(1, "mouse");
    bindInfo.AddInputDevice(2, "keyboard");

    // 窗口同步信息
    bindInfo.AddDisplay(0, "think 123");
    idNames.insert(std::make_pair(0, "think 123"));
    ASSERT_EQ(bindInfo.GetDisplayIdNames(), idNames);
    bindInfo.AddDisplay(2, "hp 223");
    idNames.insert(std::make_pair(2, "hp 223"));
    ASSERT_EQ(bindInfo.GetDisplayIdNames(), idNames);
    ASSERT_EQ(bindInfo.Dumps(), std::string("mouse<=>think 123\nkeyboard<=>hp 223\n"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_008
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelper idh("/data/service/el1/public/multimodalinput/0.txt");
    if (!(InputDisplayBindHelperTest::InitInputNode())) {
        return;
    }
    if (!(InputDisplayBindHelperTest::InitConfigFile())) {
        return;
    }
    // 读取输入节点名称
    std::string content = idh.GetContent(INPUT_DEVICE_NAME_FILE);
    ASSERT_EQ(content, INPUT_NODE_NAME);
    // 根据输入节点名称获取输入节点
    std::string inputNode = idh.GetInputNode(INPUT_NODE_NAME);
    ASSERT_EQ(inputNode, "");
    // 根据id获取输入节点名称
    std::string inputNodeName = idh.GetInputNodeNameByCfg(1000);
    ASSERT_EQ(inputNodeName, "");
    // 根据id获取输入设备
    std::string inputDevice = idh.GetInputDeviceById(1000);
    ASSERT_EQ(inputDevice, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_01
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId;
    int32_t displayId;
    InputDisplayBindHelper idh("/data/service/el1/public/multimodalinput/0.txt");
    std::string msg = "deviceId";
    deviceId = -1;
    displayId = -1;
    int32_t ret1 = idh.SetDisplayBind(deviceId, displayId, msg);
    EXPECT_EQ(ret1, RET_ERR);

    deviceId = 1;
    displayId = 2;
    int32_t ret2 = idh.SetDisplayBind(deviceId, displayId, msg);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_01
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelper idh("/data/service/el1/public/multimodalinput/0.txt");
    int32_t id = 3;
    std::string ret1 = idh.GetInputDeviceById(id);
    EXPECT_EQ(ret1, "");

    id = 6;
    std::string inputNodeName = "";
    EXPECT_TRUE(inputNodeName.empty());
    std::string ret2 = idh.GetInputDeviceById(id);
    EXPECT_EQ(ret2, "");

    id = 8;
    std::string inputNode = "";
    EXPECT_TRUE(inputNode.empty());
    std::string ret3 = idh.GetInputDeviceById(id);
    EXPECT_EQ(ret3, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNodeNameByCfg_01
 * @tc.desc: Test GetInputNodeNameByCfg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNodeNameByCfg_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = 3;
    InputDisplayBindHelper idh("/data/service/el1/public/multimodalinput/0.txt");
    std::ifstream file(INPUT_DEVICE_NAME_CONFIG);
    EXPECT_TRUE(file.is_open());
    std::string ret1 = idh.GetInputNodeNameByCfg(id);
    EXPECT_EQ(ret1, "");

    id = 2;
    std::string res = "abc";
    res.back() = '\n';
    std::string ret2 = idh.GetInputNodeNameByCfg(id);
    EXPECT_EQ(ret2, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddInputDevice_02
 * @tc.desc: Test AddInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddInputDevice_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.inputDeviceName_ = "mouse";
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddInputDevice(1, "mouse"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddInputDevice_03
 * @tc.desc: Test AddInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddInputDevice_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddInputDevice(1, "mouse"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddInputDevice_04
 * @tc.desc: Test AddInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddInputDevice_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddInputDevice(1, "mouse"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_01
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_02
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.displayName_ = "hp 223";
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_03
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.displayId_ = 0;
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_04
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    ASSERT_NO_FATAL_FAILURE(bindInfo.AddDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_05
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "";
    bool ret = bindInfo.AddDisplay(1, "hp 223");
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddDisplay_06
 * @tc.desc: Test AddDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddDisplay_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());

    int32_t id = 3;
    std::string name = "display";
    std::string deviceName = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_TRUE(deviceName.empty());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.AddDisplay(id, name));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetDesc_01
 * @tc.desc: Test GetDesc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetDesc_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    ASSERT_NO_FATAL_FAILURE(bindInfo.GetDesc());
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetDesc_02
 * @tc.desc: Test GetDesc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetDesc_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(bindInfos.GetDesc());
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_01
 * @tc.desc: Test GetBindDisplayIdByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(bindInfos.GetBindDisplayIdByInputDevice(1));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_02
 * @tc.desc: Test GetBindDisplayIdByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(bindInfos.GetBindDisplayIdByInputDevice(1));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_03
 * @tc.desc: Test GetBindDisplayIdByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetBindDisplayIdByInputDevice_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(bindInfos.GetBindDisplayIdByInputDevice(2));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetBindDisplayNameByInputDevice_01
 * @tc.desc: Test GetBindDisplayNameByInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetBindDisplayNameByInputDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(bindInfos.GetBindDisplayNameByInputDevice(1));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetDisplayIdNames_01
 * @tc.desc: Test GetDisplayIdNames
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetDisplayIdNames_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetDisplayIdNames());
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddLocalDisplay_02
 * @tc.desc: Test AddLocalDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddLocalDisplay_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.AddLocalDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddLocalDisplay_03
 * @tc.desc: Test AddLocalDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddLocalDisplay_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.AddLocalDisplay(0, "hp 223"));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_02
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputDeviceById(1));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_03
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputDeviceById(1));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_04
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputDeviceById(0));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_05
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());

    int32_t id = 5;
    std::string inputNodeName = inputDisplayBindHelper.GetInputNodeNameByCfg(id);
    EXPECT_TRUE(inputNodeName.empty());

    std::string inputNode = inputDisplayBindHelper.GetInputNode(inputNodeName);
    EXPECT_TRUE(inputNode.empty());

    std::string ret = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputDeviceById_06
 * @tc.desc: Test GetInputDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputDeviceById_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());

    int32_t id = 0;
    std::string ret1 = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_EQ(ret1, "");


    std::string inputNodeName = "mouse";
    EXPECT_FALSE(inputNodeName.empty());
    std::string ret2 = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_EQ(ret2, "");

    std::string inputNode = "keyboard";
    EXPECT_FALSE(inputNode.empty());
    std::string ret3 = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_EQ(ret3, "");

    std::string inputEvent = inputNode;
    size_t pos = inputEvent.find("input");
    EXPECT_TRUE(pos == std::string::npos);
    std::string ret4 = inputDisplayBindHelper.GetInputDeviceById(id);
    EXPECT_EQ(ret4, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNodeNameByCfg_02
 * @tc.desc: Test GetInputNodeNameByCfg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNodeNameByCfg_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputNodeNameByCfg(0));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNodeNameByCfg_03
 * @tc.desc: Test GetInputNodeNameByCfg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNodeNameByCfg_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());

    int32_t id = 2;
    std::string displayId = "";
    std::string inputNodeName = "";
    size_t pos;
    pos = std::string::npos;
    std::string ret = inputDisplayBindHelper.GetInputNodeNameByCfg(id);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNodeNameByCfg_04
 * @tc.desc: Test GetInputNodeNameByCfg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNodeNameByCfg_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());

    int32_t id = 2;
    std::string displayId = "hp223";
    std::string inputNodeName = "nodeName";
    size_t pos;
    pos = 3;
    std::string ret = inputDisplayBindHelper.GetInputNodeNameByCfg(id);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNode_01
 * @tc.desc: Test GetInputNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNode_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    std::string inputNodeName = "input5";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputNode(inputNodeName));
}

/**
 * @tc.name: InputDisplayBindHelperTest_GetInputNode_02
 * @tc.desc: Test GetInputNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_GetInputNode_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    std::string inputNodeName = "wrapper";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.GetInputNode(inputNodeName));
}

/**
 * @tc.name: InputDisplayBindHelperTest_Store_01
 * @tc.desc: Test Store
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_Store_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.Store());
}

/**
 * @tc.name: InputDisplayBindHelperTest_Store_02
 * @tc.desc: Test Store
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_Store_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper("input_display_bind_helper_tmp.cfg");
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.Store());
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_02
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    int32_t deviceId = -1;
    int32_t displayId = -1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_03
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    int32_t deviceId = -1;
    int32_t displayId = 0;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_04
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    int32_t deviceId = 1;
    int32_t displayId = -1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_05
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    int32_t deviceId = 1;
    int32_t displayId = 0;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_06
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    int32_t deviceId = 1;
    int32_t displayId = 0;
    std::string msg = "touch";
    inputDisplayBindHelper.infos_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_07
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 0;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_08
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 2;
    int32_t displayId = 1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_09
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 0;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_10
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    bindInfo.inputDeviceId_ = 2;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_11
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 0;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    bindInfo.inputDeviceId_ = -1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_12
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_12, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    bindInfo.inputDeviceId_ = 2;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_SetDisplayBind_13
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_SetDisplayBind_13, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDisplayBindHelperTest::WriteConfigFile("mouse<=>hp 223\nkeyboard<=>think 123\n");
    InputDisplayBindHelper inputDisplayBindHelper(InputDisplayBindHelperTest::GetCfgFileName());
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = -1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    bindInfo.inputDeviceId_ = -1;
    bindInfo.inputDeviceName_ = "mouse";
    bindInfo.displayId_ = 1;
    bindInfo.displayName_ = "hp 223";
    inputDisplayBindHelper.infos_->infos_.push_back(bindInfo);
    int32_t deviceId = 1;
    int32_t displayId = 1;
    std::string msg = "touch";
    ASSERT_NO_FATAL_FAILURE(inputDisplayBindHelper.SetDisplayBind(deviceId, displayId, msg));
}

/**
 * @tc.name: InputDisplayBindHelperTest_AddLocalDisplay_01
 * @tc.desc: Test AddLocalDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_AddLocalDisplay_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isStore;
    int32_t id = 3;
    std::string name = "localDisplay";
    InputDisplayBindHelper idh("/data/service/el1/public/multimodalinput/0.txt");
    isStore = false;
    ASSERT_NO_FATAL_FAILURE(idh.AddLocalDisplay(id, name));
}
} // namespace MMI
} // namespace OHOS