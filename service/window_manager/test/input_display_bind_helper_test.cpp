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

#include <fstream>

#include "input_display_bind_helper.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputDisplayBindHelperTest" };
} // namespace
class InputDisplayBindHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    static bool WriteConfigFile(const std::string &content);
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

/**
 * @tc.name: InputDisplayBindHelperTest_001
 * @tc.desc: No bind info in disk
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperTest, InputDisplayBindHelperTest_001, TestSize.Level1)
{
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
} // namespace MMI
} // namespace OHOS