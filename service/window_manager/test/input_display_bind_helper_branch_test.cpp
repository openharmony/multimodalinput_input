/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <sstream>

#include "input_display_bind_helper.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDisplayBindHelperBranchTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputDisplayBindHelperBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
};

/**
 * @tc.name: InputDisplayBindHelperBranchTest_BindInfos_GetUnbindInputDevice_001
 * @tc.desc: Test BindInfos GetUnbindInputDevice with matched unbind item
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperBranchTest,
    InputDisplayBindHelperBranchTest_BindInfos_GetUnbindInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = -1;
    bindInfo.displayId_ = 3;
    bindInfo.displayName_ = "hp 223";
    bindInfos.infos_.push_back(bindInfo);

    BindInfo ret = bindInfos.GetUnbindInputDevice("hp 223");
    EXPECT_EQ(ret.GetInputDeviceId(), -1);
    EXPECT_EQ(ret.GetDisplayId(), 3);
    EXPECT_EQ(ret.GetDisplayName(), "hp 223");
    EXPECT_TRUE(bindInfos.infos_.empty());
}

/**
 * @tc.name: InputDisplayBindHelperBranchTest_BindInfos_GetUnbindDisplay_001
 * @tc.desc: Test BindInfos GetUnbindDisplay with exact inputDeviceName match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperBranchTest,
    InputDisplayBindHelperBranchTest_BindInfos_GetUnbindDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfos bindInfos;
    BindInfo bindInfo1;
    bindInfo1.displayId_ = -1;
    bindInfo1.inputDeviceName_ = "mouse";
    bindInfos.infos_.push_back(bindInfo1);

    BindInfo bindInfo2;
    bindInfo2.displayId_ = -1;
    bindInfo2.inputDeviceName_ = "keyboard";
    bindInfos.infos_.push_back(bindInfo2);

    BindInfo ret = bindInfos.GetUnbindDisplay("keyboard");
    EXPECT_EQ(ret.GetInputDeviceName(), "keyboard");
    ASSERT_EQ(bindInfos.infos_.size(), 1);
    EXPECT_EQ(bindInfos.infos_.front().GetInputDeviceName(), "mouse");
}

/**
 * @tc.name: InputDisplayBindHelperBranchTest_BindInfos_StreamIn_001
 * @tc.desc: Test BindInfos operator >> stops after invalid line
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperBranchTest, InputDisplayBindHelperBranchTest_BindInfos_StreamIn_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::istringstream iss("mouse<=>hp 223\ninvalid format\nkeyboard<=>think 123\n");
    BindInfos bindInfos;

    iss >> bindInfos;

    ASSERT_EQ(bindInfos.infos_.size(), 1);
    EXPECT_EQ(bindInfos.infos_.front().GetInputDeviceName(), "mouse");
    EXPECT_EQ(bindInfos.infos_.front().GetDisplayName(), "hp 223");
}

/**
 * @tc.name: InputDisplayBindHelperBranchTest_BindInfo_AddInputDevice_001
 * @tc.desc: Test BindInfo AddInputDevice reject keeps original state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDisplayBindHelperBranchTest, InputDisplayBindHelperBranchTest_BindInfo_AddInputDevice_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    BindInfo bindInfo;
    bindInfo.inputDeviceId_ = 7;
    bindInfo.inputNodeName_ = "oldNode";
    bindInfo.inputDeviceName_ = "oldDevice";

    bool ret = bindInfo.AddInputDevice(1, "newNode", "newDevice");

    EXPECT_FALSE(ret);
    EXPECT_EQ(bindInfo.GetInputDeviceId(), 7);
    EXPECT_EQ(bindInfo.GetInputNodeName(), "oldNode");
    EXPECT_EQ(bindInfo.GetInputDeviceName(), "oldDevice");
}
} // namespace MMI
} // namespace OHOS
