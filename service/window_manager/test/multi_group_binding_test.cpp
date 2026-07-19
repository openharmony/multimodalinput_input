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

#include "input_windows_manager.h"
#include "input_display_bind_helper.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultiGroupBindingTest"

using namespace testing::ext;

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAIN_FOCUS_WINDOW_ID = 10;
constexpr int32_t SEC_FOCUS_WINDOW_ID = 20;
constexpr int32_t MAIN_DISPLAY_WIDTH = 1920;
constexpr int32_t MAIN_DISPLAY_HEIGHT = 1080;
constexpr int32_t MAIN_DISPLAY_DPI = 240;
constexpr int32_t SEC_DISPLAY_WIDTH = 1280;
constexpr int32_t SEC_DISPLAY_HEIGHT = 720;
constexpr int32_t SEC_DISPLAY_DPI = 160;

class MultiGroupBindingTest : public testing::Test {
public:
    void SetUp() override
    {
        mgr_ = std::make_shared<InputWindowsManager>();
        SetupTwoGroups();
    }

    void SetupTwoGroups()
    {
        OLD::DisplayGroupInfo mainGroup;
        mainGroup.groupId = 0;
        mainGroup.type = GroupType::GROUP_DEFAULT;
        mainGroup.focusWindowId = MAIN_FOCUS_WINDOW_ID;
        OLD::DisplayInfo mainDisplay = { .id = 1 };
        mainDisplay.width = MAIN_DISPLAY_WIDTH;
        mainDisplay.height = MAIN_DISPLAY_HEIGHT;
        mainDisplay.dpi = MAIN_DISPLAY_DPI;
        mainDisplay.name = "main";
        mainDisplay.uniq = "default0";
        mainDisplay.direction = DIRECTION0;
        mainGroup.displaysInfo.push_back(mainDisplay);
        mgr_->UpdateDisplayInfo(mainGroup);

        OLD::DisplayGroupInfo secGroup;
        secGroup.groupId = 1;
        secGroup.type = GroupType::GROUP_SPECIAL;
        secGroup.focusWindowId = SEC_FOCUS_WINDOW_ID;
        OLD::DisplayInfo secDisplay = { .id = 2 };
        secDisplay.width = SEC_DISPLAY_WIDTH;
        secDisplay.height = SEC_DISPLAY_HEIGHT;
        secDisplay.dpi = SEC_DISPLAY_DPI;
        secDisplay.name = "secondary";
        secDisplay.uniq = "secondary0";
        secDisplay.direction = DIRECTION0;
        secGroup.displaysInfo.push_back(secDisplay);
        mgr_->UpdateDisplayInfo(secGroup);
    }

    std::shared_ptr<InputWindowsManager> mgr_;
};

HWTEST_F(MultiGroupBindingTest, BindValidDisplay_001, TestSize.Level1)
{
    std::string msg;
    int32_t ret = mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);
    EXPECT_EQ(ret, RET_OK);

    auto binding = mgr_->bindInfo_.GetRuntimeBinding(100);
    ASSERT_TRUE(binding.has_value());
    EXPECT_EQ(binding->displayId, 2);
    EXPECT_EQ(binding->groupId, 1);
}

HWTEST_F(MultiGroupBindingTest, BindInvalidDisplay_001, TestSize.Level1)
{
    std::string msg;
    int32_t ret = mgr_->BindDeviceToDisplayGroupByDisplay(100, 999, msg);
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_FALSE(msg.empty());
}

HWTEST_F(MultiGroupBindingTest, UnbindDevice_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);
    ASSERT_TRUE(mgr_->bindInfo_.GetRuntimeBinding(100).has_value());

    int32_t ret = mgr_->UnbindDeviceFromDisplayGroup(100, msg);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FALSE(mgr_->bindInfo_.GetRuntimeBinding(100).has_value());
}

HWTEST_F(MultiGroupBindingTest, RebindOverwrite_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 1, msg);
    auto b1 = mgr_->bindInfo_.GetRuntimeBinding(100);
    ASSERT_TRUE(b1.has_value());
    EXPECT_EQ(b1->groupId, 0);

    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);
    auto b2 = mgr_->bindInfo_.GetRuntimeBinding(100);
    ASSERT_TRUE(b2.has_value());
    EXPECT_EQ(b2->groupId, 1);
}

HWTEST_F(MultiGroupBindingTest, TwoDevicesDifferentGroups_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 1, msg);
    mgr_->BindDeviceToDisplayGroupByDisplay(200, 2, msg);

    auto b1 = mgr_->bindInfo_.GetRuntimeBinding(100);
    auto b2 = mgr_->bindInfo_.GetRuntimeBinding(200);
    ASSERT_TRUE(b1.has_value());
    ASSERT_TRUE(b2.has_value());
    EXPECT_NE(b1->groupId, b2->groupId);
}

HWTEST_F(MultiGroupBindingTest, ResolveGroupId_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);

    EXPECT_EQ(mgr_->GetDeviceGroupId(100), 1);
    EXPECT_EQ(mgr_->GetDeviceGroupId(999), DEFAULT_GROUP_ID);
}

HWTEST_F(MultiGroupBindingTest, UnbindMissingIsNoOp_001, TestSize.Level1)
{
    std::string msg;
    int32_t ret = mgr_->UnbindDeviceFromDisplayGroup(999, msg);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(MultiGroupBindingTest, DeviceOfflineAutoUnbind_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);
    ASSERT_TRUE(mgr_->bindInfo_.GetRuntimeBinding(100).has_value());

    mgr_->bindInfo_.ClearRuntimeBindingsByDevice(100);
    EXPECT_FALSE(mgr_->bindInfo_.GetRuntimeBinding(100).has_value());
}

} // namespace
} // namespace MMI
} // namespace OHOS
