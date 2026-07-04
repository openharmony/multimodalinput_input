/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <memory>

#include <gtest/gtest.h>

#include "input_windows_manager.h"
#include "old_display_info.h"
#include "window_info.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerDisplayChangeTest"

using namespace testing::ext;

namespace OHOS {
namespace MMI {
namespace {
    // Named TEST_GROUP_ID to avoid clashing with OHOS::MMI::DEFAULT_GROUP_ID in window_info.h.
    constexpr int32_t TEST_GROUP_ID = 0;
    constexpr int32_t MAIN_DISPLAY_ID = 0;
    constexpr int32_t SECONDARY_DISPLAY_ID = 1;
    constexpr int32_t TERTIARY_DISPLAY_ID = 2;
    constexpr int32_t DISPLAY_WIDTH = 1080;
    constexpr int32_t DISPLAY_HEIGHT = 1920;
    constexpr int32_t DISPLAY_WIDTH_HI = 2160;
    constexpr int32_t DISPLAY_HEIGHT_HI = 3840;
} // namespace

/**
 * @brief Test fixture for InputWindowsManager::HasDisplayGroupInfoChanged
 *
 * Covers the display change detection added for PLUGIN_DISPLAY_DEVICE_ENABLE
 * (AC-1.4). The method is a pure const comparator over two DisplayGroupInfo
 * inputs and a hasOldGroupInfo flag, so it can be exercised without any
 * runtime singleton.
 */
class InputWindowsManagerDisplayChangeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp(void) override
    {
        windowsManager_ = std::make_shared<InputWindowsManager>();
        ASSERT_NE(windowsManager_, nullptr);
    }

    void TearDown(void) override
    {
        windowsManager_.reset();
    }

protected:
    OLD::DisplayInfo CreateDisplayInfo(int32_t id, int32_t width = DISPLAY_WIDTH,
        int32_t height = DISPLAY_HEIGHT, Direction direction = Direction::DIRECTION0,
        DisplaySourceMode sourceMode = DisplaySourceMode::SCREEN_MAIN) const
    {
        OLD::DisplayInfo info;
        info.id = id;
        info.x = 0;
        info.y = 0;
        info.width = width;
        info.height = height;
        info.direction = direction;
        info.displayMode = DisplayMode::UNKNOWN;
        info.displaySourceMode = sourceMode;
        info.rsId = static_cast<uint64_t>(id);
        info.name = "Display_" + std::to_string(id);
        info.uniq = "default" + std::to_string(id);
        return info;
    }

    OLD::DisplayGroupInfo CreateDisplayGroupInfo(int32_t groupId, int32_t mainDisplayId,
        std::vector<OLD::DisplayInfo> displays) const
    {
        OLD::DisplayGroupInfo groupInfo;
        groupInfo.groupId = groupId;
        groupInfo.mainDisplayId = mainDisplayId;
        groupInfo.displaysInfo = std::move(displays);
        return groupInfo;
    }

    std::shared_ptr<InputWindowsManager> windowsManager_;
};

/**
 * @tc.name: HasDisplayGroupInfoChanged_NoOldInfo_001
 * @tc.type: FUNC
 * @tc.desc: Initialization (hasOldGroupInfo=false) must not report a change.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_NoOldInfo_001, TestSize.Level1)
{
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID, { CreateDisplayInfo(MAIN_DISPLAY_ID) });
    auto empty = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID, {});

    EXPECT_FALSE(windowsManager_->HasDisplayGroupInfoChanged(empty, newGroup, false));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_ScreenAdded_002
 * @tc.type: FUNC
 * @tc.desc: Adding a screen is detected as a change.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_ScreenAdded_002, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID, { CreateDisplayInfo(MAIN_DISPLAY_ID) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(SECONDARY_DISPLAY_ID) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_ScreenRemoved_003
 * @tc.type: FUNC
 * @tc.desc: Removing a screen is detected as a change.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_ScreenRemoved_003, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(SECONDARY_DISPLAY_ID) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID, { CreateDisplayInfo(MAIN_DISPLAY_ID) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_MainDisplaySwitched_004
 * @tc.type: FUNC
 * @tc.desc: Switching main display ID (external-only mode) is detected.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_MainDisplaySwitched_004, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(SECONDARY_DISPLAY_ID) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, SECONDARY_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(SECONDARY_DISPLAY_ID) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_DirectionChanged_005
 * @tc.type: FUNC
 * @tc.desc: Rotation (direction) change is detected.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_DirectionChanged_005, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION90) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_ResolutionChanged_006
 * @tc.type: FUNC
 * @tc.desc: Resolution change is detected.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_ResolutionChanged_006, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH_HI, DISPLAY_HEIGHT_HI) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_SourceModeChanged_007
 * @tc.type: FUNC
 * @tc.desc: Mirror/extend (displaySourceMode) change is detected.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_SourceModeChanged_007, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0,
            DisplaySourceMode::SCREEN_MAIN) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0,
            DisplaySourceMode::SCREEN_MIRROR) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_DisplayReplaced_008
 * @tc.type: FUNC
 * @tc.desc: A display being replaced by a different ID is detected.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_DisplayReplaced_008, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(SECONDARY_DISPLAY_ID) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID), CreateDisplayInfo(TERTIARY_DISPLAY_ID) });

    EXPECT_TRUE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: HasDisplayGroupInfoChanged_NoChange_009
 * @tc.type: FUNC
 * @tc.desc: Identical display info must not report a change (no false positive).
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, HasDisplayGroupInfoChanged_NoChange_009, TestSize.Level1)
{
    auto oldGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0) });
    auto newGroup = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID,
        { CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0) });

    EXPECT_FALSE(windowsManager_->HasDisplayGroupInfoChanged(oldGroup, newGroup, true));
}

/**
 * @tc.name: GetDisplayGroupInfos_ReturnsVector_010
 * @tc.type: FUNC
 * @tc.desc: GetDisplayGroupInfos returns a (possibly empty) vector without crashing.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, GetDisplayGroupInfos_ReturnsVector_010, TestSize.Level1)
{
    auto groups = windowsManager_->GetDisplayGroupInfos();
    EXPECT_GE(groups.size(), 0u);
}

/**
 * @tc.name: GetDisplayGroupInfos_ReturnsPluginFields_011
 * @tc.type: FUNC
 * @tc.desc: GetDisplayGroupInfos returns plugin display DTO fields without exposing OLD display info.
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerDisplayChangeTest, GetDisplayGroupInfos_ReturnsPluginFields_011, TestSize.Level1)
{
    constexpr uint64_t rsId = 12345;
    auto display = CreateDisplayInfo(MAIN_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, Direction::DIRECTION0,
        DisplaySourceMode::SCREEN_MIRROR);
    display.rsId = rsId;
    auto group = CreateDisplayGroupInfo(TEST_GROUP_ID, MAIN_DISPLAY_ID, { display });
    windowsManager_->InitDisplayGroupInfo(group);

    auto groups = windowsManager_->GetDisplayGroupInfos();
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].groupId, TEST_GROUP_ID);
    EXPECT_EQ(groups[0].mainDisplayId, MAIN_DISPLAY_ID);
    ASSERT_EQ(groups[0].displayInfos.size(), 1u);
    EXPECT_EQ(groups[0].displayInfos[0].displayId, MAIN_DISPLAY_ID);
    EXPECT_EQ(groups[0].displayInfos[0].rsId, rsId);
    EXPECT_EQ(groups[0].displayInfos[0].mode, static_cast<int32_t>(DisplaySourceMode::SCREEN_MIRROR));
}
} // namespace MMI
} // namespace OHOS
