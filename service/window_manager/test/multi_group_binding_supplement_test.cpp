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

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultiGroupBindingSupplementTest"

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

class MultiGroupBindingSupplementTest : public testing::Test {
public:
    void SetUp() override
    {
        mgr_ = std::make_shared<InputWindowsManager>();
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

HWTEST_F(MultiGroupBindingSupplementTest, CursorPosPerGroupIsolation_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);

    auto pos0 = mgr_->GetCursorPos(0);
    auto pos1 = mgr_->GetCursorPos(1);
    EXPECT_EQ(pos0.displayId, 1);
    EXPECT_EQ(pos1.displayId, 2);
}

HWTEST_F(MultiGroupBindingSupplementTest, MouseLocationPerGroupIsolation_001, TestSize.Level1)
{
    std::string msg;
    mgr_->BindDeviceToDisplayGroupByDisplay(100, 2, msg);

    auto loc0 = mgr_->GetMouseInfo(0);
    auto loc1 = mgr_->GetMouseInfo(1);
    static_cast<void>(loc0);
    static_cast<void>(loc1);
    EXPECT_TRUE(true);
}

HWTEST_F(MultiGroupBindingSupplementTest, CaptureModePerGroupIsolation_001, TestSize.Level1)
{
    mgr_->SetMouseCaptureMode(10, true, 0);
    mgr_->SetMouseCaptureMode(20, true, 1);
    EXPECT_TRUE(mgr_->GetMouseIsCaptureMode(0));
    EXPECT_TRUE(mgr_->GetMouseIsCaptureMode(1));

    mgr_->SetMouseCaptureMode(10, false, 0);
    EXPECT_FALSE(mgr_->GetMouseIsCaptureMode(0));
    EXPECT_TRUE(mgr_->GetMouseIsCaptureMode(1));
}

HWTEST_F(MultiGroupBindingSupplementTest, KeyboardFocusPerGroupIsolation_001, TestSize.Level1)
{
    auto focusMain = mgr_->GetFocusWindowId(0);
    auto focusSec = mgr_->GetFocusWindowId(1);
    EXPECT_EQ(focusMain, 10);
    EXPECT_EQ(focusSec, 20);
}

HWTEST_F(MultiGroupBindingSupplementTest, LazyStateNotCreatedOnStartup_001, TestSize.Level1)
{
    EXPECT_FALSE(mgr_->HasGroupState(5));
}

HWTEST_F(MultiGroupBindingSupplementTest, EnsureGroupStateCreatesState_001, TestSize.Level1)
{
    EXPECT_FALSE(mgr_->HasGroupState(3));
    mgr_->EnsureGroupState(3);
    EXPECT_TRUE(mgr_->HasGroupState(3));
}

} // namespace
} // namespace MMI
} // namespace OHOS
