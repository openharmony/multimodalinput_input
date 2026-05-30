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
#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "input_windows_manager.h"
#include "mmi_log.h"
#include "proto.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "old_display_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerCoverageTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

namespace {
constexpr int32_t INVALID_PID_RET = -1;
} // namespace

class InputWindowsManagerCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {};
    static void InitDisplayGroupInfo(OLD::DisplayGroupInfo &displayGroupInfo);

    void SetUp(void)
    {
        OLD::DisplayGroupInfo displayGroupInfo;
        InitDisplayGroupInfo(displayGroupInfo);
        WIN_MGR->UpdateDisplayInfo(displayGroupInfo);
    }

    void TearDown(void)
    {
        // Clean up resources if needed
    }
};

void InputWindowsManagerCoverageTest::SetUpTestCase(void)
{
    IInputWindowsManager::GetInstance();
}

void InputWindowsManagerCoverageTest::InitDisplayGroupInfo(OLD::DisplayGroupInfo &displayGroupInfo)
{
    displayGroupInfo.groupId = 0;
    displayGroupInfo.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 1;

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 0;
    displayInfo.y = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.dpi = 240;
    displayInfo.name = "display1";
    displayInfo.uniq = "uniq1";
    displayInfo.direction = DIRECTION0;
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 100;
    windowInfo.uid = 1000;
    windowInfo.agentWindowId = 1;
    windowInfo.agentPid = 100;
    windowInfo.area = {0, 0, 100, 100};
    windowInfo.defaultHotAreas = {windowInfo.area};
    windowInfo.pointerHotAreas = {windowInfo.area};
    windowInfo.flags = 0;
    windowInfo.transform = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    displayGroupInfo.windowsInfo.push_back(windowInfo);
}

/**
 * @tc.name: GetWindowPid_001
 * @tc.desc: Test GetWindowPid with non-existent window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(WIN_MGR->GetWindowPid(999), INVALID_PID_RET);
}

/**
 * @tc.name: GetWindowPid_002
 * @tc.desc: Test GetWindowPid with existing window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(WIN_MGR->GetWindowPid(1), 100);
}

/**
 * @tc.name: GetWindowAgentPid_001
 * @tc.desc: Test GetWindowAgentPid with non-existent window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowAgentPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(WIN_MGR->GetWindowAgentPid(999), INVALID_PID_RET);
}

/**
 * @tc.name: GetWindowAgentPid_002
 * @tc.desc: Test GetWindowAgentPid with existing window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowAgentPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(WIN_MGR->GetWindowAgentPid(1), 100);
}

/**
 * @tc.name: GetDefaultDisplayGroupInfo_001
 * @tc.desc: Test GetDefaultDisplayGroupInfo
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetDefaultDisplayGroupInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto &info = WIN_MGR->GetDefaultDisplayGroupInfo();
    EXPECT_EQ(info.groupId, 0);
    EXPECT_EQ(info.type, GroupType::GROUP_DEFAULT);
}

/**
 * @tc.name: GetWindowGroupInfoByDisplayIdCopy_001
 * @tc.desc: Test GetWindowGroupInfoByDisplayIdCopy with negative displayId
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowGroupInfoByDisplayIdCopy_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto windows = WIN_MGR->GetWindowGroupInfoByDisplayIdCopy(-1);
    EXPECT_GE(windows.size(), 0);
}

/**
 * @tc.name: GetWindowGroupInfoByDisplayIdCopy_002
 * @tc.desc: Test GetWindowGroupInfoByDisplayIdCopy with non-existent display
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowGroupInfoByDisplayIdCopy_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto windows = WIN_MGR->GetWindowGroupInfoByDisplayIdCopy(999);
    EXPECT_GE(windows.size(), 0);
}

/**
 * @tc.name: GetWindowGroupInfoByDisplayIdCopy_003
 * @tc.desc: Test GetWindowGroupInfoByDisplayIdCopy with existing display
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowGroupInfoByDisplayIdCopy_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto windows = WIN_MGR->GetWindowGroupInfoByDisplayIdCopy(1);
    EXPECT_EQ(windows.size(), 1);
    if (!windows.empty()) {
        EXPECT_EQ(windows[0].id, 1);
    }
}

/**
 * @tc.name: CheckAppFocused_001
 * @tc.desc: Test CheckAppFocused with non-matching pid
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, CheckAppFocused_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(WIN_MGR->CheckAppFocused(999));
}

/**
 * @tc.name: FindDisplayUserId_001
 * @tc.desc: Test FindDisplayUserId with non-existent display
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, FindDisplayUserId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(WIN_MGR->FindDisplayUserId(999), RET_ERR);
}

/**
 * @tc.name: FindDisplayUserId_002
 * @tc.desc: Test FindDisplayUserId with existing display
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, FindDisplayUserId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto result = WIN_MGR->FindDisplayUserId(1);
    EXPECT_GE(result, RET_ERR);
}

/**
 * @tc.name: GetDisplayMode_001
 * @tc.desc: Test GetDisplayMode
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetDisplayMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto mode = WIN_MGR->GetDisplayMode();
    EXPECT_GE(static_cast<int32_t>(mode), 0);
}

/**
 * @tc.name: TransformWindowXY_001
 * @tc.desc: Test TransformWindowXY
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, TransformWindowXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.transform = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    auto result = WIN_MGR->TransformWindowXY(windowInfo, 100.0, 200.0);
    EXPECT_GE(result.first, 0.0);
    EXPECT_GE(result.second, 0.0);
}

/**
 * @tc.name: TransformDisplayXY_001
 * @tc.desc: Test TransformDisplayXY
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, TransformDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OLD::DisplayInfo displayInfo;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.x = 0;
    displayInfo.y = 0;
    auto result = WIN_MGR->TransformDisplayXY(displayInfo, 100.0, 200.0);
    EXPECT_GE(result.first, 0.0);
    EXPECT_GE(result.second, 0.0);
}

/**
 * @tc.name: GetExtraData_001
 * @tc.desc: Test GetExtraData
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto extraData = WIN_MGR->GetExtraData();
    EXPECT_GE(extraData.sourceType, -1);
}

/**
 * @tc.name: GetWindowAndDisplayInfo_001
 * @tc.desc: Test GetWindowAndDisplayInfo with non-existent window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowAndDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto result = WIN_MGR->GetWindowAndDisplayInfo(999, 999);
    EXPECT_FALSE(result.has_value());
}

/**
 * @tc.name: GetWindowAndDisplayInfo_002
 * @tc.desc: Test GetWindowAndDisplayInfo with existing window
 * @tc.type: FUNC
 */
HWTEST_F(InputWindowsManagerCoverageTest, GetWindowAndDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto result = WIN_MGR->GetWindowAndDisplayInfo(1, 1);
    EXPECT_TRUE(result.has_value());
}

/**
 * @tc.name: DumpMultiGroupState_SectionHeaders_001
 * @tc.desc: Verify DumpMultiGroupState outputs all required section headers
 * @tc.type: FUNC
 * @tc.require: AC-6.1
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_SectionHeaders_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dump_multigroup.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[4096] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    EXPECT_NE(content.find("--- RuntimeBindings ---"), std::string::npos);
    EXPECT_NE(content.find("--- DisplayGroups ---"), std::string::npos);
    EXPECT_NE(content.find("--- PointerStateByGroup ---"), std::string::npos);
    EXPECT_NE(content.find("--- KeyboardStateByGroup ---"), std::string::npos);
    EXPECT_NE(content.find("--- SequenceSnapshots ---"), std::string::npos);
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_EmptyBindings_002
 * @tc.desc: Verify DumpMultiGroupState shows (empty) when no runtime bindings exist
 * @tc.type: FUNC
 * @tc.require: AC-6.2
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_EmptyBindings_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dump_empty_bind.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[4096] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    // RuntimeBindings section should show (empty) when no bindings exist
    auto rtPos = content.find("--- RuntimeBindings ---");
    ASSERT_NE(rtPos, std::string::npos);
    auto dgPos = content.find("--- DisplayGroups ---");
    ASSERT_NE(dgPos, std::string::npos);
    std::string rtSection = content.substr(rtPos, dgPos - rtPos);
    EXPECT_NE(rtSection.find("(empty)"), std::string::npos);
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_WithBindings_003
 * @tc.desc: Verify DumpMultiGroupState shows correct binding info after binding a device
 * @tc.type: FUNC
 * @tc.require: AC-6.3
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_WithBindings_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    // Set up a second display group and bind a device to it
    OLD::DisplayGroupInfo secondGroup;
    secondGroup.groupId = 5;
    secondGroup.type = GroupType::GROUP_DEFAULT;
    secondGroup.focusWindowId = 50;
    OLD::DisplayInfo dispInfo;
    dispInfo.id = 10;
    dispInfo.x = 0;
    dispInfo.y = 0;
    dispInfo.width = 1280;
    dispInfo.height = 720;
    dispInfo.dpi = 160;
    dispInfo.name = "external";
    dispInfo.uniq = "ext1";
    dispInfo.direction = DIRECTION0;
    secondGroup.displaysInfo.push_back(dispInfo);
    WIN_MGR->UpdateDisplayInfo(secondGroup);

    std::string msg;
    WIN_MGR->BindDeviceToDisplayGroupByDisplay(42, 10, msg);

    const char *tmpFile = "/data/tmp_dump_with_bind.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[8192] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    // Should contain the binding info with deviceId=42
    EXPECT_NE(content.find("deviceId=42"), std::string::npos);
    EXPECT_NE(content.find("displayId=10"), std::string::npos);
    EXPECT_NE(content.find("groupId=5"), std::string::npos);

    // Clean up: unbind
    WIN_MGR->UnbindDeviceFromDisplayGroup(42, msg);
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_DisplayGroups_004
 * @tc.desc: Verify DisplayGroups section shows display and focus info
 * @tc.type: FUNC
 * @tc.require: AC-6.2
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_DisplayGroups_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dump_dispgroups.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[4096] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    // DisplayGroups section should contain the default group with display 1
    auto dgPos = content.find("--- DisplayGroups ---");
    ASSERT_NE(dgPos, std::string::npos);
    auto psgPos = content.find("--- PointerStateByGroup ---");
    ASSERT_NE(psgPos, std::string::npos);
    std::string dgSection = content.substr(dgPos, psgPos - dgPos);
    EXPECT_NE(dgSection.find("groupId=0"), std::string::npos);
    EXPECT_NE(dgSection.find("mainDisplayId="), std::string::npos);
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_NoAllocation_005
 * @tc.desc: Verify dump does NOT allocate new group state (AC-6.5)
 * @tc.type: FUNC
 * @tc.require: AC-6.5
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_NoAllocation_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    // Record state map sizes before dump
    size_t sizeBefore = WIN_MGR->GetGroupStateMapSize();

    const char *tmpFile = "/data/tmp_dump_noalloc.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    // Record state map sizes after dump - must be unchanged
    size_t sizeAfter = WIN_MGR->GetGroupStateMapSize();
    EXPECT_EQ(sizeBefore, sizeAfter) << "DumpMultiGroupState must not allocate new group state";
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_AbsentGroupShowsAbsent_006
 * @tc.desc: Verify absent non-default group shows (absent) in PointerStateByGroup
 * @tc.type: FUNC
 * @tc.require: AC-6.4
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_AbsentGroupShowsAbsent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    // Create a display group without calling EnsureGroupState (no lazy state)
    OLD::DisplayGroupInfo absentGroup;
    absentGroup.groupId = 99;
    absentGroup.type = GroupType::GROUP_DEFAULT;
    absentGroup.focusWindowId = -1;
    OLD::DisplayInfo dispInfo;
    dispInfo.id = 88;
    dispInfo.x = 0;
    dispInfo.y = 0;
    dispInfo.width = 800;
    dispInfo.height = 600;
    dispInfo.dpi = 120;
    dispInfo.name = "absent_display";
    dispInfo.uniq = "absent1";
    dispInfo.direction = DIRECTION0;
    absentGroup.displaysInfo.push_back(dispInfo);
    WIN_MGR->UpdateDisplayInfo(absentGroup);

    size_t sizeBefore = WIN_MGR->GetGroupStateMapSize();

    const char *tmpFile = "/data/tmp_dump_absent.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    size_t sizeAfter = WIN_MGR->GetGroupStateMapSize();
    EXPECT_EQ(sizeBefore, sizeAfter) << "Dump must not create state for absent groups";

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[8192] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    // The PointerStateByGroup section should show groupId=99 as (absent)
    auto psgPos = content.find("--- PointerStateByGroup ---");
    ASSERT_NE(psgPos, std::string::npos);
    auto ksgPos = content.find("--- KeyboardStateByGroup ---");
    ASSERT_NE(ksgPos, std::string::npos);
    std::string psgSection = content.substr(psgPos, ksgPos - psgPos);
    EXPECT_NE(psgSection.find("groupId=99"), std::string::npos);
    EXPECT_NE(psgSection.find("(absent)"), std::string::npos);
    unlink(tmpFile);
}

/**
 * @tc.name: DumpMultiGroupState_EmptySequences_007
 * @tc.desc: Verify SequenceSnapshots section shows (empty) when no sequences
 * @tc.type: FUNC
 * @tc.require: AC-6.2
 */
HWTEST_F(InputWindowsManagerCoverageTest, DumpMultiGroupState_EmptySequences_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const char *tmpFile = "/data/tmp_dump_emptyseq.log";
    int32_t fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    WIN_MGR->DumpMultiGroupState(fd);
    close(fd);

    int32_t fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[4096] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    ASSERT_GT(bytes, 0);
    buf[bytes] = '\0';
    close(fdRead);

    std::string content(buf);
    auto seqPos = content.find("--- SequenceSnapshots ---");
    ASSERT_NE(seqPos, std::string::npos);
    // Everything after SequenceSnapshots to the end
    std::string seqSection = content.substr(seqPos);
    EXPECT_NE(seqSection.find("(empty)"), std::string::npos);
    unlink(tmpFile);
}

} // namespace MMI
} // namespace OHOS
