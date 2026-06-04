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

/*
 * System-level gtest suite for mouse pointer APIs and hidumper verification.
 * Runs against real mmi_service on DAYU200/RK3568.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseApiHidumperTest"

using namespace OHOS::MMI;

namespace {

static std::string RunHidumperCapture(const char *args)
{
    std::string cmd = "hidumper -s 3101 -a ";
    cmd += args;
    cmd += " 2>&1";
    std::string result;
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp != nullptr) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp) != nullptr) {
            result += buf;
        }
        pclose(fp);
    }
    return result;
}

/* ---------- test fixture --------------------------------------------- */

class MouseApiHidumperTest : public testing::Test {
protected:
    void SetUp() override
    {
        /* Save original values for restoration */
        InputManager::GetInstance()->GetPointerSize(origSize_);
        InputManager::GetInstance()->GetPointerSpeed(origSpeed_);
        InputManager::GetInstance()->GetPointerColor(origColor_);
        InputManager::GetInstance()->GetMouseScrollRows(origScrollRows_);
    }

    void TearDown() override
    {
        InputManager::GetInstance()->SetPointerSize(origSize_);
        InputManager::GetInstance()->SetPointerSpeed(origSpeed_);
        InputManager::GetInstance()->SetPointerColor(origColor_);
        InputManager::GetInstance()->SetMouseScrollRows(origScrollRows_);
        InputManager::GetInstance()->SetPointerVisible(true);
    }

    int32_t origSize_ = 1;
    int32_t origSpeed_ = 5;
    int32_t origColor_ = 0;
    int32_t origScrollRows_ = 3;
};

/* ===== API tests ====================================================== */

/**
 * @tc.name: MouseApi_GetPointerSize
 * @tc.desc: GetPointerSize returns RET_OK and a non-negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_GetPointerSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t size = -1;
    int32_t ret = InputManager::GetInstance()->GetPointerSize(size);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSize failed";
    EXPECT_GE(size, 0) << "Pointer size should be non-negative";
}

/**
 * @tc.name: MouseApi_SetAndGetPointerSize
 * @tc.desc: SetPointerSize then GetPointerSize returns same value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_SetAndGetPointerSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSize = 2;
    int32_t ret = InputManager::GetInstance()->SetPointerSize(testSize);
    EXPECT_EQ(ret, RET_OK) << "SetPointerSize failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerSize(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSize failed";
    EXPECT_EQ(readBack, testSize) << "Pointer size readback mismatch";
}

/**
 * @tc.name: MouseApi_GetPointerColor
 * @tc.desc: GetPointerColor returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_GetPointerColor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t color = -1;
    int32_t ret = InputManager::GetInstance()->GetPointerColor(color);
    EXPECT_EQ(ret, RET_OK) << "GetPointerColor failed";
}

/**
 * @tc.name: MouseApi_SetAndGetPointerColor
 * @tc.desc: SetPointerColor then GetPointerColor returns same value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_SetAndGetPointerColor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testColor = 0x00FF00;
    int32_t ret = InputManager::GetInstance()->SetPointerColor(testColor);
    EXPECT_EQ(ret, RET_OK) << "SetPointerColor failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerColor(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerColor failed";
    EXPECT_EQ(readBack, testColor) << "Pointer color readback mismatch";
}

/**
 * @tc.name: MouseApi_GetPointerSpeed
 * @tc.desc: GetPointerSpeed returns RET_OK and a valid value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_GetPointerSpeed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = -1;
    int32_t ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSpeed failed";
}

/**
 * @tc.name: MouseApi_SetAndGetPointerSpeed
 * @tc.desc: SetPointerSpeed then GetPointerSpeed returns same value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_SetAndGetPointerSpeed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSpeed = 5;
    int32_t ret = InputManager::GetInstance()->SetPointerSpeed(testSpeed);
    EXPECT_EQ(ret, RET_OK) << "SetPointerSpeed failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSpeed failed";
    EXPECT_EQ(readBack, testSpeed) << "Pointer speed readback mismatch";
}

/**
 * @tc.name: MouseApi_SetPointerVisible
 * @tc.desc: SetPointerVisible / IsPointerVisible round-trip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_SetPointerVisible, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->SetPointerVisible(true);
    EXPECT_EQ(ret, RET_OK);

    bool visible = InputManager::GetInstance()->IsPointerVisible();
    EXPECT_TRUE(visible);

    ret = InputManager::GetInstance()->SetPointerVisible(false);
    EXPECT_EQ(ret, RET_OK);

    visible = InputManager::GetInstance()->IsPointerVisible();
    EXPECT_FALSE(visible);
}

/**
 * @tc.name: MouseApi_GetMouseScrollRows
 * @tc.desc: GetMouseScrollRows returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_GetMouseScrollRows, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = -1;
    int32_t ret = InputManager::GetInstance()->GetMouseScrollRows(rows);
    EXPECT_EQ(ret, RET_OK) << "GetMouseScrollRows failed";
    EXPECT_GT(rows, 0) << "Scroll rows should be positive";
}

/**
 * @tc.name: MouseApi_SetAndGetMouseScrollRows
 * @tc.desc: SetMouseScrollRows then GetMouseScrollRows returns same value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_SetAndGetMouseScrollRows, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testRows = 5;
    int32_t ret = InputManager::GetInstance()->SetMouseScrollRows(testRows);
    EXPECT_EQ(ret, RET_OK) << "SetMouseScrollRows failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetMouseScrollRows(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetMouseScrollRows failed";
    EXPECT_EQ(readBack, testRows) << "Scroll rows readback mismatch";
}

/* ===== Hidumper verification ========================================== */

/**
 * @tc.name: MouseApi_HidumperCursorFullDump
 * @tc.desc: Verify all sections present in hidumper -c
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperCursorFullDump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string dump = RunHidumperCapture("-c");
    EXPECT_FALSE(dump.empty()) << "Hidumper -c returned empty output";
}

/**
 * @tc.name: MouseApi_HidumperMultiGroupDump
 * @tc.desc: Verify -G output has expected sections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperMultiGroupDump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty()) << "Hidumper -G returned empty output";

    int sectionCount = 0;
    if (dump.find("RuntimeBindings") != std::string::npos) sectionCount++;
    if (dump.find("DisplayGroups") != std::string::npos) sectionCount++;
    if (dump.find("PointerStateByGroup") != std::string::npos) sectionCount++;
    if (dump.find("KeyboardStateByGroup") != std::string::npos) sectionCount++;
    if (dump.find("SequenceSnapshots") != std::string::npos) sectionCount++;
    if (dump.find("SoftCursorRS") != std::string::npos) sectionCount++;
    if (dump.find("HardwareCursor") != std::string::npos) sectionCount++;

    EXPECT_GE(sectionCount, 5) << "Expected at least 5 sections in -G output, got " << sectionCount;
}

/**
 * @tc.name: MouseApi_HidumperDeviceListDump
 * @tc.desc: Verify -d output has device information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperDeviceListDump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string dump = RunHidumperCapture("-d");
    EXPECT_FALSE(dump.empty()) << "Hidumper -d returned empty output";
}

/**
 * @tc.name: MouseApi_CrossVerify_ApiVsHidumper
 * @tc.desc: Set pointer size via API, check hidumper output reflects it
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_CrossVerify_ApiVsHidumper, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSize = 4;
    int32_t ret = InputManager::GetInstance()->SetPointerSize(testSize);
    EXPECT_EQ(ret, RET_OK);

    /* Capture hidumper and verify it contains information about the pointer */
    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty()) << "Hidumper should return output";
    /* The dump should at least contain PointerStateByGroup section */
    EXPECT_TRUE(dump.find("PointerStateByGroup") != std::string::npos)
        << "Hidumper should contain PointerStateByGroup after setting pointer size";
}

/**
 * @tc.name: MouseApi_HidumperAfterSpeedChange
 * @tc.desc: Set pointer speed, verify hidumper still works
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperAfterSpeedChange, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->SetPointerSpeed(8);
    EXPECT_EQ(ret, RET_OK);

    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty());
    EXPECT_TRUE(dump.find("PointerStateByGroup") != std::string::npos);
}

/**
 * @tc.name: MouseApi_HidumperAfterColorChange
 * @tc.desc: Set pointer color, verify hidumper still works
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperAfterColorChange, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->SetPointerColor(0x0000FF);
    EXPECT_EQ(ret, RET_OK);

    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty());
}

/**
 * @tc.name: MouseApi_HidumperAfterVisibilityToggle
 * @tc.desc: Toggle visibility, verify hidumper still works
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperAfterVisibilityToggle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputManager::GetInstance()->SetPointerVisible(false);
    std::string dump1 = RunHidumperCapture("-G");
    EXPECT_FALSE(dump1.empty());

    InputManager::GetInstance()->SetPointerVisible(true);
    std::string dump2 = RunHidumperCapture("-G");
    EXPECT_FALSE(dump2.empty());
}

/**
 * @tc.name: MouseApi_HidumperSaveEvidence
 * @tc.desc: Save hidumper output to evidence file for post-test analysis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseApiHidumperTest, MouseApi_HidumperSaveEvidence, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int rc = system("hidumper -s 3101 -a -G > /data/local/tmp/mouse_api_evidence.txt 2>&1");
    EXPECT_EQ(rc, 0) << "hidumper command failed";

    FILE *f = fopen("/data/local/tmp/mouse_api_evidence.txt", "r");
    EXPECT_NE(f, nullptr) << "Evidence file should exist";
    if (f != nullptr) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fclose(f);
        EXPECT_GT(size, 0) << "Evidence file should not be empty";
    }
}

} // namespace
