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

#include <fstream>
#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>

#include "mmi_log.h"
#include "key_map_manager.h"
#include "key_map_manager_mock.h"
#include "config_policy_utils.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMapManagerTest"
#undef MAX_PATH_LEN
#define MAX_PATH_LEN              256

namespace OHOS {
namespace MMI {

namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class KeyMapManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyMapManagerTest_GetProFilePath_001
 * @tc.desc: Test the funcation GetProFilePath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetProFilePath_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    static char testFile[] = "example.pro";
    EXPECT_CALL(mocker, GetProFileAbsPath)
        .WillRepeatedly(Return(testFile));

    std::ofstream ofs("example.pro");
    EXPECT_TRUE(ofs.is_open());
    ofs << "KEY_BTN_1 123 1111\n" << std::endl;
    std::string testPathSuffix = "example";
    std::string result = KeyMapMgr->GetProFilePath(testPathSuffix);
    std::string expectReutrn = "example.pro";
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    if (std::remove(testFile) == 0) {
        std::cout << "test file removed success" << std::endl;
    } else {
        std::cerr << "test file removed fail" << std::endl;
    }
}

/**
 * @tc.name: KeyMapManagerTest_GetProFilePath_002
 * @tc.desc: Test the funcation GetProFilePath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyMapManagerTest, KeyMapManagerTest_GetProFilePath_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    KeyMgrMock mocker;
    static char testFile[] = "example.pro";
    char testFile1[MAX_PATH_LEN] = { };
    char * testFile2 = nullptr;
    char testFile3[MAX_PATH_LEN + 2] = { };
    for (int i = 0; i < MAX_PATH_LEN + 1; ++i) {
        testFile3[i] = 'A';
    }
    EXPECT_CALL(mocker, GetProFileAbsPath)
        .WillOnce(Return(testFile1))
        .WillOnce(Return(testFile2))
        .WillOnce(Return(testFile3));;

    std::ofstream ofs("example.pro");
    EXPECT_TRUE(ofs.is_open());
    ofs << "KEY_BRL_DOT10 506 3210 HOS_KEY_BRL_DOT10\n" << std::endl;
    std::string testPathSuffix = "example";
    std::string result = KeyMapMgr->GetProFilePath(testPathSuffix);
    std::string expectReutrn = "/vendor/etc/keymap/example.pro";
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    result = KeyMapMgr->GetProFilePath(testPathSuffix);
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    result = KeyMapMgr->GetProFilePath(testPathSuffix);
    EXPECT_STREQ(result.c_str(), expectReutrn.c_str());

    if (std::remove(testFile) == 0) {
        std::cout << "test file removed success" << std::endl;
    } else {
        std::cerr << "test file removed fail" << std::endl;
    }
}

} // namespace MMI
} // namespace OHOS
