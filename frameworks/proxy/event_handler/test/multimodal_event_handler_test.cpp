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
#include <cJSON.h>
#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "define_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalEventHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
char g_cfgName[] { "custom_input_product_config.json" };
}
using namespace testing::ext;
using namespace testing;

class MultimodalEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

private:
    void SerializeInputProductConfig(cJSON *jsonProductConfig);
    template<typename T>
    void BuildInputProductConfig(T maxTouchPoints);
    void BuildInputProductConfig3();
    void BuildInputProductConfig6();
    void BuildInputProductConfig7();
    void BuildInputProductConfig8();
};

void MultimodalEventHandlerTest::SerializeInputProductConfig(cJSON *jsonProductConfig)
{
    CHKPV(jsonProductConfig);
    auto sProductConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonProductConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sProductConfig.get();
        ofs.flush();
        ofs.close();
    }
}

template<typename T>
void MultimodalEventHandlerTest::BuildInputProductConfig(T maxTouchPoints)
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonTouchscreen = cJSON_CreateObject();
    CHKPV(jsonTouchscreen);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "touchscreen", jsonTouchscreen)) {
        cJSON_Delete(jsonTouchscreen);
        return;
    }
    cJSON *jsonMaxTouchPoints = nullptr;

    if constexpr(std::is_integral_v<T> || std::is_floating_point_v<T>) {
        jsonMaxTouchPoints = cJSON_CreateNumber(maxTouchPoints);
    } else if (std::is_same_v<std::remove_const_t<T>, char*>) {
        jsonMaxTouchPoints = cJSON_CreateRaw(maxTouchPoints);
    }
    CHKPV(jsonMaxTouchPoints);
    if (!cJSON_AddItemToObject(jsonTouchscreen, "MaxTouchPoints", jsonMaxTouchPoints)) {
        cJSON_Delete(jsonMaxTouchPoints);
        return;
    }
    SerializeInputProductConfig(jsonProductConfig.get());
}

void MultimodalEventHandlerTest::BuildInputProductConfig3()
{
    const std::ofstream::pos_type tailPos { 4096 };
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs.seekp(tailPos);
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }
}

void MultimodalEventHandlerTest::BuildInputProductConfig6()
{
    int32_t maxTouchPoints { 9 };
    auto jsonMaxTouchPoints = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateNumber(maxTouchPoints),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    SerializeInputProductConfig(jsonMaxTouchPoints.get());
}

void MultimodalEventHandlerTest::BuildInputProductConfig7()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    SerializeInputProductConfig(jsonProductConfig.get());
}

void MultimodalEventHandlerTest::BuildInputProductConfig8()
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonTouchscreen = cJSON_CreateObject();
    CHKPV(jsonTouchscreen);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "touchscreen", jsonTouchscreen)) {
        cJSON_Delete(jsonTouchscreen);
        return;
    }
    SerializeInputProductConfig(jsonProductConfig.get());
}

/**
 * @tc.name: MultimodalEventHandlerTest_ReadMaxMultiTouchPointNum_001
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(nullptr));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_002
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_003
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildInputProductConfig3();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_004
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    auto uid = ::getuid();
    int32_t inputUid { 6606 };
    ::setuid(inputUid);
    int32_t maxTouchPoints { 11 };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));
    EXPECT_EQ(::chmod(g_cfgName, 0), 0);

    int32_t panglaiUid { 7655 };
    ::setuid(panglaiUid);
    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    ::setuid(uid);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_005
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    char maxTouchPoints[] { "9a" };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_006
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildInputProductConfig6();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_007
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildInputProductConfig7();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_008
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    BuildInputProductConfig8();
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_009
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    double maxTouchPoints { 9.01 };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_010
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    int32_t maxTouchPoints { 11 };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_011
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    int32_t maxTouchPoints { -1 };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, -1);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: ReadMaxMultiTouchPointNum_012
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, ReadMaxMultiTouchPointNum_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    int32_t maxTouchPoints { 10 };
    BuildInputProductConfig(maxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxMultiTouchPointNum {};
    MultimodalEventHandler::ReadMaxMultiTouchPointNum(maxMultiTouchPointNum);
    EXPECT_EQ(maxMultiTouchPointNum, maxTouchPoints);
    std::filesystem::remove(g_cfgName);
}

/**
 * @tc.name: GetMaxMultiTouchPointNum_001
 * @tc.desc: Test MultimodalEventHandler::ReadMaxMultiTouchPointNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalEventHandlerTest, GetMaxMultiTouchPointNum_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetOneCfgFile).WillOnce(testing::Return(g_cfgName));

    constexpr int32_t expectedMaxTouchPoints { 10 };
    BuildInputProductConfig(expectedMaxTouchPoints);
    std::error_code ec {};
    EXPECT_TRUE(std::filesystem::exists(g_cfgName, ec));

    int32_t maxTouchPoints {};
    auto ret = MultimodalEventHandler::GetMaxMultiTouchPointNum(maxTouchPoints);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(maxTouchPoints, expectedMaxTouchPoints);
    std::filesystem::remove(g_cfgName);
}
} // namespace MMI
} // namespace OHOS
