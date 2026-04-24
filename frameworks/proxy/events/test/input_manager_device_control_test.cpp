/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "input_manager.h"
#include "define_multimodal.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerDeviceControlTest"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class InputManagerDeviceControlTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void InputManagerDeviceControlTest::SetUpTestCase()
{}

void InputManagerDeviceControlTest::TearDownTestCase()
{}

void InputManagerDeviceControlTest::SetUp()
{}

void InputManagerDeviceControlTest::TearDown()
{}

/**
 * @tc.name: DisableInputEventDispatch_001
 * @tc.desc: Test DisableInputEventDispatch with disabled=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, DisableInputEventDispatch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DisableInputEventDispatch_002
 * @tc.desc: Test DisableInputEventDispatch with disabled=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, DisableInputEventDispatch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->DisableInputEventDispatch(true);
    MMI_HILOGI("DisableInputEventDispatch(true) ret:%{public}d", ret);
    EXPECT_EQ(ret, RET_OK);
    InputManager::GetInstance()->DisableInputEventDispatch(false);
}

/**
 * @tc.name: DisableInputEventDispatch_003
 * @tc.desc: Test DisableInputEventDispatch idempotency - disable twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, DisableInputEventDispatch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret1 = InputManager::GetInstance()->DisableInputEventDispatch(true);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = InputManager::GetInstance()->DisableInputEventDispatch(true);
    EXPECT_EQ(ret2, RET_OK);

    int32_t ret3 = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret3, RET_OK);
}

/**
 * @tc.name: DisableInputEventDispatch_004
 * @tc.desc: Test DisableInputEventDispatch idempotency - enable twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, DisableInputEventDispatch_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret1 = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: DisableInputEventDispatch_005
 * @tc.desc: Test DisableInputEventDispatch disable then enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, DisableInputEventDispatch_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret1 = InputManager::GetInstance()->DisableInputEventDispatch(true);
    EXPECT_EQ(ret1, RET_OK);

    int32_t ret2 = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: SetInputDeviceEnabled_001
 * @tc.desc: Test SetInputDeviceEnabled with invalid device id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, SetInputDeviceEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t INVALID_DEVICE_ID = 99999;
    auto ret = InputManager::GetInstance()->SetInputDeviceEnabled(INVALID_DEVICE_ID, true,
        [](int32_t result) {
            EXPECT_EQ(result, ERROR_DEVICE_NOT_EXIST);
        });
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PriorityRule_001
 * @tc.desc: Test priority rule - SetInputDeviceEnabled should fail after DisableInputEventDispatch(true)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, PriorityRule_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = InputManager::GetInstance()->DisableInputEventDispatch(true);
    EXPECT_EQ(ret, RET_OK);

    constexpr int32_t TEST_DEVICE_ID { 1 };
    InputManager::GetInstance()->SetInputDeviceEnabled(TEST_DEVICE_ID, false,
        [](int32_t result) {
            EXPECT_EQ(result, RET_OK);
        });

    auto ret2 = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: PriorityRule_002
 * @tc.desc: Test priority rule - SetInputDeviceEnabled should work after DisableInputEventDispatch(false)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, PriorityRule_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->DisableInputEventDispatch(false);
    EXPECT_EQ(ret, RET_OK);

    constexpr int32_t TEST_DEVICE_ID { 1 };
    auto ret2 = InputManager::GetInstance()->SetInputDeviceEnabled(TEST_DEVICE_ID, false,
        [](int32_t result) {
            EXPECT_TRUE(result == RET_OK || result == ERROR_DEVICE_NOT_EXIST);
        });
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: EnableInputExtension_001
 * @tc.desc: Test EnableInputExtension with enabled=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_001";
    int32_t ret = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    MMI_HILOGI("EnableInputExtension(true) ret:%{public}d", ret);
    EXPECT_EQ(ret, PARAM_INPUT_INVALID);
    InputManager::GetInstance()->EnableInputExtension(uuid, false);
}

/**
 * @tc.name: EnableInputExtension_002
 * @tc.desc: Test EnableInputExtension with enabled=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_002";
    int32_t ret = InputManager::GetInstance()->EnableInputExtension(uuid, false);
    MMI_HILOGI("EnableInputExtension(false) ret:%{public}d", ret);
    EXPECT_EQ(ret, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: EnableInputExtension_003
 * @tc.desc: Test EnableInputExtension with empty uuid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "";
    int32_t ret = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    MMI_HILOGI("EnableInputExtension with empty uuid ret:%{public}d", ret);
    EXPECT_EQ(ret, PARAM_INPUT_INVALID);
    InputManager::GetInstance()->EnableInputExtension(uuid, false);
}

/**
 * @tc.name: EnableInputExtension_004
 * @tc.desc: Test EnableInputExtension enable then disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_004";
    int32_t ret1 = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    EXPECT_EQ(ret1, PARAM_INPUT_INVALID);

    int32_t ret2 = InputManager::GetInstance()->EnableInputExtension(uuid, false);
    EXPECT_EQ(ret2, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: EnableInputExtension_005
 * @tc.desc: Test EnableInputExtension idempotency - enable twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_005";
    int32_t ret1 = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    EXPECT_EQ(ret1, PARAM_INPUT_INVALID);

    int32_t ret2 = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    EXPECT_EQ(ret2, PARAM_INPUT_INVALID);

    InputManager::GetInstance()->EnableInputExtension(uuid, false);
}

/**
 * @tc.name: EnableInputExtension_006
 * @tc.desc: Test EnableInputExtension idempotency - disable twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_006";
    int32_t ret1 = InputManager::GetInstance()->EnableInputExtension(uuid, false);
    EXPECT_EQ(ret1, PARAM_INPUT_INVALID);

    int32_t ret2 = InputManager::GetInstance()->EnableInputExtension(uuid, false);
    EXPECT_EQ(ret2, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: EnableInputExtension_007
 * @tc.desc: Test EnableInputExtension with multiple different uuids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid1 = "extension_uuid_A";
    const std::string uuid2 = "extension_uuid_B";
    const std::string uuid3 = "extension_uuid_C";

    int32_t ret1 = InputManager::GetInstance()->EnableInputExtension(uuid1, true);
    EXPECT_EQ(ret1, PARAM_INPUT_INVALID);

    int32_t ret2 = InputManager::GetInstance()->EnableInputExtension(uuid2, true);
    EXPECT_EQ(ret2, PARAM_INPUT_INVALID);

    int32_t ret3 = InputManager::GetInstance()->EnableInputExtension(uuid3, true);
    EXPECT_EQ(ret3, PARAM_INPUT_INVALID);

    InputManager::GetInstance()->EnableInputExtension(uuid1, false);
    InputManager::GetInstance()->EnableInputExtension(uuid2, false);
    InputManager::GetInstance()->EnableInputExtension(uuid3, false);
}

/**
 * @tc.name: EnableInputExtension_008
 * @tc.desc: Test EnableInputExtension disable then enable (reverse toggle)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerDeviceControlTest, EnableInputExtension_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    const std::string uuid = "test_extension_uuid_008";
    int32_t ret1 = InputManager::GetInstance()->EnableInputExtension(uuid, false);
    EXPECT_EQ(ret1, PARAM_INPUT_INVALID);

    int32_t ret2 = InputManager::GetInstance()->EnableInputExtension(uuid, true);
    EXPECT_EQ(ret2, PARAM_INPUT_INVALID);

    InputManager::GetInstance()->EnableInputExtension(uuid, false);
}
} // namespace MMI
} // namespace OHOS
