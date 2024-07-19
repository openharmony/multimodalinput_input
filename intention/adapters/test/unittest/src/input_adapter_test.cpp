/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <memory>
#include <utility>
#include <vector>

#include <unistd.h>

#include "accesstoken_kit.h"
#include <gtest/gtest.h>
#include "input_device.h"
#include "pointer_event.h"
#include "securec.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "input_adapter.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "InputAdapterTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_CORE { "system_core" };
uint64_t g_tokenID { 0 };
const char* g_cores[] = { "ohos.permission.INPUT_MONITORING" };
const char* g_coresInject[] = { "ohos.permission.INJECT_INPUT_EVENT" };
} // namespace

class InputAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void SetPermission(const std::string &level, const char** perms, size_t permAmount);
    static void RemovePermission();
};

void InputAdapterTest::SetPermission(const std::string &level, const char** perms, size_t permAmount)
{
    CALL_DEBUG_ENTER;
    if (perms == nullptr || permAmount == 0) {
        FI_HILOGE("The perms is empty");
        return;
    }

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permAmount,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "InputAdapterTest",
        .aplStr = level.c_str(),
    };
    g_tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(g_tokenID);
    OHOS::Security::AccessToken::AccessTokenKit::AccessTokenKit::ReloadNativeTokenInfo();
}

void InputAdapterTest::RemovePermission()
{
    CALL_DEBUG_ENTER;
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenID);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to remove permission");
        return;
    }
}

void InputAdapterTest::SetUpTestCase() {}

void InputAdapterTest::SetUp() {}

void InputAdapterTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: TestPointerAddMonitor
 * @tc.desc: Test AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestPointerAddMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_FALSE(monitorId > 0);
    inputAdapter->RemoveMonitor(monitorId);
    RemovePermission();
}

/**
 * @tc.name: TestPointerAddMonitor
 * @tc.desc: Test AddMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestKeyAddMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t monitorId = inputAdapter->AddMonitor(callback);
    ASSERT_FALSE(monitorId > 0);
    inputAdapter->RemoveMonitor(monitorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddKeyEventInterceptor
 * @tc.desc: Test AddKeyEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddKeyEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_FALSE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddPointerEventInterceptor
 * @tc.desc: Test AddPointerEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddPointerEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto callback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(callback);
    ASSERT_FALSE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddBothEventInterceptor
 * @tc.desc: Test AddBothEventInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddBothEventInterceptor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto pointerCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) {
        FI_HILOGI("OnEvent");
    };
    auto keyCallback = [] (std::shared_ptr<OHOS::MMI::KeyEvent>) {
        FI_HILOGI("OnEvent");
    };
    int32_t interceptorId = inputAdapter->AddInterceptor(pointerCallback, keyCallback);
    ASSERT_FALSE(interceptorId > 0);
    inputAdapter->RemoveInterceptor(interceptorId);
    RemovePermission();
}

/**
 * @tc.name: TestAddFilter
 * @tc.desc: Test AddFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, AddFilter, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    auto filterCallback = [] (std::shared_ptr<OHOS::MMI::PointerEvent>) -> bool {
        FI_HILOGI("OnEvent");
        return true;
    };
    int32_t filterId = inputAdapter->AddFilter(filterCallback);
    ASSERT_FALSE(filterId > 0);
    inputAdapter->RemoveFilter(filterId);
    RemovePermission();
}

/**
 * @tc.name: TestSetPointerVisibility
 * @tc.desc: Test SetPointerVisibility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSetPointerVisibility, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t filterId = inputAdapter->SetPointerVisibility(true);
    ASSERT_FALSE(filterId > 0);
    RemovePermission();
}

/**
 * @tc.name: TestSetPointerLocation
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSetPointerLocation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t filterId = inputAdapter->SetPointerLocation(0, 0);
    ASSERT_FALSE(filterId > 0);
    RemovePermission();
}

/**
 * @tc.name: TestEnableInputDevice
 * @tc.desc: Test EnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestEnableInputDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_cores, sizeof(g_cores) / sizeof(g_cores[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    int32_t ret = inputAdapter->EnableInputDevice(true);
    ASSERT_EQ(ret, RET_OK);
    RemovePermission();
}

/**
 * @tc.name: TestSimulateKeyEvent
 * @tc.desc: Test SimulateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSimulateKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::KeyEvent::Create()));
    RemovePermission();
}

/**
 * @tc.name: TestSimulatePointerEvent
 * @tc.desc: Test SimulatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputAdapterTest, TestSimulatePointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetPermission(SYSTEM_CORE, g_coresInject, sizeof(g_coresInject) / sizeof(g_coresInject[0]));
    std::shared_ptr<IInputAdapter> inputAdapter = std::make_shared<InputAdapter>();
    ASSERT_NO_FATAL_FAILURE(inputAdapter->SimulateInputEvent(MMI::PointerEvent::Create()));
    RemovePermission();
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
