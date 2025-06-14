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

#include <cstdio>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_device_consumer_handler.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceConsumerHandlerTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

const std::string PROGRAM_NAME { "uds_session_test" };
constexpr int32_t MODULE_TYPE { 1 };
constexpr int32_t UDS_FD { 1 };
constexpr int32_t UDS_UID { 100 };
constexpr int32_t UDS_PID { 100 };

class InputDeviceConsumerHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputDeviceConsumerHandlerTest::SetUpTestCase(void)
{
}

void InputDeviceConsumerHandlerTest::TearDownTestCase(void)
{
}

void InputDeviceConsumerHandlerTest::SetUp()
{
}

void InputDeviceConsumerHandlerTest::TearDown()
{
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::string name = "test";
    deviceNames.push_back("ttttt");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->SetDeviceConsumerHandler(deviceNames, sess);
    DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_ClearDeviceConsumerHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_ClearDeviceConsumerHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    deviceNames.push_back("test");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->ClearDeviceConsumerHandler(deviceNames, sess);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_RemoveDeviceHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_RemoveDeviceHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    deviceNames.push_back("test");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->deviceConsumerHandler_.RemoveDeviceHandler(deviceNames, sess);
    ASSERT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
