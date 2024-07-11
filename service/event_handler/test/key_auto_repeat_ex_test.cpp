/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "key_auto_repeat.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyAutoRepeatExTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class KeyAutoRepeatExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void KeyAutoRepeatExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void KeyAutoRepeatExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: KeyAutoRepeatExTest_RemoveDeviceConfig
 * @tc.desc: Cover if (iter == deviceConfig_.end()) branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_RemoveDeviceConfig, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 10;
    EXPECT_CALL(*messageParcelMock_, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));
    KeyAutoRepeat keyAutoRepeat;
    libinput_device device {};
    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.RemoveDeviceConfig(&device));
}

/**
 * @tc.name: KeyAutoRepeatExTest_RemoveDeviceConfig_001
 * @tc.desc: Cover the else branch of if (iter == deviceConfig_.end())
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyAutoRepeatExTest, KeyAutoRepeatExTest_RemoveDeviceConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 15;
    EXPECT_CALL(*messageParcelMock_, FindInputDeviceId(_)).WillRepeatedly(Return(deviceId));
    KeyAutoRepeat keyAutoRepeat;
    libinput_device device {};
    DeviceConfig deviceConfig;
    keyAutoRepeat.deviceConfig_.insert(std::make_pair(deviceId, deviceConfig));
    EXPECT_NO_FATAL_FAILURE(keyAutoRepeat.RemoveDeviceConfig(&device));
}
} // namespace MMI
} // namespace OHOS