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

#include <gtest/gtest.h>
#include "fingerprint_event_processor.h"
#include "general_keyboard.h"
#include "general_mouse.h"
#include "input_device_manager.h"
#include "libinput_wrapper.h"
#include "libinput-private.h"
#include "mmi_log.h"
#include "event_log_helper.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingerprintEventProcessorTest"

class FingerprintEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

private:
    static void SetupVirtualDevice();
    static void CloseVirtualDevice();
    static GeneralMouse vMouse_;
    static GeneralKeyboard vKeyboard_;
    static LibinputWrapper libinput_;
};

GeneralMouse FingerprintEventProcessorTest::vMouse_;
GeneralKeyboard FingerprintEventProcessorTest::vKeyboard_;
LibinputWrapper FingerprintEventProcessorTest::libinput_;

void FingerprintEventProcessorTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupVirtualDevice();
}

void FingerprintEventProcessorTest::TearDownTestCase(void)
{
    CloseVirtualDevice();
}

void FingerprintEventProcessorTest::SetupVirtualDevice()
{
    ASSERT_TRUE(vMouse_.SetUp());
    std::cout << "device node name: " << vMouse_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vMouse_.GetDevPath()));

    ASSERT_TRUE(vKeyboard_.SetUp());
    std::cout << "device node name: " << vKeyboard_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vKeyboard_.GetDevPath()));

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
}

void FingerprintEventProcessorTest::CloseVirtualDevice()
{
    libinput_.RemovePath(vMouse_.GetDevPath());
    vMouse_.Close();
    libinput_.RemovePath(vKeyboard_.GetDevPath());
    vKeyboard_.Close();
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_IsFingerprintEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    FingerprintEventProcessor fpeProcessor;
    bool ret = fpeProcessor.IsFingerprintEvent(event);
    ASSERT_FALSE(ret);
}

HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_HandleFingerprintEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    FingerprintEventProcessor fpeProcessor;
    int32_t ret = fpeProcessor.HandleFingerprintEvent(event);
    ASSERT_NE(ret, RET_ERR);
}

HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalyseKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vKeyboard_.SendEvent(EV_KEY, 29, 1);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 1);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vKeyboard_.SendEvent(EV_KEY, KEY_C, 0);
    vKeyboard_.SendEvent(EV_KEY, 29, 0);
    vKeyboard_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    FingerprintEventProcessor fpeProcessor;
    int32_t ret = fpeProcessor.AnalyseKeyEvent(event);
    ASSERT_NE(ret, RET_ERR);
}

HWTEST_F(FingerprintEventProcessorTest, FingerprintEventProcessorTest_AnalysePointEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    FingerprintEventProcessor fpeProcessor;
    int32_t ret = fpeProcessor.AnalysePointEvent(event);
    ASSERT_NE(ret, RET_ERR);
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS