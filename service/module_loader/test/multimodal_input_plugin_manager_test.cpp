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

#include "general_mouse.h"
#include "libinput_wrapper.h"
#include "multimodal_input_plugin_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputPluginManagerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

const std::string PATH { "/system/lib64/multimodalinput/autorun" };

class MultimodalInputPluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void SetupMouse();
    static void CloseMouse();

    void SetUp();
private:
    std::shared_ptr<InputPluginManager> manager;
    static LibinputWrapper libinput_;
    static GeneralMouse vMouse_;
};

GeneralMouse MultimodalInputPluginManagerTest::vMouse_;
LibinputWrapper MultimodalInputPluginManagerTest::libinput_;


void MultimodalInputPluginManagerTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupMouse();
}

void MultimodalInputPluginManagerTest::TearDownTestCase(void)
{
    CloseMouse();
}

void MultimodalInputPluginManagerTest::SetupMouse()
{
    ASSERT_TRUE(vMouse_.SetUp());
    std::cout << "device node name: " << vMouse_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vMouse_.GetDevPath()));

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
}

void MultimodalInputPluginManagerTest::CloseMouse()
{
    libinput_.RemovePath(vMouse_.GetDevPath());
    vMouse_.Close();
}

void MultimodalInputPluginManagerTest::SetUp()
{
    manager = std::make_shared<InputPluginManager>(PATH);
}

/**
 * @tc.name  : MultimodalInputPluginManagerTest_Init_001
 * @tc.number: Init_001
 * @tc.desc  : 测试初始化是否成功
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_Init_001, TestSize.Level0) {
    int32_t valV1 = manager->Init();
    EXPECT_EQ(valV1, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleEvent_02
 * @tc.desc: Test_HandleEvent_02
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    int32_t result = manager->HandleEvent(event, GetSysClockTime(),
                     InputPluginStage::INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_03
 * @tc.desc: Test_IntermediateEndEvent_03
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IntermediateEndEvent_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vMouse_.SendEvent(EV_REL, REL_X, 5);
    vMouse_.SendEvent(EV_REL, REL_Y, -10);
    vMouse_.SendEvent(EV_SYN, SYN_REPORT, 0);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;

    EXPECT_TRUE(manager->IntermediateEndEvent(event));
}

} // namespace MMI
} // namespace OHOS
