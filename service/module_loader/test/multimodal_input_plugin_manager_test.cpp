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
#include "libinput_interface.h"
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
    EXPECT_GE(result, RET_OK);
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

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetInstance_001
 * @tc.desc: GetInstance will return not nullptr when instance_=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetInstance_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string dir = "/system/lib64/multimodalinput/autorun/libpointer_predict_insertion.z.so";
    InputPluginManager::instance_ = nullptr;
    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance(dir);
    ASSERT_NE(ptr, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetInstance_002
 * @tc.desc: GetInstance will return not nullptr when instance_!=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetInstance_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_001
 * @tc.desc: Init will return RET_OK when directory_ is valid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    int32_t ret = ptr->Init();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_002
 * @tc.desc: Init will return RET_OK when directory_ is invalid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string dir = "/test/test/test/test/";
    InputPluginManager::instance_ = nullptr;
    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance(dir);
    ASSERT_NE(ptr, nullptr);

    int32_t ret = ptr->Init();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_003
 * @tc.desc: Init will return RET_OK when directory_ is invalid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string dir = "/";
    InputPluginManager::instance_ = nullptr;
    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance(dir);
    ASSERT_NE(ptr, nullptr);

    int32_t ret = ptr->Init();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_004
 * @tc.desc: Init will return RET_OK when directory_ is invalid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_004,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string dir = "/system/lib64/multimodalinput/autorun/test.c";
    InputPluginManager::instance_ = nullptr;
    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance(dir);
    ASSERT_NE(ptr, nullptr);

    int32_t ret = ptr->Init();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_005
 * @tc.desc: Init will return RET_OK when directory_ is invalid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_005,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string dir = "/system/lib64/multimodalinput/autorun/test.so";
    InputPluginManager::instance_ = nullptr;
    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance(dir);
    ASSERT_NE(ptr, nullptr);

    int32_t ret = ptr->Init();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_001
 * @tc.desc: LoadPlugin will return true when LoadPlugin get valid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    std::string dir = "/system/lib64/multimodalinput/autorun/libpointer_predict_insertion.z.so";
    bool ret = ptr->LoadPlugin(dir);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_002
 * @tc.desc: LoadPlugin will return true when LoadPlugin get valid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    std::string dir = "/system/lib64/multimodalinput/autorun/test.so";
    bool ret = ptr->LoadPlugin(dir);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PrintPlugins_001
 * @tc.desc: PrintPlugins will print plugin info when plugins_!=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PrintPlugins_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::string path = "/system/lib64/multimodalinput/autorun/libpointer_predict_insertion.z.so";
    void *handle = dlopen(path.c_str(), RTLD_LAZY);
    ASSERT_NE(handle, nullptr);

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();
    ptr->plugins_.insert({stage, {nullptr}});

    ASSERT_NO_FATAL_FAILURE(ptr->PrintPlugins());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginAssignmentCallBack_001
 * @tc.desc: Nothing will happenned when callback=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginAssignmentCallBack_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::function<void(libinput_event *, int64_t)> callback = nullptr;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    ASSERT_NO_FATAL_FAILURE(ptr->PluginAssignmentCallBack(callback, stage));
}

static void DispatchEvent(libinput_event *event, int64_t frameTime)
{
    (void)event;
    (void)frameTime;
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginAssignmentCallBack_002
 * @tc.desc: Nothing will happenned when callback!=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginAssignmentCallBack_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    InputPlugin inputPlugin;
    std::function<void(libinput_event *, int64_t)> callback = DispatchEvent;

    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    ASSERT_NO_FATAL_FAILURE(ptr->PluginAssignmentCallBack(callback, stage));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleEvent_001
 * @tc.desc: HandleEvent will return RET_NOTDO when event=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    int64_t frameTime = 0;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    int32_t ret = ptr->HandleEvent(nullptr, frameTime, stage);
    EXPECT_EQ(ret, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_001
 * @tc.desc: DoHandleEvent will return RET_NOTDO when event=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    int64_t frameTime = 0;
    InputPlugin iplugin;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    int32_t ret = ptr->DoHandleEvent(nullptr, frameTime, &iplugin, stage);
    EXPECT_EQ(ret, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_002
 * @tc.desc: DoHandleEvent will return RET_NOTDO when event=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    int64_t frameTime = 0;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    int32_t ret = ptr->DoHandleEvent(nullptr, frameTime, nullptr, stage);
    EXPECT_EQ(ret, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_003
 * @tc.desc: DoHandleEvent will return RET_NOTDO when event=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);

    int64_t frameTime = 0;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    int32_t ret = ptr->DoHandleEvent(event, frameTime, nullptr, stage);
    EXPECT_EQ(ret, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_004
 * @tc.desc: DoHandleEvent will return RET_NOTDO when event=nullptr
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);

    int64_t frameTime = 0;
    InputPlugin iplugin;
    std::shared_ptr<IInputPlugin> iPin;
    InputPluginStage stage = iPin->GetStage();

    int32_t ret = ptr->DoHandleEvent(event, frameTime, &iplugin, stage);
    EXPECT_EQ(ret, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_001
 * @tc.desc: IntermediateEndEvent will true when libinput_event_type before LIBINPUT_EVENT_GESTURE_HOLD_END
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IntermediateEndEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event event;
    event.type = LIBINPUT_EVENT_TABLET_TOOL_TIP;

    bool ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_POINTER_MOTION;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_POINTER_AXIS;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_002
 * @tc.desc: IntermediateEndEvent will true when libinput_event_type before LIBINPUT_EVENT_GESTURE_HOLD_END
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IntermediateEndEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event event;
    event.type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;

    bool ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCH_UP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCH_UP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCH_MOTION;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCH_CANCEL;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCHPAD_UP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_003
 * @tc.desc: IntermediateEndEvent will true when libinput_event_type before LIBINPUT_EVENT_GESTURE_HOLD_END
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IntermediateEndEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event event;
    event.type = LIBINPUT_EVENT_TABLET_TOOL_AXIS;

    bool ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_SWIPE_END;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_KEYBOARD_KEY;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_SWIPE_END;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_PINCH_UPDATE;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);

    event.type = LIBINPUT_EVENT_GESTURE_PINCH_END;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_004
 * @tc.desc: IntermediateEndEvent will true when libinput_event_type before LIBINPUT_EVENT_GESTURE_HOLD_END
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IntermediateEndEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    std::shared_ptr<InputPluginManager> ptr = InputPluginManager::GetInstance();
    ASSERT_NE(ptr, nullptr);

    libinput_event event;
    event.type = LIBINPUT_EVENT_KEYBOARD_KEY;

    bool ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_POINTER_BUTTON;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_POINTER_TAP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_POINTER_TAP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);

    event.type = LIBINPUT_EVENT_TABLET_TOOL_TIP;
    ret = ptr->IntermediateEndEvent(&event);
    EXPECT_EQ(ret, false);
}

} // namespace MMI
} // namespace OHOS
