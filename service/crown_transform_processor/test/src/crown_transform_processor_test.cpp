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

#include <cstdio>
#include <gtest/gtest.h>

#include "display_manager.h"

#include "crown_transform_processor.h"
#include "general_crown.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
public:
static void SetUpTestCase(void);
static void TearDownTestCase(void);
static void SetupCrown();
static void CloseCrown();
static void UpdateDisplayInfo();
static void InitHandler();
libinput_event *GetEvent();

private:
static GeneralCrown vCrown_;

void CrownTransformProcessorTest::SetUpTestCase(void)
{
ASSERT_TRUE(libinput_.Init());
SetupCrown();
UpdateDisplayInfo();

InitHandler();
}

void CrownTransformProcessorTest::TearDownTestCase(void)
{
{
libinput_.RemovePath(vCrown_.GetDevPath());
vCrown_.Close();
}

void CrownTransformProcessorTest::UpdateDisplayInfo()
{
auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
ASSERT_TRUE(display != nullptr);

DisplayGroupInfo displays {
    .width = display->GetWidth(),
    .height = display->GetHeight(),
    .focusWindowId = -1,
};
displays.displaysInfo.push_back(DisplayInfo {
    .name = "default display",
    .width = display->GetWidth(),
    .height = display->GetHeight(),
});
WIN_MGR->UpdateDisplayInfo(displays);
}

void CrownTransformProcessorTest::InitHandler()
{
UDSServer udsServer;
std::shared_ptrOHOS::MMI::InputEventHandler inputHandler = InputHandler;
ASSERT_NO_FATAL_FAILURE(inputHandler->Init(udsServer));
std::string name = libinput_device_get_name(dev);
MMI_HILOGD("pointer device: %{public}s", name.c_str());
ASSERT_TRUE(CROWN_EVENT_HDR->IsCrownEvent(event));
}

/**

@tc.name: CrownTransformProcessorTest_NormalizeRotateEvent_003
@tc.desc: Test NormalizeRotateEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_NormalizeRotateEvent_003, TestSize.Level1)
{
CALL_TEST_DEBUG;
vCrown_.SendEvent(EV_REL, REL_WHEEL, 5);
vCrown_.SendEvent(EV_SYN, SYN_REPORT, 0);
libinput_event *event = GetEvent();
ASSERT_TRUE(event != nullptr);
struct libinput_device *dev = libinput_event_get_device(event);
ASSERT_TRUE(dev != nullptr);
std::string name = libinput_device_get_name(dev);
MMI_HILOGD("pointer device: %{public}s", name.c_str());
int32_t result = CROWN_EVENT_HDR->NormalizeRotateEvent(event);
EXPECT_NE(result, RET_OK);
}


/**
 * @tc.name: CrownTransformProcessorTest_NormalizeRotateEvent_003
 * @tc.desc: Test NormalizeRotateEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_NormalizeRotateEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vCrown_.SendEvent(EV_REL, REL_WHEEL, 5);
    vCrown_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = GetEvent();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::string name = libinput_device_get_name(dev);
    MMI_HILOGD("pointer device: %{public}s", name.c_str());
    int32_t result = CROWN_EVENT_HDR->NormalizeRotateEvent(event);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateBegin_004
 * @tc.desc: Test HandleCrownRotateBegin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateBegin_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vCrown_.SendEvent(EV_REL, REL_WHEEL, 30);
    vCrown_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = GetEvent();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::string name = libinput_device_get_name(dev);
    MMI_HILOGD("pointer device: %{public}s", name.c_str());
    struct libinput_event_pointer *rawPointerEvent = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(rawPointerEvent != nullptr);
    int32_t result = CROWN_EVENT_HDR->HandleCrownRotateBegin(rawPointerEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateUpdate_005
 * @tc.desc: Test HandleCrownRotateUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateUpdate_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vCrown_.SendEvent(EV_REL, REL_WHEEL, -30);
    vCrown_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = GetEvent();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::string name = libinput_device_get_name(dev);
    MMI_HILOGD("pointer device: %{public}s", name.c_str());
    struct libinput_event_pointer *rawPointerEvent = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(rawPointerEvent != nullptr);
    int32_t result = CROWN_EVENT_HDR->HandleCrownRotateUpdate(rawPointerEvent);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateEnd_006
 * @tc.desc: Test HandleCrownRotateEnd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateEnd_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(CROWN_EVENT_HDR->HandleCrownRotateEnd());
}

/**
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_007
 * @tc.desc: Test HandleCrownRotateBeginAndUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotateBeginAndUpdate_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    vCrown_.SendEvent(EV_REL, REL_WHEEL, 10);
    vCrown_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = GetEvent();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::string name = libinput_device_get_name(dev);
    MMI_HILOGD("pointer device: %{public}s", name.c_str());
    struct libinput_event_pointer *rawPointerEvent = libinput_event_get_pointer_event(event);
    ASSERT_TRUE(rawPointerEvent != nullptr);
    int32_t result = CROWN_EVENT_HDR->HandleCrownRotateBeginAndUpdate(rawPointerEvent,
        PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: CrownTransformProcessorTest_HandleCrownRotatePostInner_008
 * @tc.desc: Test HandleCrownRotatePostInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_HandleCrownRotatePostInner_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    double angularVelocity = 67.0;
    double degree = 11.0;
    int32_t action = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
    ASSERT_NO_FATAL_FAILURE(CROWN_EVENT_HDR->HandleCrownRotatePostInner(angularVelocity, degree, action));
}

/**
 * @tc.name: CrownTransformProcessorTest_DumpInner_009
 * @tc.desc: Test DumpInner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_DumpInner_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(CROWN_EVENT_HDR->DumpInner());
}

/**
 * @tc.name: CrownTransformProcessorTest_Dump_010
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CrownTransformProcessorTest, CrownTransformProcessorTest_Dump_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args;
    std::vector<std::string> idNames;
    int32_t fd = 0;
    CROWN_EVENT_HDR->Dump(fd, args);
    ASSERT_EQ(args, idNames);
}
}
}