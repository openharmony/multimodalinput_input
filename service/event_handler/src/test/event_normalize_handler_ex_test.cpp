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

#include "event_normalize_handler.h"
#include "input_device_manager.h"
#include "libinput.h"
#include "touch_event_normalize.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventNormalizeHandlerEXTest"

struct udev_device {
    uint32_t tags { 0 };
};

struct libinput_device {
    struct udev_device udevDev;
    unsigned int busType { 0 };
    unsigned int version { 0 };
    unsigned int product { 0 };
    unsigned int vendor { 0 };
    char name[9];
};

struct libinput_event {
    enum LibinputEventType type;
    struct libinput_device *device;
};

extern "C" {
const char *LibinputDeviceGetName(struct libinput_device *device)
{
    const char* pName = device->name;
    return pName;
}
}

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
} // namespace

class EventTestHandler final : public IInputEventHandler {
public:
    EventTestHandler() = default;
    DISALLOW_COPY_AND_MOVE(EventTestHandler);
    ~EventTestHandler() override = default;
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) {}
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
};

bool InputDeviceManager::IsInputDeviceEnable(int32_t deviceId)
{
    return true;
}

std::shared_ptr<PointerEvent> TouchEventNormalize::OnLibInput(struct libinput_event *event, DeviceType deviceType)
{
    return PointerEvent::Create();
}

class EventNormalizeHandlerEXTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EventNormalizeHandlerEXTest::SetUpTestCase(void)
{
}

void EventNormalizeHandlerEXTest::TearDownTestCase(void)
{
}

void EventNormalizeHandlerEXTest::SetUp()
{
}

void EventNormalizeHandlerEXTest::TearDown()
{
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleEvent_001
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    int64_t frameTime = 10000;
    libinput_event event;
    event.type = LIBINPUT_EVENT_TOUCHPAD_ACTIVE;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    handler.HandleEvent(&event, frameTime);
    EXPECT_EQ(handler.nextHandler_, nullptr);
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleEvent_002
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    int64_t frameTime = 10000;
    libinput_event event;
    event.type = LIBINPUT_EVENT_GESTURE_PINCH_BEGIN;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    handler.HandleEvent(&event, frameTime);
    EXPECT_EQ(handler.nextHandler_, nullptr);
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleTouchPadAction_001
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleTouchPadAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event;
    event.type = LIBINPUT_EVENT_TOUCHPAD_ACTIVE;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    handler.nextHandler_ = std::make_shared<EventTestHandler>();
    handler.HandleTouchPadAction(&event);
    EXPECT_EQ(event.device->version, 1);
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandleTouchPadAction_002
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandleTouchPadAction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    libinput_event event;
    event.type = LIBINPUT_EVENT_TOUCHPAD_MOTION;
    struct libinput_device libDev {
        .udevDev { 2 },
        .busType = 1,
        .version = 1,
        .product = 1,
        .vendor = 1,
        .name = "test",
    };
    event.device = &libDev;
    handler.nextHandler_ = std::make_shared<EventTestHandler>();
    handler.HandleTouchPadAction(&event);
    EXPECT_EQ(event.device->vendor, 1);
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandlePointerEvent_001
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandlePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    handler.nextHandler_ = std::make_shared<EventTestHandler>();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_TOUCHPAD_ACTIVE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    handler.HandlePointerEvent(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerId(), 0);
}

/**
 * @tc.name: EventNormalizeHandlerEXTest_HandlePointerEvent_002
 * @tc.desc: Test the function TerminateAxis
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerEXTest, EventNormalizeHandlerEXTest_HandlePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventNormalizeHandler handler;
    handler.nextHandler_ = std::make_shared<EventTestHandler>();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    handler.HandlePointerEvent(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerId(), 0);
}
} // namespace MMI
} // namespace OHOS