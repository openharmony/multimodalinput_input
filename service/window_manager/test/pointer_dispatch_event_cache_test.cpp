/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "pointer_dispatch_event_cache.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;

constexpr int32_t POINTER_ID { 1 };
constexpr int32_t TOUCH_DEVICE_ID { 11 };
constexpr int32_t STYLUS_DEVICE_ID { 22 };
constexpr int32_t OTHER_DEVICE_ID { 33 };
} // namespace

class PointerDispatchEventCacheTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

protected:
    static std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t pointerId, int32_t deviceId, int32_t toolType)
    {
        auto pointerEvent = PointerEvent::Create();
        if (pointerEvent == nullptr) {
            return nullptr;
        }
        PointerEvent::PointerItem pointerItem;
        pointerItem.SetPointerId(pointerId);
        pointerItem.SetDeviceId(deviceId);
        pointerItem.SetToolType(toolType);
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetDeviceId(deviceId);
        pointerEvent->AddPointerItem(pointerItem);
        return pointerEvent;
    }
};

/**
 * @tc.name: PointerDispatchEventCacheTest_001
 * @tc.desc: Verify nullptr update keeps cache empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_001, TestSize.Level1)
{
    PointerDispatchEventCache cache;

    cache.Update(nullptr);

    EXPECT_EQ(cache.GetTouchEvent(), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_MOVE), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), nullptr);
}

/**
 * @tc.name: PointerDispatchEventCacheTest_002
 * @tc.desc: Verify touch and stylus events are cached separately
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_002, TestSize.Level1)
{
    PointerDispatchEventCache cache;
    auto touchEvent = CreatePointerEvent(POINTER_ID, TOUCH_DEVICE_ID, PointerEvent::TOOL_TYPE_FINGER);
    auto stylusEvent = CreatePointerEvent(POINTER_ID, STYLUS_DEVICE_ID, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_NE(touchEvent, nullptr);
    ASSERT_NE(stylusEvent, nullptr);

    cache.Update(touchEvent);
    cache.Update(stylusEvent);

    EXPECT_EQ(cache.GetTouchEvent(), touchEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_MOVE), touchEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), stylusEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_OUT_WINDOW), stylusEvent);
}

/**
 * @tc.name: PointerDispatchEventCacheTest_003
 * @tc.desc: Verify pencil tool type is treated as stylus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_003, TestSize.Level1)
{
    PointerDispatchEventCache cache;
    auto pencilEvent = CreatePointerEvent(POINTER_ID, STYLUS_DEVICE_ID, PointerEvent::TOOL_TYPE_PENCIL);
    ASSERT_NE(pencilEvent, nullptr);

    cache.Update(pencilEvent);

    EXPECT_EQ(cache.GetTouchEvent(), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), pencilEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_MOVE), nullptr);
}

/**
 * @tc.name: PointerDispatchEventCacheTest_004
 * @tc.desc: Verify missing pointer item falls back to touch cache
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_004, TestSize.Level1)
{
    PointerDispatchEventCache cache;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(POINTER_ID);
    pointerEvent->SetDeviceId(TOUCH_DEVICE_ID);

    cache.Update(pointerEvent);

    EXPECT_EQ(cache.GetTouchEvent(), pointerEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_MOVE), pointerEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), nullptr);
}

/**
 * @tc.name: PointerDispatchEventCacheTest_005
 * @tc.desc: Verify ClearDeviceEvents only clears matching device caches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_005, TestSize.Level1)
{
    PointerDispatchEventCache cache;
    auto touchEvent = CreatePointerEvent(POINTER_ID, TOUCH_DEVICE_ID, PointerEvent::TOOL_TYPE_FINGER);
    auto stylusEvent = CreatePointerEvent(POINTER_ID, STYLUS_DEVICE_ID, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_NE(touchEvent, nullptr);
    ASSERT_NE(stylusEvent, nullptr);

    cache.Update(touchEvent);
    cache.Update(stylusEvent);
    cache.ClearDeviceEvents(OTHER_DEVICE_ID);

    EXPECT_EQ(cache.GetTouchEvent(), touchEvent);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), stylusEvent);

    cache.ClearDeviceEvents(TOUCH_DEVICE_ID);
    EXPECT_EQ(cache.GetTouchEvent(), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), stylusEvent);

    cache.ClearDeviceEvents(STYLUS_DEVICE_ID);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), nullptr);
}

/**
 * @tc.name: PointerDispatchEventCacheTest_006
 * @tc.desc: Verify ClearTouch and Reset clear expected caches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDispatchEventCacheTest, PointerDispatchEventCacheTest_006, TestSize.Level1)
{
    PointerDispatchEventCache cache;
    auto touchEvent = CreatePointerEvent(POINTER_ID, TOUCH_DEVICE_ID, PointerEvent::TOOL_TYPE_FINGER);
    auto stylusEvent = CreatePointerEvent(POINTER_ID, STYLUS_DEVICE_ID, PointerEvent::TOOL_TYPE_PEN);
    ASSERT_NE(touchEvent, nullptr);
    ASSERT_NE(stylusEvent, nullptr);

    cache.Update(touchEvent);
    cache.Update(stylusEvent);
    cache.ClearTouch();

    EXPECT_EQ(cache.GetTouchEvent(), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), stylusEvent);

    cache.Reset();

    EXPECT_EQ(cache.GetTouchEvent(), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_LEVITATE_IN_WINDOW), nullptr);
    EXPECT_EQ(cache.GetForDispatch(PointerEvent::POINTER_ACTION_MOVE), nullptr);
}
} // namespace MMI
} // namespace OHOS
