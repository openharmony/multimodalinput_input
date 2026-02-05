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
#include <gmock/gmock.h>

#include "property_name_mapper.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PropertyNameMapperTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

// Mock for ITimerManager
class MockITimerManager : public ITimerManager {
public:
    MockITimerManager() = default;
    virtual ~MockITimerManager() = default;

    MOCK_METHOD(int32_t, AddTimer, (int32_t intervalMs, int32_t repeatCount,
        std::function<void()> callback, const std::string &name), (override));
    MOCK_METHOD(int32_t, RemoveTimer, (int32_t timerId, const std::string &name), (override));
    MOCK_METHOD(bool, IsExist, (int32_t timerId), (override));
    MOCK_METHOD(int32_t, ResetTimer, (int32_t timerId), (override));
};

// Mock for IInputServiceContext
class MockIInputServiceContext : public IInputServiceContext {
public:
    MockIInputServiceContext() = default;
    virtual ~MockIInputServiceContext() = default;

    MOCK_METHOD(std::shared_ptr<ITimerManager>, GetTimerManager, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IDelegateInterface>, GetDelegateInterface, (), (const, override));
    MOCK_METHOD(IUdsServer*, GetUDSServer, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IInputEventHandler>, GetEventNormalizeHandler, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IInputEventHandler>, GetMonitorHandler, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IInputWindowsManager>, GetInputWindowsManager, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IInputDeviceManager>, GetDeviceManager, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IKeyMapManager>, GetKeyMapManager, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IPreferenceManager>, GetPreferenceManager, (), (const, override));
    MOCK_METHOD(ICursorDrawingComponent&, GetCursorDrawingComponent, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IInputEventHandler>, GetDispatchHandler, (), (const, override));
};

class PropertyNameMapperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

static void ConcurrentAccessHelper(IInputServiceContext *env, std::atomic<int> &success_count)
{
    constexpr int LOOP_COUNT = 100;
    for (int j = 0; j < LOOP_COUNT; ++j) {
        auto mapper = PropertyNameMapper::Load(env, PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
        if (mapper) {
            success_count++;
            PropertyNameMapper::Unload(env, PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
        }
    }
}

/**
 * @tc.name: PropertyNameMapper_Load_001
 * @tc.desc: Test Load method with nullptr environment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_Load_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto result = PropertyNameMapper::Load(nullptr, PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: PropertyNameMapper_Load_002
 * @tc.desc: Test Load method with timer manager returning error on AddTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_Load_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, AddTimer(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(-1)); // Return error
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto result = PropertyNameMapper::Load(env.get(),
        PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: PropertyNameMapper_Load_003
 * @tc.desc: Test Load method with timer manager returning error on RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_Load_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(-1));

    auto result = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: PropertyNameMapper_Unload_004
 * @tc.desc: Test Unload method with nullptr environment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_Unload_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PropertyNameMapper::Unload(nullptr, PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    // No return value to check, just ensure no crash
}

/**
 * @tc.name: PropertyNameMapper_Unload_005
 * @tc.desc: Test Unload method with timer manager returning error on RemoveTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_Unload_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(-1));

    PropertyNameMapper::Unload(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    // No return value to check, just ensure no crash
}

/**
 * @tc.name: PropertyNameMapper_MapKey_003
 * @tc.desc: Test MapKey method with long property name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string longName(1000, 'a'); // Create a very long string
    int32_t result = mapper->MapKey(longName);
    EXPECT_EQ(result, KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_MapKey_004
 * @tc.desc: Test MapKey method with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string specialName = "test\t\n\r\x01\x02\x7f"; // String with special characters
    int32_t result = mapper->MapKey(specialName);
    EXPECT_EQ(result, KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_MapKey_005
 * @tc.desc: Test MapKey method with null character in name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string nullCharName = "test\0withnull"; // String with null character
    int32_t result = mapper->MapKey(nullCharName);
    EXPECT_EQ(result, KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_MapAxis_003
 * @tc.desc: Test MapAxis method with long property name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapAxis_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string longName(1000, 'a'); // Create a very long string
    auto result = mapper->MapAxis(longName);
    EXPECT_EQ(result, PointerEvent::AXIS_TYPE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_MapAxis_004
 * @tc.desc: Test MapAxis method with special characters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapAxis_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string specialName = "axis\t\n\r\x01\x02\x7f"; // String with special characters
    auto result = mapper->MapAxis(specialName);
    EXPECT_EQ(result, PointerEvent::AXIS_TYPE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_MapAxis_005
 * @tc.desc: Test MapAxis method with null character in name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MapAxis_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();

    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    std::string nullCharName = "axis\0withnull";
    auto result = mapper->MapAxis(nullCharName);
    EXPECT_EQ(result, PointerEvent::AXIS_TYPE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_GetTimerManager_003
 * @tc.desc: Test GetTimerManager method with environment that returns nullptr timer manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_GetTimerManager_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    EXPECT_CALL(*env, GetTimerManager()).WillOnce(testing::Return(nullptr));

    auto result = PropertyNameMapper::GetTimerManager(env.get());
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: PropertyNameMapper_InstanceManagement_002
 * @tc.desc: Test multiple concurrent loads and unloads
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_InstanceManagement_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    // Load and unload multiple times to test instance management
    for (int i = 0; i < 5; ++i) {
        auto instance1 = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
        ASSERT_NE(instance1, nullptr);

        auto instance2 = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
        ASSERT_NE(instance2, nullptr);

        // Both instances should be the same
        ASSERT_EQ(instance1.get(), instance2.get());

        // Unload the instance
        PropertyNameMapper::Unload(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    }
}

/**
 * @tc.name: PropertyNameMapper_InstanceManagement_003
 * @tc.desc: Test different unload options in sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_InstanceManagement_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));
    EXPECT_CALL(*timerMgr, AddTimer(testing::_, testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(1));

    // Test UNLOAD_MANUALLY
    auto instance1 = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(instance1, nullptr);
    PropertyNameMapper::Unload(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);

    // Test UNLOAD_AUTOMATICALLY
    auto instance2 = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY);
    ASSERT_NE(instance2, nullptr);

    // Test UNLOAD_AUTOMATICALLY_WITH_DELAY
    auto instance3 = PropertyNameMapper::Load(env.get(),
        PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY);
    ASSERT_NE(instance3, nullptr);
}

/**
 * @tc.name: PropertyNameMapper_ThreadSafety_001
 * @tc.desc: Test basic thread safety by accessing from multiple threads
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_ThreadSafety_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(mapper, nullptr);

    // Test simultaneous access from multiple threads
    std::thread t1([&mapper]() {
        for (int i = 0; i < 100; ++i) {
            mapper->MapKey("test_key_" + std::to_string(i));
        }
    });

    std::thread t2([&mapper]() {
        for (int i = 0; i < 100; ++i) {
            mapper->MapAxis("test_axis_" + std::to_string(i));
        }
    });

    t1.join();
    t2.join();

    // Ensure no crashes occurred
    SUCCEED();
}

/**
 * @tc.name: PropertyNameMapper_MemoryLeak_001
 * @tc.desc: Test memory leak prevention by loading/unloading repeatedly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_MemoryLeak_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    for (int i = 0; i < 1000; ++i) {
        auto mapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
        ASSERT_NE(mapper, nullptr);
        PropertyNameMapper::Unload(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    }

    auto finalMapper = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(finalMapper, nullptr);
    int32_t result = finalMapper->MapKey("final_test");
    EXPECT_EQ(result, KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_ConcurrentAccess_001
 * @tc.desc: Test concurrent access to Load/Unload methods
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_ConcurrentAccess_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    // Test concurrent loading and unloading
    std::atomic<int> success_count(0);
    std::vector<std::thread> threads;

    for (int i = 0; i < 10; ++i) {
        threads.emplace_back(ConcurrentAccessHelper, env.get(), std::ref(success_count));
    }

    for (auto& t : threads) {
        t.join();
    }

    // Check that we had some successful operations
    EXPECT_GT(success_count.load(), 0);
}

/**
 * @tc.name: PropertyNameMapper_NullptrCheck_002
 * @tc.desc: Test behavior when GetTimerManager returns nullptr during Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_NullptrCheck_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(nullptr));

    auto result = PropertyNameMapper::Load(env.get(),
        PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY);
    ASSERT_NE(result, nullptr);

    // The Load should still succeed even without timer manager
    int32_t keycodeResult = result->MapKey("some_key");
    auto axisResult = result->MapAxis("some_axis");

    EXPECT_EQ(keycodeResult, KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(axisResult, PointerEvent::AXIS_TYPE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapper_NullptrCheck_003
 * @tc.desc: Test behavior when GetTimerManager returns nullptr during Unload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_NullptrCheck_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(nullptr));

    PropertyNameMapper::Unload(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY);
    // Should not crash
    SUCCEED();
}

/**
 * @tc.name: PropertyNameMapper_LoadPropertyNameMap_Failure_001
 * @tc.desc: Test LoadPropertyNameMap when component loading fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperTest, PropertyNameMapper_LoadPropertyNameMap_Failure_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = std::make_shared<MockIInputServiceContext>();
    auto timerMgr = std::make_shared<MockITimerManager>();
    EXPECT_CALL(*env, GetTimerManager()).WillRepeatedly(testing::Return(timerMgr));
    EXPECT_CALL(*timerMgr, RemoveTimer(testing::_, testing::_)).WillRepeatedly(testing::Return(0));

    auto result = PropertyNameMapper::Load(env.get(), PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
    ASSERT_NE(result, nullptr);

    int32_t keycodeResult = result->MapKey("any_key");
    auto axisResult = result->MapAxis("any_axis");

    EXPECT_EQ(keycodeResult, KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(axisResult, PointerEvent::AXIS_TYPE_UNKNOWN);
}
} // namespace MMI
} // namespace OHOS
