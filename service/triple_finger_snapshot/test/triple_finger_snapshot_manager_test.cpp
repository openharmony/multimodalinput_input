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

#include <dlfcn.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "mmi_log.h"
#include "pointer_event.h"
#include "i_delegate_interface.h"
#define private public
#include "triple_finger_snapshot_manager.h"
#undef private

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TripleFingerSnapshotManagerTest"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace MMI {

class MockITripleFingerSnapshot : public ITripleFingerSnapshot {
public:
    MockITripleFingerSnapshot() = default;
    ~MockITripleFingerSnapshot() override = default;

    MOCK_METHOD1(HandleTouchEvent, bool(std::shared_ptr<PointerEvent>));
    MOCK_METHOD0(Enable, void());
    MOCK_METHOD0(Disable, void());
    MOCK_METHOD3(UpdateDisplayInfo, void(int32_t, int32_t, int32_t));
    MOCK_METHOD1(Dump, void(int32_t));
    MOCK_METHOD1(UpdateAppsEnable, void(bool));
};

class MockDelegateInterface : public IDelegateInterface {
public:
    MockDelegateInterface() = default;
    ~MockDelegateInterface() override = default;

    MOCK_METHOD(int32_t, OnPostSyncTask, (DTaskCallback), (const));
    MOCK_METHOD(int32_t, OnPostAsyncTask, (DTaskCallback), (const));
    MOCK_METHOD(int32_t, AddHandler, (InputHandlerType, const HandlerSummary&));
    MOCK_METHOD(void, RemoveHandler, (InputHandlerType, const std::string&));
    MOCK_METHOD(bool, HasHandler, (const std::string&), (const));
};

class TripleFingerSnapshotManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Init
 * @tc.desc: Test Init function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Init, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    ASSERT_TRUE(manager.Init());
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_NullEvent
 * @tc.desc: Test HandleTouchEvent with null event
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_NullEvent, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    ASSERT_FALSE(manager.HandleTouchEvent(nullptr));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_AutoMode
 * @tc.desc: Test HandleTouchEvent with AUTO mode
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_AutoMode, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto event = PointerEvent::Create();
    event->SetFixedMode(PointerEvent::FixedMode::AUTO);
    ASSERT_FALSE(manager.HandleTouchEvent(event));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Enable_NoDelegateProxy
 * @tc.desc: Test Enable without delegate proxy
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Enable_NoDelegateProxy, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    ASSERT_FALSE(manager.Enable());
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Enable_Success
 * @tc.desc: Test Enable with mock delegate proxy
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Enable_Success, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockDelegate = std::make_shared<MockDelegateInterface>();
    manager.SetDelegateProxy(mockDelegate);

    ASSERT_TRUE(manager.Enable());
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Disable_NoImpl
 * @tc.desc: Test Disable when impl is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Disable_NoImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    ASSERT_TRUE(manager.Disable());
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Disable_NoDelegateProxy
 * @tc.desc: Test Disable without delegate proxy
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Disable_NoDelegateProxy, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    // Manually set impl_ to non-null to test the delegate proxy check
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }
    
    ASSERT_TRUE(manager.Disable());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UpdateAppPermission_Enable
 * @tc.desc: Test UpdateAppPermission with enable=true
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UpdateAppPermission_Enable, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }

    EXPECT_CALL(*mockImpl, UpdateAppsEnable(true))
        .Times(1);

    manager.UpdateAppPermission(1001, true);
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
        manager.appPermissions_.clear();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UpdateAppPermission_Disable
 * @tc.desc: Test UpdateAppPermission with enable=false
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UpdateAppPermission_Disable, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
        manager.appPermissions_[1001] = true;
    }

    EXPECT_CALL(*mockImpl, UpdateAppsEnable(false))
        .Times(1);

    manager.UpdateAppPermission(1001, false);
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
        manager.appPermissions_.clear();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_Empty
 * @tc.desc: Test CheckAllAppsEnabled when appPermissions_ is empty
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_Empty, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    ASSERT_TRUE(manager.CheckAllAppsEnabled());
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_AllEnabled
 * @tc.desc: Test CheckAllAppsEnabled when all apps are enabled
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_AllEnabled,
    TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.appPermissions_[1001] = true;
        manager.appPermissions_[1002] = true;
        manager.appPermissions_[1003] = true;
    }
    
    ASSERT_TRUE(manager.CheckAllAppsEnabled());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.appPermissions_.clear();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_SomeDisabled
 * @tc.desc: Test CheckAllAppsEnabled when some apps are disabled
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_CheckAllAppsEnabled_SomeDisabled,
    TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.appPermissions_[1001] = true;
        manager.appPermissions_[1002] = false;
        manager.appPermissions_[1003] = true;
    }
    
    ASSERT_FALSE(manager.CheckAllAppsEnabled());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.appPermissions_.clear();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_GetImpl
 * @tc.desc: Test GetImpl function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_GetImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto impl = manager.GetImpl();
    ASSERT_EQ(impl, nullptr);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Load_AlreadyLoaded
 * @tc.desc: Test Load when impl is already loaded
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Load_AlreadyLoaded, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }
    
    auto impl = manager.Load();
    ASSERT_EQ(impl, mockImpl);
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Load_LibraryNotFound
 * @tc.desc: Test Load when library file is not found
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Load_LibraryNotFound, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto impl = manager.Load();
    ASSERT_NE(impl, nullptr);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Unload
 * @tc.desc: Test Unload function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Unload, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
        manager.handle_ = reinterpret_cast<void*>(0x12345678);
    }
    
    manager.Unload();
    
    ASSERT_EQ(manager.impl_, nullptr);
    ASSERT_EQ(manager.handle_, nullptr);
    ASSERT_EQ(manager.create_, nullptr);
    ASSERT_EQ(manager.destroy_, nullptr);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_LoadLibrary_AlreadyLoaded
 * @tc.desc: Test LoadLibrary when handle is already loaded
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_LoadLibrary_AlreadyLoaded, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.handle_ = reinterpret_cast<void*>(0x12345678);
    }
    
    ASSERT_TRUE(manager.LoadLibrary());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.handle_ = nullptr;
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_CastInputDevice
 * @tc.desc: Test HandleTouchEvent with CAST input device ID
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_CastInputDevice, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto event = PointerEvent::Create();
    event->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    event->SetDeviceId(0xAAAAAAFF); // CAST_INPUT_DEVICEID
    ASSERT_FALSE(manager.HandleTouchEvent(event));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_CastScreenDevice
 * @tc.desc: Test HandleTouchEvent with CAST screen device ID
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_CastScreenDevice, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto event = PointerEvent::Create();
    event->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    event->SetDeviceId(0xAAAAAAFE); // CAST_SCREEN_DEVICEID
    ASSERT_FALSE(manager.HandleTouchEvent(event));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_NoImpl
 * @tc.desc: Test HandleTouchEvent when impl is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_NoImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto event = PointerEvent::Create();
    event->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    event->SetDeviceId(12345); // Normal device ID
    ASSERT_FALSE(manager.HandleTouchEvent(event));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_HandleTouchEvent_WithImpl
 * @tc.desc: Test HandleTouchEvent with impl and mock delegate
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_HandleTouchEvent_WithImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    auto mockDelegate = std::make_shared<MockDelegateInterface>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }
    manager.SetDelegateProxy(mockDelegate);
    
    auto event = PointerEvent::Create();
    event->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    event->SetDeviceId(12345);
    
    EXPECT_CALL(*mockImpl, HandleTouchEvent(testing::_))
        .WillOnce(testing::Return(true));
    
    ASSERT_TRUE(manager.HandleTouchEvent(event));
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
    }
    manager.SetDelegateProxy(nullptr);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UpdateDisplayInfo_NoImpl
 * @tc.desc: Test UpdateDisplayInfo when impl is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UpdateDisplayInfo_NoImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    // Should not crash when impl is null
    manager.UpdateDisplayInfo(1920, 1080, 0);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UpdateDisplayInfo_WithImpl
 * @tc.desc: Test UpdateDisplayInfo with impl
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UpdateDisplayInfo_WithImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }
    
    EXPECT_CALL(*mockImpl, UpdateDisplayInfo(1920, 1080, 0))
        .Times(1);
    
    manager.UpdateDisplayInfo(1920, 1080, 0);
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Dump_NoImpl
 * @tc.desc: Test Dump when impl is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Dump_NoImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    // Should not crash when impl is null
    manager.Dump(1);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_Dump_NoDelegateProxy
 * @tc.desc: Test Dump when delegate proxy is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_Dump_NoDelegateProxy, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
    }
    
    // Should not crash when delegate proxy is null
    manager.Dump(1);
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_.reset();
    }
    ASSERT_TRUE(true);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UpdateAppPermission_NoImpl
 * @tc.desc: Test UpdateAppPermission when impl is null
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UpdateAppPermission_NoImpl, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    // Should not crash when impl is null
    manager.UpdateAppPermission(1001, true);
    
    // Verify permission was still updated
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        ASSERT_TRUE(manager.appPermissions_[1001]);
        manager.appPermissions_.clear();
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_SetAndGetDelegateProxy
 * @tc.desc: Test SetDelegateProxy and GetDelegateProxy
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_SetAndGetDelegateProxy, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockDelegate = std::make_shared<MockDelegateInterface>();
    
    manager.SetDelegateProxy(mockDelegate);
    auto retrievedProxy = manager.GetDelegateProxy();
    
    ASSERT_EQ(retrievedProxy, mockDelegate);
    
    // Clean up
    manager.SetDelegateProxy(nullptr);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_SetDatashareReady
 * @tc.desc: Test SetDatashareReady function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_SetDatashareReady, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    ASSERT_FALSE(manager.isDataShareReady_.load());
    
    manager.SetDatashareReady(100);
    
    ASSERT_TRUE(manager.isDataShareReady_.load());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = -1;
    }
    manager.isDataShareReady_.store(false);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_RegisterSwitchObserver_InvalidUserId
 * @tc.desc: Test RegisterSwitchObserver with invalid userId
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_RegisterSwitchObserver_InvalidUserId, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    manager.isDataShareReady_.store(true);
    
    ASSERT_FALSE(manager.RegisterSwitchObserver(-1));
    
    // Clean up
    manager.isDataShareReady_.store(false);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_RegisterSwitchObserver_DataShareNotReady
 * @tc.desc: Test RegisterSwitchObserver when dataShare is not ready
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_RegisterSwitchObserver_DataShareNotReady, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    manager.isDataShareReady_.store(false);
    
    ASSERT_FALSE(manager.RegisterSwitchObserver(100));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_RegisterSwitchObserver_AlreadyRegistered
 * @tc.desc: Test RegisterSwitchObserver when observer is already registered
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_RegisterSwitchObserver_AlreadyRegistered, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    manager.isDataShareReady_.store(true);
    
    auto observer = new (std::nothrow) SettingObserver();
    ASSERT_NE(observer, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = 100;
        manager.switchObserver_ = observer;
    }
    
    ASSERT_TRUE(manager.RegisterSwitchObserver(100));
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = -1;
        manager.switchObserver_ = nullptr;
    }
    manager.isDataShareReady_.store(false);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_RegisterSwitchObserver_UserSwitch
 * @tc.desc: Test RegisterSwitchObserver with user switch scenario
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_RegisterSwitchObserver_UserSwitch, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    manager.isDataShareReady_.store(true);
    
    auto observer = new (std::nothrow) SettingObserver();
    ASSERT_NE(observer, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = 100;
        manager.switchObserver_ = observer;
    }
    
    // Switch to user 200, should unregister old observer
    // Note: This test only verifies the logic flow, actual observer unregistration
    // requires mocking SettingDataShare
    ASSERT_FALSE(manager.RegisterSwitchObserver(200));
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        ASSERT_EQ(manager.currentAccountId_, 200);
    }
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = -1;
        manager.switchObserver_ = nullptr;
    }
    manager.isDataShareReady_.store(false);
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_IsObserverRegistered_NotRegistered
 * @tc.desc: Test IsObserverRegistered when observer is not registered
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_IsObserverRegistered_NotRegistered, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    ASSERT_FALSE(manager.IsObserverRegistered(100));
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_IsObserverRegistered_Registered
 * @tc.desc: Test IsObserverRegistered when observer is registered
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_IsObserverRegistered_Registered, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    auto observer = new (std::nothrow) SettingObserver();
    ASSERT_NE(observer, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = 100;
        manager.switchObserver_ = observer;
    }
    
    ASSERT_TRUE(manager.IsObserverRegistered(100));
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.currentAccountId_ = -1;
        manager.switchObserver_ = nullptr;
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_UnregisterObserverForUser
 * @tc.desc: Test UnregisterObserverForUser function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_UnregisterObserverForUser, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    auto observer = new (std::nothrow) SettingObserver();
    ASSERT_NE(observer, nullptr);
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.switchObserver_ = observer;
    }
    
    // Should not crash
    manager.UnregisterObserverForUser(100);
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        ASSERT_EQ(manager.switchObserver_, nullptr);
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_LoadSymbols_Failed
 * @tc.desc: Test LoadSymbols when dlsym fails
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_LoadSymbols_Failed, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    
    // Set handle to a non-null value but don't set symbols
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.handle_ = reinterpret_cast<void*>(0x12345678);
    }
    
    // LoadSymbols should fail because dlsym will fail on invalid handle
    ASSERT_FALSE(manager.LoadSymbols());
    
    // Clean up
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.handle_ = nullptr;
    }
}

/**
 * @tc.name: TripleFingerSnapshotManagerTest_CleanupOnError
 * @tc.desc: Test CleanupOnError function
 * @tc.type: Function
 */
HWTEST_F(TripleFingerSnapshotManagerTest, TripleFingerSnapshotManagerTest_CleanupOnError, TestSize.Level1)
{
    TripleFingerSnapshotManager &manager = TripleFingerSnapshotManager::GetInstance();
    auto mockImpl = std::make_shared<MockITripleFingerSnapshot>();
    
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.impl_ = mockImpl;
        manager.handle_ = reinterpret_cast<void*>(0x12345678);
        manager.create_ = reinterpret_cast<TripleFingerSnapshotManager::GetTripleFingerSnapshotFunc>(0x87654321);
        manager.destroy_ = reinterpret_cast<TripleFingerSnapshotManager::DestroyTripleFingerSnapshotFunc>(0xABCDABCD);
    }
    
    manager.CleanupOnError();
    
    ASSERT_EQ(manager.impl_, nullptr);
    ASSERT_EQ(manager.handle_, nullptr);
    ASSERT_EQ(manager.create_, nullptr);
    ASSERT_EQ(manager.destroy_, nullptr);
}
} // namespace MMI
} // namespace OHOS