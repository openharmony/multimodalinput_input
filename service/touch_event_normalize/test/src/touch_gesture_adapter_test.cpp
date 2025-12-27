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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "config_policy_utils.h"
#include "input_event_handler.h"
#include "input_service_context.h"
#include "touch_gesture_adapter.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureAdapterTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
char g_cfgName[] { "custom_input_product_config.json" };
constexpr int32_t DUMMY_VALUE { -1 };
}

class TouchGestureAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}

private:
    void BuildInputProductConfig(const TouchGestureParameter &param);
    void SerializeInputProductConfig(cJSON *jsonProductConfig);

    template<typename T>
    bool AddTouchGestureParam(cJSON *jsonTouchGesture, const char *name, T value);

    InputServiceContext env_ {};
};

void TouchGestureAdapterTest::SetUpTestCase()
{
    InputHandler->BuildInputHandlerChain();
}

void TouchGestureAdapterTest::BuildInputProductConfig(const TouchGestureParameter &param)
{
    auto jsonProductConfig = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonProductConfig);
    auto jsonTouchGesture = cJSON_CreateObject();
    CHKPV(jsonTouchGesture);
    if (!cJSON_AddItemToObject(jsonProductConfig.get(), "TouchGesture", jsonTouchGesture)) {
        cJSON_Delete(jsonTouchGesture);
        return;
    }
    AddTouchGestureParam(jsonTouchGesture, "MaxFingerSpacing", param.GetMaxFingerSpacing());
    AddTouchGestureParam(jsonTouchGesture, "MaxDownInterval", param.GetMaxDownInterval());
    AddTouchGestureParam(jsonTouchGesture, "FingerMovementThreshold", param.GetFingerMovementThreshold());
    AddTouchGestureParam(jsonTouchGesture, "FingerCountOffsetForPinch", param.GetFingerCountOffsetForPinch());
    AddTouchGestureParam(jsonTouchGesture, "ContinuousPinchesForNotification",
        param.GetContinuousPinchesForNotification());
    AddTouchGestureParam(jsonTouchGesture, "MinGravityOffsetForPinch", param.GetMinGravityOffsetForPinch());
    AddTouchGestureParam(jsonTouchGesture, "MinKeepTimeForSwipe", param.GetMinKeepTimeForSwipe());
    SerializeInputProductConfig(jsonProductConfig.get());
}

template<typename T>
bool TouchGestureAdapterTest::AddTouchGestureParam(cJSON *jsonTouchGesture, const char *name, T value)
{
    if constexpr(std::is_integral_v<T> || std::is_floating_point_v<T>) {
        if (static_cast<int32_t>(value) == DUMMY_VALUE) {
            return true;
        }
        cJSON *jsonParam = cJSON_CreateNumber(value);
        if (jsonParam == nullptr) {
            return false;
        }
        if (!cJSON_AddItemToObject(jsonTouchGesture, name, jsonParam)) {
            cJSON_Delete(jsonParam);
            return false;
        }
        return true;
    }
    return false;
}

void TouchGestureAdapterTest::SerializeInputProductConfig(cJSON *jsonProductConfig)
{
    CHKPV(jsonProductConfig);
    auto sProductConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonProductConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    std::ofstream ofs(g_cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sProductConfig.get();
        ofs.flush();
        ofs.close();
    }
}

/**
 * @tc.name: TouchGestureParameter_Load_001
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    int32_t minKeepTime { 30 };
    param.minKeepTimeForSwipe_ = minKeepTime;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    EXPECT_EQ(param1.GetMinKeepTimeForSwipe(), minKeepTime);
}

/**
 * @tc.name: TouchGestureParameter_Load_002
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    param.fingerCountOffsetForPinch_ = DUMMY_VALUE;
    param.continuousPinchesForNotification_ = DUMMY_VALUE;
    param.minKeepTimeForSwipe_ = DUMMY_VALUE;
    param.maxDownInterval_ = DUMMY_VALUE;
    param.maxFingerSpacing_ = DUMMY_VALUE;
    param.fingerMovementThreshold_ = DUMMY_VALUE;
    param.minGravityOffsetForPinch_ = DUMMY_VALUE;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr int32_t defaultMinKeepTime { 15 };
    EXPECT_EQ(param1.GetMinKeepTimeForSwipe(), defaultMinKeepTime);
}

/**
 * @tc.name: TouchGestureParameter_Load_003
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    int32_t paramValue { -2 };
    param.fingerCountOffsetForPinch_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr int32_t defaultValue { 1 };
    EXPECT_EQ(param1.GetFingerCountOffsetForPinch(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_004
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    int32_t paramValue { -2 };
    param.continuousPinchesForNotification_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr int32_t defaultValue { 2 };
    EXPECT_EQ(param1.GetContinuousPinchesForNotification(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_005
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    int32_t paramValue { -2 };
    param.minKeepTimeForSwipe_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr int32_t defaultValue { 15 };
    EXPECT_EQ(param1.GetMinKeepTimeForSwipe(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_006
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    int64_t paramValue { -2 };
    param.maxDownInterval_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr int32_t defaultValue { 100000 };
    EXPECT_EQ(param1.GetMaxDownInterval(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_007
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    float paramValue { -2.0F };
    param.maxFingerSpacing_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr float defaultValue { 2000 };
    EXPECT_EQ(param1.GetMaxFingerSpacing(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_008
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    float paramValue { -2.0F };
    param.fingerMovementThreshold_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr float defaultValue { 3.0 };
    EXPECT_EQ(param1.GetFingerMovementThreshold(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_Load_009
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_Load_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    struct CfgFiles cfgFiles {};
    cfgFiles.paths[0] = g_cfgName;

    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(&cfgFiles));

    TouchGestureParameter param {};
    float paramValue { -2.0F };
    param.minGravityOffsetForPinch_ = paramValue;
    BuildInputProductConfig(param);

    TouchGestureParameter param1 {};
    param1.LoadTouchGestureParameter();
    constexpr float defaultValue { 0.5 };
    EXPECT_EQ(param1.GetMinGravityOffsetForPinch(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_LoadTouchGestureParameter_001
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_LoadTouchGestureParameter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NiceMock<ConfigPolicyUtilsMock> cfgPolicyUtils;
    EXPECT_CALL(cfgPolicyUtils, GetCfgFiles).WillOnce(testing::Return(nullptr));

    TouchGestureParameter param {};
    param.LoadTouchGestureParameter();
    constexpr int32_t defaultValue { 2 };
    EXPECT_EQ(param.GetContinuousPinchesForNotification(), defaultValue);
}

/**
 * @tc.name: TouchGestureParameter_LoadTouchGestureParameter_002
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_LoadTouchGestureParameter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr char cfgName[] { "test_config.json" };
    TouchGestureParameter param {};
    EXPECT_FALSE(param.LoadTouchGestureParameter(cfgName));
}

/**
 * @tc.name: TouchGestureParameter_LoadTouchGestureParameter_003
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_LoadTouchGestureParameter_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr char cfgName[] { "test_config.json" };
    const std::ofstream::pos_type tailPos { 4096 };
    std::ofstream ofs(cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs.seekp(tailPos);
        ofs << "tail";
        ofs.flush();
        ofs.close();
    }

    TouchGestureParameter param {};
    EXPECT_FALSE(param.LoadTouchGestureParameter(cfgName));
}

/**
 * @tc.name: TouchGestureParameter_LoadTouchGestureParameter_004
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_LoadTouchGestureParameter_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr char cfgName[] { "test_config.json" };
    std::ofstream ofs(cfgName, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << "tail";
        ofs.close();
    }

    TouchGestureParameter param {};
    EXPECT_FALSE(param.LoadTouchGestureParameter(cfgName));
}

/**
 * @tc.name: TouchGestureParameter_ReadTouchGestureParameter_001
 * @tc.desc: Test the function TouchGestureParameter::Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureParameter_ReadTouchGestureParameter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureParameter param {};
    EXPECT_FALSE(param.ReadTouchGestureParameter(nullptr));
}

/**
 * @tc.name: TouchGestureAdapterTest_GetDelegateInterface_001
 * @tc.desc: Test the function TouchGestureAdapter::GetDelegateInterface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetDelegateInterface_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegate = TouchGestureAdapter::GetDelegateInterface(nullptr);
    EXPECT_EQ(delegate, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetUDSServer_001
 * @tc.desc: Test the function TouchGestureAdapter::GetUDSServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetUDSServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto udsServer = TouchGestureAdapter::GetUDSServer(nullptr);
    EXPECT_EQ(udsServer, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetEventNormalizeHandler_001
 * @tc.desc: Test the function SetGestureEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetEventNormalizeHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto handler = TouchGestureAdapter::GetEventNormalizeHandler(nullptr);
    EXPECT_EQ(handler, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetEventNormalizeHandler_002
 * @tc.desc: Test the function TouchGestureAdapter::GetEventNormalizeHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetEventNormalizeHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto handler = TouchGestureAdapter::GetEventNormalizeHandler(&env_);
    EXPECT_NE(handler, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetMonitorHandler_001
 * @tc.desc: Test the function TouchGestureAdapter::GetMonitorHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetMonitorHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto handler = TouchGestureAdapter::GetMonitorHandler(nullptr);
    EXPECT_EQ(handler, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetTimerManager_001
 * @tc.desc: Test the function TouchGestureAdapter::GetTimerManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetTimerManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto timerMgr = TouchGestureAdapter::GetTimerManager(nullptr);
    EXPECT_EQ(timerMgr, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_GetInputWindowsManager_001
 * @tc.desc: Test the function TouchGestureAdapter::GetInputWindowsManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetInputWindowsManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winMgr = TouchGestureAdapter::GetInputWindowsManager(nullptr);
    EXPECT_EQ(winMgr, nullptr);
}

/**
 * @tc.name: TouchGestureAdapterTest_SetGestureEnable_001
 * @tc.desc: Test the function SetGestureEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_SetGestureEnable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = TOUCH_GESTURE_TYPE_SWIPE;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    touchGestureAdapter->Init();
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(false, adapterType, 0));
}

/**
 * @tc.name: TouchGestureAdapterTest_process_001
 * @tc.desc: Test the function process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_process_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    touchGestureAdapter->shouldDeliverToNext_ = true;
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = true;
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = false;
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
    touchGestureAdapter->shouldDeliverToNext_ = false;
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_process_002
 * @tc.desc: Test TouchGestureAdapter::process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_process_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto nextAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_PINCH, nullptr);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nextAdapter);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_process_003
 * @tc.desc: Test TouchGestureAdapter::process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_process_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto nextAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_PINCH, nullptr);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nextAdapter);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    touchGestureAdapter->shouldDeliverToNext_ = false;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_process_004
 * @tc.desc: Test TouchGestureAdapter::process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_process_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->process(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_Init_001
 * @tc.desc: Test the function Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->Init());
}

/**
 * @tc.name: TouchGestureAdapterTest_GetGestureFactory_001
 * @tc.desc: Test the function GetGestureFactory
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_GetGestureFactory_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->GetGestureFactory(&env_));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_001
 * @tc.desc: Test the function OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureType_ = 2;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_002
 * @tc.desc: Test the function OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    touchGestureAdapter->gestureStarted_ = true;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = 2;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    touchGestureAdapter->gestureStarted_ = true;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->gestureStarted_ = false;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnSwipeGesture_001
 * @tc.desc: Test the function OnSwipeGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnSwipeGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnSwipeGesture(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnSwipeGesture(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnPinchGesture_001
 * @tc.desc: Test the function OnPinchGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnPinchGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnPinchGesture(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnPinchGesture(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnGestureEvent_001
 * @tc.desc: Test the function OnGestureEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnGestureEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    GestureMode mode = GestureMode::ACTION_SWIPE_DOWN;
    bool ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_UP;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_LEFT;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_SWIPE_RIGHT;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_PINCH_CLOSED;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_PINCH_OPENED;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, true);
    mode = GestureMode::ACTION_UNKNOWN;
    ret = touchGestureAdapter->OnGestureEvent(event, mode);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: TouchGestureAdapterTest_SetGestureEnable_002
 * @tc.desc: Test the function SetGestureEnable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_SetGestureEnable_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = TOUCH_GESTURE_TYPE_ALL;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_SWIPE;
    touchGestureAdapter->gestureType_ = TOUCH_GESTURE_TYPE_SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    adapterType = TOUCH_GESTURE_TYPE_ALL;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    adapterType = TOUCH_GESTURE_TYPE_PINCH;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    touchGestureAdapter->nextAdapter_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
    touchGestureAdapter->nextAdapter_ = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->SetGestureCondition(true, adapterType, 0));
}

/**
 * @tc.name: TouchGestureAdapterTest_OnTouchEvent_003
 * @tc.desc: Test the function OnTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_OnTouchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchGestureType adapterType = 5;
    std::shared_ptr<TouchGestureAdapter> nextAdapter = nullptr;
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, adapterType, nextAdapter);
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    std::shared_ptr<OHOS::MMI::TouchGestureDetector::GestureListener> listener = nullptr;
    touchGestureAdapter->gestureDetector_ = std::make_shared<TouchGestureDetector>(&env_, adapterType, listener);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->gestureType_ = 2;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    touchGestureAdapter->gestureStarted_ = true;
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::SWIPE;
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
    touchGestureAdapter->state_ = TouchGestureAdapter::GestureState::IDLE;
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->OnTouchEvent(event));
}

/**
 * @tc.name: TouchGestureAdapterTest_LogTouchEvent_01
 * @tc.desc: Test TouchGestureAdapter::LogTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_LogTouchEvent_01, TestSize.Level1)
{
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->LogTouchEvent(nullptr));
}

/**
 * @tc.name: TouchGestureAdapterTest_LogTouchEvent_02
 * @tc.desc: Test TouchGestureAdapter::LogTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_LogTouchEvent_02, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->LogTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_LogTouchEvent_03
 * @tc.desc: Test TouchGestureAdapter::LogTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_LogTouchEvent_03, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->LogTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_LogTouchEvent_04
 * @tc.desc: Test TouchGestureAdapter::LogTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_LogTouchEvent_04, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->LogTouchEvent(pointerEvent));
}

/**
 * @tc.name: TouchGestureAdapterTest_LogTouchEvent_05
 * @tc.desc: Test TouchGestureAdapter::LogTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureAdapterTest, TouchGestureAdapterTest_LogTouchEvent_05, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t pointerId = 1;
    PointerEvent::PointerItem pointerItem {};
    pointerItem.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(pointerItem);
    pointerEvent->SetPointerId(pointerId);
    auto touchGestureAdapter = std::make_shared<TouchGestureAdapter>(&env_, TOUCH_GESTURE_TYPE_SWIPE, nullptr);
    ASSERT_NO_FATAL_FAILURE(touchGestureAdapter->LogTouchEvent(pointerEvent));
}
} // namespace MMI
} // namespace OHOS
