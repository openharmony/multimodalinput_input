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


#include <gtest/gtest.h>

#include "input_device_impl.h"
#include "i_input_device_listener.h"
#include <cinttypes>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceImplTest"

namespace OHOS {
namespace MMI {
namespace {
std::string INPUT_DEV_CHANGE_ADD_DEV = "add";
std::string INPUT_DEV_CHANGE_REMOVE_DEV = "remove";
using namespace testing::ext;
} // namespace

class InputDeviceImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class InputDeviceListenerMock : public IInputDeviceListener {
public:
    InputDeviceListenerMock() = default;
    virtual ~InputDeviceListenerMock() = default;

    void OnDeviceAdded(int32_t deviceId, const std::string &type)
    {
        MMI_HILOGI("OnDeviceAdded enter");
        return;
    }

    void OnDeviceRemoved(int32_t deviceId, const std::string &type)
    {
        MMI_HILOGI("OnDeviceRemoved enter");
        return;
    }
};

/**
 * @tc.name: InputDeviceImplTest_RegisterDevListener_001
 * @tc.desc: Test RegisterDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_RegisterDevListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    std::string type = "test";
    auto listener = std::make_shared<InputDeviceListenerMock>();
    int32_t ret = manager.RegisterDevListener(type, listener);
    EXPECT_EQ(ret, RET_ERR);

    std::list<InputDeviceImpl::InputDevListenerPtr> devListener;
    devListener.push_back(listener);
    manager.devListener_.insert(std::make_pair(CHANGED_TYPE, devListener));
    auto listener2 = std::make_shared<InputDeviceListenerMock>();
    ret = manager.RegisterDevListener(type, listener2);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceImplTest_OnDevListener_001
 * @tc.desc: Test OnDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_OnDevListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    manager.devListener_.clear();

    std::string type = INPUT_DEV_CHANGE_ADD_DEV;
    int32_t deviceId = 0;
    EXPECT_NO_FATAL_FAILURE(manager.OnDevListener(deviceId, type));

    auto listener = std::make_shared<InputDeviceListenerMock>();
    std::list<InputDeviceImpl::InputDevListenerPtr> devListener;
    devListener.push_back(listener);
    manager.devListener_.insert(std::make_pair(CHANGED_TYPE, devListener));
    EXPECT_NO_FATAL_FAILURE(manager.OnDevListener(deviceId, type));

    type = INPUT_DEV_CHANGE_REMOVE_DEV;
    EXPECT_NO_FATAL_FAILURE(manager.OnDevListener(deviceId, type));

    type = "test";
    EXPECT_NO_FATAL_FAILURE(manager.OnDevListener(deviceId, type));
}

/**
 * @tc.name: InputDeviceImplTest_OnSetInputDeviceAck_001
 * @tc.desc: Test OnSetInputDeviceAck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_OnSetInputDeviceAck_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;

    int32_t index = 0;
    int32_t result = 0;
    EXPECT_NO_FATAL_FAILURE(manager.OnSetInputDeviceAck(index, result));
}

/**
 * @tc.name: InputDeviceImplTest_OnConnected_001
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_OnConnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;

    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());

    manager.devListener_.clear();
    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());

    auto listener = std::make_shared<InputDeviceListenerMock>();
    std::list<InputDeviceImpl::InputDevListenerPtr> devListener;
    devListener.push_back(listener);
    manager.devListener_.insert(std::make_pair(CHANGED_TYPE, devListener));
    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());

    manager.isListeningProcess_ = true;
    EXPECT_NO_FATAL_FAILURE(manager.OnConnected());
}

/**
 * @tc.name: InputDeviceImplTest_StopListeningToServer_001
 * @tc.desc: Test StopListeningToServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_StopListeningToServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    manager.isListeningProcess_ = true;
    EXPECT_NO_FATAL_FAILURE(manager.StopListeningToServer());
}

/**
 * @tc.name: InputDeviceImplTest_SupportKeys_001
 * @tc.desc: Test SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceImplTest, InputDeviceImplTest_SupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDeviceImpl manager;
    auto callback = [](std::vector<bool> &event) {};

    int32_t deviceId = 9999;
    std::vector<int32_t> keyCodes;
    EXPECT_EQ(manager.SupportKeys(deviceId, keyCodes, callback), RET_ERR);
}
} // namespace MMI
} // namespace OHOS
