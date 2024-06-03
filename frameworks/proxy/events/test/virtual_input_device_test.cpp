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

#include <cinttypes>

#include "event_util_test.h"
#include "input_manager.h"
#include "input_manager_util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "VirtualInputDeviceTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 100;

} // namespace

class VirtualInputDeviceTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    std::string GetEventDump();
    static bool CmpInputDevice(std::shared_ptr<InputDevice> one, std::shared_ptr<InputDevice> other);
};

class VirtualInputDeviceListener : public IInputDeviceListener {
public:
    ~VirtualInputDeviceListener() override = default;
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override
    {
        MMI_HILOGI("deviceId:%{public}d added, type:%{public}s", deviceId, type.c_str());
        KeyboardType keyType { KeyboardType::KEYBOARD_TYPE_NONE };
        auto keyboardCallback = [&keyType] (int32_t keyboardType) {
            MMI_HILOGI("KeyboardType:%{public}d", keyboardType);
        };
        int32_t ret = InputManager::GetInstance()->GetKeyboardType(deviceId, keyboardCallback);
        ASSERT_EQ(ret, RET_OK);
    }

    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override
    {
        MMI_HILOGI("DeviceId:%{public}d removed, type:%{public}s", deviceId, type.c_str());
    }
};

void VirtualInputDeviceTest::SetUpTestCase()
{
    ASSERT_TRUE(TestUtil->Init());
}

void VirtualInputDeviceTest::SetUp()
{
    TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
}

void VirtualInputDeviceTest::TearDown()
{
    TestUtil->AddEventDump("");
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
}

std::string VirtualInputDeviceTest::GetEventDump()
{
    return TestUtil->GetEventDump();
}

bool VirtualInputDeviceTest::CmpInputDevice(std::shared_ptr<InputDevice> one, std::shared_ptr<InputDevice> other)
{
    if (one == nullptr && other == nullptr) {
        return true;
    }
    if (one == nullptr || other == nullptr) {
        return false;
    }
    return one->GetName() == other->GetName() && one->GetType() == other->GetType() &&
        one->GetBus() == other->GetBus() && one->GetVersion() == other->GetVersion() &&
        one->GetProduct() == other->GetProduct() && one->GetVendor() == other->GetVendor() &&
        one->GetPhys() == other->GetPhys() && one->GetUniq() == other->GetUniq() &&
        one->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD) ==
        other->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD) &&
        one->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER) ==
        other->HasCapability(InputDeviceCapability::INPUT_DEV_CAP_POINTER);
};

/**
 * @tc.name: VirtualInputDeviceTest_AddVirtualInputDevice_001
 * @tc.desc: Add virtual input device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualInputDeviceTest, VirtualInputDeviceTest_AddVirtualInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto inputDeviceAdd = std::make_shared<InputDevice>();
    inputDeviceAdd->SetName("VirtualDeviceName");
    inputDeviceAdd->SetType(-1);
    inputDeviceAdd->SetBus(-1);
    inputDeviceAdd->SetVersion(-1);
    inputDeviceAdd->SetProduct(-1);
    inputDeviceAdd->SetVendor(-1);
    inputDeviceAdd->SetPhys("Phys");
    inputDeviceAdd->SetUniq("unique");
    inputDeviceAdd->AddCapability(InputDeviceCapability::INPUT_DEV_CAP_KEYBOARD);
    int32_t deviceId { -1 };
    int32_t ret = InputManager::GetInstance()->AddVirtualInputDevice(inputDeviceAdd, deviceId);
    ASSERT_EQ(ret, RET_OK);
    auto inputDeviceGet = std::make_shared<InputDevice>();
    auto inputDevFun = [&inputDeviceGet] (std::shared_ptr<InputDevice> dev) {
        inputDeviceGet = dev;
    };
    ASSERT_TRUE(InputManager::GetInstance()->GetDevice(deviceId, inputDevFun) == RET_OK);
    ASSERT_TRUE(CmpInputDevice(inputDeviceAdd, inputDeviceGet));
    ret = InputManager::GetInstance()->RemoveVirtualInputDevice(deviceId);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: VirtualInputDeviceTest_RemoveVirtualInputDevice_001
 * @tc.desc: Remove virtual input device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualInputDeviceTest, VirtualInputDeviceTest_RemoveVirtualInputDevice_001, TestSize.Level1)
{
    auto inputDeviceAdd = std::make_shared<InputDevice>();
    int32_t deviceId { -1 };
    int32_t ret = InputManager::GetInstance()->AddVirtualInputDevice(inputDeviceAdd, deviceId);
    ASSERT_EQ(ret, RET_OK);
    auto inputDeviceGet = std::make_shared<InputDevice>();
    auto inputDevFun = [&inputDeviceGet] (std::shared_ptr<InputDevice> dev) {
        inputDeviceGet = dev;
    };
    ret = InputManager::GetInstance()->GetDevice(deviceId, inputDevFun);
    ASSERT_EQ(ret, RET_OK);
    ret = InputManager::GetInstance()->RemoveVirtualInputDevice(deviceId);
    ASSERT_EQ(ret, RET_OK);
    ret = InputManager::GetInstance()->RemoveVirtualInputDevice(deviceId);
    ASSERT_NE(ret, RET_OK);
    ret = InputManager::GetInstance()->GetDevice(deviceId, inputDevFun);
    ASSERT_NE(ret, RET_OK);
}
/**
 * @tc.name: VirtualInputDeviceTest_TestHotPlug
 * @tc.desc: Test virtual input hot plug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VirtualInputDeviceTest, VirtualInputDeviceTest_TestHotPlug, TestSize.Level1)
{
    auto listener = std::make_shared<VirtualInputDeviceListener>();
    int32_t ret = InputManager::GetInstance()->RegisterDevListener("change", listener);
    ASSERT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
