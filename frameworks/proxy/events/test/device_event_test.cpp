/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "device_event.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class DeviceEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(DeviceEventTest, Initialize, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 0;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
}

HWTEST_F(DeviceEventTest, Initialize_01, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
}

HWTEST_F(DeviceEventTest, Initialize_02, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = -20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
}

HWTEST_F(DeviceEventTest, Initialize_03, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = -100000;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
}

HWTEST_F(DeviceEventTest, Initialize_04, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 100000;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
}

HWTEST_F(DeviceEventTest, GetName, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
}

HWTEST_F(DeviceEventTest, GetName_01, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name123";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
}

HWTEST_F(DeviceEventTest, GetName_02, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name123";
    std::string sysName = "sysName";
    int32_t inputDeviceId = -20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
}

HWTEST_F(DeviceEventTest, GetSysName, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetSysName();
}

HWTEST_F(DeviceEventTest, GetSysName_01, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName123";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetSysName();
}

HWTEST_F(DeviceEventTest, GetSysName_02, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName123";
    int32_t inputDeviceId = 0;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetSysName();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName123";
    int32_t inputDeviceId = 0;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetInputDeviceId();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId_01, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string name = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 20;
    deviceEvent.Initialize(name, sysName, inputDeviceId);
    deviceEvent.GetInputDeviceId();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId_02, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = -20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetInputDeviceId();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId_03, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name";
    std::string sysName = "sysName";
    int32_t inputDeviceId = 0;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
    deviceEvent.GetSysName();
    deviceEvent.GetInputDeviceId();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId_04, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name12321213113455asfdg";
    std::string sysName = "sysName123112231231211231";
    int32_t inputDeviceId = -20;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
    deviceEvent.GetSysName();
    deviceEvent.GetInputDeviceId();
}

HWTEST_F(DeviceEventTest, GetInputDeviceId_05, TestSize.Level1)
{
    DeviceEvent deviceEvent;
    std::string strName = "name12321213113455asfdg";
    std::string sysName = "sysName123112231231211231";
    int32_t inputDeviceId = -100000;
    deviceEvent.Initialize(strName, sysName, inputDeviceId);
    deviceEvent.GetName();
    deviceEvent.GetSysName();
    deviceEvent.GetInputDeviceId();
}
} // namespace
