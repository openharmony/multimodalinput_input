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

#include "define_multimodal.h"
#include "dfx_hisysevent_device.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DfxHisysEventTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DfxHisysEventDeviceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(DfxHisysEventDeviceTest, ReportDeviceFault_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = 1;
    auto type = DfxHisyseventDevice::DeviceFaultType::DEVICE_FAULT_TYPE_SYS;
    ASSERT_NO_FATAL_FAILURE(DfxHisyseventDevice::ReportDeviceFault(type, "test fault 1"));
    type = DfxHisyseventDevice::DeviceFaultType::DEVICE_FAULT_TYPE_INNER;
    ASSERT_NO_FATAL_FAILURE(DfxHisyseventDevice::ReportDeviceFault(id, type, "test fault 2"));
}

HWTEST_F(DfxHisysEventDeviceTest, ReportDeviceBehavior_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = -1;
    ASSERT_NO_FATAL_FAILURE(DfxHisyseventDevice::ReportDeviceBehavior(id, "test behavior"));
    id = 1;
    ASSERT_NO_FATAL_FAILURE(DfxHisyseventDevice::ReportDeviceBehavior(id, "test behavior"));
}

} // namespace MMI
} // namespace OHOS