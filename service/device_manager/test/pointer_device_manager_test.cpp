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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "delegate_interface.h"
#include "pointer_device_manager.h"

namespace OHOS {
namespace MMI {
using namespace testing::ext;

class PointerDeviceManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
};

/**
 * @tc.name: PointerDeviceManager_001
 * @tc.desc: Obtain PointerDeviceManager single instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDeviceManagerTest, PointerDeviceManager_001, TestSize.Level1)
{
    EXPECT_EQ(POINTER_DEV_MGR.isInit, false);
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
/**
 * @tc.name: GetDelegateProxy_001
 * @tc.desc: GetDelegateProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDeviceManagerTest, GetDelegateProxy_001, TestSize.Level1)
{
    EXPECT_EQ(POINTER_DEV_MGR.GetDelegateProxy(), nullptr);
}

/**
 * @tc.name: SetDelegateProxy_001
 * @tc.desc: SetDelegateProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDeviceManagerTest, SetDelegateProxy_001, TestSize.Level1)
{
    DelegateTasks delegateTasks;
    std::function<int32_t(DTaskCallback)> fun = [&](DTaskCallback cb) -> int32_t {
        return delegateTasks.PostSyncTask(cb);
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [&](DTaskCallback cb) -> int32_t {
        return delegateTasks.PostAsyncTask(cb);
    };
    std::shared_ptr<DelegateInterface> delegateInterface = std::make_shared<DelegateInterface>(fun, asyncFun);

    POINTER_DEV_MGR.SetDelegateProxy(delegateInterface);
    EXPECT_NE(POINTER_DEV_MGR.GetDelegateProxy(), nullptr);
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
} // namespace MMI
} // namespace OHOS
