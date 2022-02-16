/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "error_multimodal.h"
#include "input_event_monitor_manager.h"
#include "input_handler_manager.h"
#include "input_manager.h"
#include "interceptor_manager.h"
#include "key_event_pre.h"
#include "multimodal_event_handler.h"
#include "pointer_event.h"
#include "proto.h"
#include "run_shell_util.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace MMI;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 500;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputManagerManualTest" };
}

class InputManagerManualTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp();
    void TearDown() {}

protected:
    void AddInputEventFilter();
    void SimulateInputEventHelper(int32_t globalX, int32_t globalY, int32_t expectVal);
private:
    int32_t callbackRet = 0;
};

void InputManagerManualTest::SetUp()
{
    callbackRet = 0;
}

void InputManagerManualTest::AddInputEventFilter()
{
    MMI_LOGD("enter");
    auto callback = [this](std::shared_ptr<PointerEvent> pointer) -> bool {
        MMI_LOGT("callback enter");
        CHKPF(pointer);
        const std::vector<int32_t> ids = pointer->GetPointersIdList();
        if (ids.empty()) {
            MMI_LOGE("ids is empty");
            return false;
        }

        const int firstPointerId = ids[0];
        PointerEvent::PointerItem item;
        if (!pointer->GetPointerItem(firstPointerId, item)) {
            MMI_LOGE("GetPointerItem:%{public}d fail", firstPointerId);
            return false;
        }

        const int32_t x = item.GetGlobalX();
        const int32_t y = item.GetGlobalY();
        if (x == 10 && y == 10) {
            MMI_LOGI("The values of X and y are both 10, which meets the expectation and callbackRet is set to 1");
            callbackRet = 1;
            return true;
        }

        MMI_LOGI("The values of X and y are not 10, which meets the expectation and callbackRet is set to 2");
        callbackRet = 2;
        return false;
    };

    int ret = InputManager::GetInstance()->AddInputEventFilter(callback);
    ASSERT_EQ(ret, RET_OK);
    MMI_LOGD("leave");
}

void InputManagerManualTest::SimulateInputEventHelper(int32_t globalX, int32_t globalY, int32_t expectVal)
{
    MMI_LOGD("enter");
    const int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetGlobalX(globalX);
    item.SetGlobalY(globalY);

    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(-1);
    pointerEvent->SetPointerId(pointerId);

    MMI_LOGI("Call InputManager::SimulateInputEvent");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    EXPECT_EQ(callbackRet, expectVal);
    MMI_LOGD("leave");
}

HWTEST_F(InputManagerManualTest, HandlePointerEventFilter_001, TestSize.Level1)
{
    MMI_LOGD("enter");
    AddInputEventFilter();
    SimulateInputEventHelper(10, 10, 1); // set global x and global y are 10, will expect value is 1
    SimulateInputEventHelper(0, 0, 2); // set global x and global y are not 10, will expect value is 2
}
}