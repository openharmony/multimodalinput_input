/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "pointer_drawing_manager.h"
#include "error_multimodal.h"
#include <chrono>
#include <thread>

namespace {
using namespace std;
using namespace testing::ext;
using namespace OHOS::MMI;

class PointerDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(PointerDrawingManagerTest, PointerDrawManagerTest_001, TestSize.Level1)
{
    DrawWgr->DrawPointer(0, 0, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 10, 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 100, 100);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 400, 400);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 800, 800);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 1000, 800);
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    DrawWgr->DrawPointer(0, 600, 600);
}

} // namespace
