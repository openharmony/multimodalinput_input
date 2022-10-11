/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "window_utils_test.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "wm_common.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "WindowUtilsTest" };
constexpr int32_t IMAGE_WIDTH = 720;
constexpr int32_t IMAGE_HEIGHT = 1280;
constexpr uint32_t defaultWindowId = -1;
std::string windowName = "WindowUtilsTest";
} // namespace

WindowUtilsTest::~WindowUtilsTest()
{
    ClearTestWindow();
}

std::shared_ptr<WindowUtilsTest> WindowUtilsTest::GetInstance()
{
    if (windowUtils_ == nullptr) {
        windowUtils_ = std::make_shared<WindowUtilsTest>();
    }
    return windowUtils_;
}

void WindowUtilsTest::ClearTestWindow()
{
    CALL_DEBUG_ENTER;
    CHKPV(testWindow_);
    testWindow_->Destroy();
}

bool WindowUtilsTest::DrawTestWindow()
{
    CALL_DEBUG_ENTER;
    testWindow_ = Rosen::Window::Find(windowName);
    if (testWindow_ == nullptr) {
        CreateSmoothWindow();
    }

    CHKPF(testWindow_);
    return testWindow_->Show() == Rosen::WMError::WM_OK;
}

sptr<Rosen::Window>& WindowUtilsTest::GetWindow()
{
    return testWindow_;
}

uint32_t WindowUtilsTest::GetWindowId()
{
    CHKPR(testWindow_, defaultWindowId);
    return testWindow_->GetWindowId();
}

void WindowUtilsTest::CreateSmoothWindow()
{
    TestWindowInfo info = {
        .name = windowName,
        .rect = {
            .posX_ = 0,
            .posY_ = 0,
            .width_ = IMAGE_WIDTH,
            .height_ = IMAGE_HEIGHT,
        },
        .type = Rosen::WindowType::WINDOW_TYPE_KEYGUARD,
        .mode = Rosen::WindowMode::WINDOW_MODE_FULLSCREEN,
        .needAvoid = false,
        .parentLimit = false,
        .parentId = Rosen::INVALID_WINDOW_ID,
    };
    testWindow_ = CreateWindow(info);
}

sptr<Rosen::Window> WindowUtilsTest::CreateWindow(const TestWindowInfo& info)
{
    sptr<Rosen::WindowOption> option = new (std::nothrow) Rosen::WindowOption();
    CHKPP(option);
    option->SetWindowRect(info.rect);
    option->SetWindowType(info.type);
    option->SetWindowMode(info.mode);
    option->SetFocusable(info.focusable_);
    option->SetTurnScreenOn(true);
    option->SetDisplayId(0);
    option->SetRequestedOrientation(info.orientation_);
    option->SetMainHandlerAvailable(false);
    if (info.parentId != Rosen::INVALID_WINDOW_ID) {
        option->SetParentId(info.parentId);
    }
    if (info.needAvoid) {
        option->AddWindowFlag(Rosen::WindowFlag::WINDOW_FLAG_NEED_AVOID);
    } else {
        option->RemoveWindowFlag(Rosen::WindowFlag::WINDOW_FLAG_NEED_AVOID);
    }
    if (info.parentLimit) {
        option->AddWindowFlag(Rosen::WindowFlag::WINDOW_FLAG_PARENT_LIMIT);
    } else {
        option->RemoveWindowFlag(Rosen::WindowFlag::WINDOW_FLAG_PARENT_LIMIT);
    }
    return Rosen::Window::Create(info.name, option);
}
} // namespace MMI
} // namespace OHOS