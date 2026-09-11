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

#include "mock_controller_factory.h"

#include <cstdint>
#include <memory>

#include "input_manager.h"
#include "keyboard_controller_impl.h"
#include "mouse_controller_impl.h"

namespace OHOS::MMI::InputCli {
namespace {
constexpr int32_t SECOND_DISPLAY_OFFSET_X = 1000;

int32_t ResultFor(const std::string &call, const std::string &failureCall, int32_t failureResult)
{
    return call == failureCall ? failureResult : 0;
}
} // namespace

MockControllerConfig &MockControllerState()
{
    static MockControllerConfig config;
    return config;
}

void ResetMockControllerState()
{
    MockControllerState() = {};
}

void MockControllerFixture::Configure(std::vector<RecordedCall> &calls, const MockControllerOptions &options)
{
    MockControllerState() = { &calls, options.mouseCreateResult, options.keyboardCreateResult,
        options.mouseFailureCall, options.mouseFailureResult, options.keyboardFailureCall,
        options.keyboardFailureResult, options.recordDestruction };
}

int32_t MockControllerFixture::MouseCreateCount() const
{
    return MockControllerState().mouseCreateCount;
}

int32_t MockControllerFixture::KeyboardCreateCount() const
{
    return MockControllerState().keyboardCreateCount;
}

} // namespace OHOS::MMI::InputCli

// Test-only definitions replace the platform implementation at link time.
namespace OHOS::MMI {
using namespace InputCli;

InputManager *InputManager::GetInstance()
{
    static InputManager instance;
    return &instance;
}

MouseControllerImpl::MouseControllerImpl() = default;
KeyboardControllerImpl::KeyboardControllerImpl() = default;

MouseControllerImpl::~MouseControllerImpl()
{
    if (MockControllerState().recordDestruction) {
        MockControllerState().calls->push_back({ "DestroyMouse", {} });
    }
}

int32_t MouseControllerImpl::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    MockControllerState().calls->push_back({ "MoveTo", { displayId, x, y } });
    return ResultFor("MoveTo", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::MoveToGlobal(int32_t x, int32_t y)
{
    MockControllerState().calls->push_back({ "MoveToGlobal", { x, y } });
    return ResultFor("MoveToGlobal", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

int32_t InputManager::GetGlobalCoordinates(int32_t displayId, int32_t x, int32_t y,
    int32_t &globalX, int32_t &globalY)
{
    globalX = x + (displayId == 1 ? SECOND_DISPLAY_OFFSET_X : 0);
    globalY = y;
    return ResultFor("GetGlobalCoordinates", MockControllerState().mouseFailureCall,
        MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::PressButton(int32_t button)
{
    MockControllerState().calls->push_back({ "PressButton", { button } });
    return ResultFor("PressButton", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::ReleaseButton(int32_t button)
{
    MockControllerState().calls->push_back({ "ReleaseButton", { button } });
    return ResultFor("ReleaseButton", MockControllerState().mouseFailureCall,
        MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::BeginAxis(int32_t axisType, int32_t value)
{
    MockControllerState().calls->push_back({ "BeginAxis", { axisType, value } });
    return ResultFor("BeginAxis", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::UpdateAxis(int32_t axisType, int32_t value)
{
    MockControllerState().calls->push_back({ "UpdateAxis", { axisType, value } });
    return ResultFor("UpdateAxis", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

int32_t MouseControllerImpl::EndAxis(int32_t axisType)
{
    MockControllerState().calls->push_back({ "EndAxis", { axisType } });
    return ResultFor("EndAxis", MockControllerState().mouseFailureCall, MockControllerState().mouseFailureResult);
}

KeyboardControllerImpl::~KeyboardControllerImpl()
{
    if (MockControllerState().recordDestruction) {
        MockControllerState().calls->push_back({ "DestroyKeyboard", {} });
    }
}

int32_t KeyboardControllerImpl::PressKey(int32_t key)
{
    MockControllerState().calls->push_back({ "PressKey", { key } });
    return ResultFor("PressKey", MockControllerState().keyboardFailureCall,
        MockControllerState().keyboardFailureResult);
}

int32_t KeyboardControllerImpl::ReleaseKey(int32_t key)
{
    MockControllerState().calls->push_back({ "ReleaseKey", { key } });
    return ResultFor("ReleaseKey", MockControllerState().keyboardFailureCall,
        MockControllerState().keyboardFailureResult);
}

int32_t InputManager::CreateMouseController(std::shared_ptr<MouseControllerImpl> &controller)
{
    controller.reset();
    MockControllerConfig &state = MockControllerState();
    ++state.mouseCreateCount;
    if (state.calls == nullptr || state.mouseCreateResult != 0) {
        return state.mouseCreateResult;
    }
    controller = std::make_shared<MouseControllerImpl>();
    return state.mouseCreateResult;
}

int32_t InputManager::CreateKeyboardController(std::shared_ptr<KeyboardControllerImpl> &controller)
{
    controller.reset();
    MockControllerConfig &state = MockControllerState();
    ++state.keyboardCreateCount;
    if (state.calls == nullptr || state.keyboardCreateResult != 0) {
        return state.keyboardCreateResult;
    }
    controller = std::make_shared<KeyboardControllerImpl>();
    return state.keyboardCreateResult;
}
} // namespace OHOS::MMI
