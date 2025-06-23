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

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>

#include "event_filter_handler.h"
#include "fingersense_wrapper.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "libinput_interface.h"
#include "mmi_log.h"
#include "mock_input_windows_manager.h"
#include "pixel_map.h"
#include "pointer_drawing_manager.h"
#include "proto.h"
#include "scene_board_judgement.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "util.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerOneTest"

using namespace OHOS::MMI;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
MockInputWindowsManager *g_inputWindowManagerInterface;

MockInputWindowsManager::MockInputWindowsManager()
{
    g_inputWindowManagerInterface = this;
}

MockInputWindowsManager::~MockInputWindowsManager()
{
    g_inputWindowManagerInterface = nullptr;
}

static InputWindowsManagerInterface *GetInputWindowsManagerInterface()
{
    return g_inputWindowManagerInterface;
}

std::optional<WindowInfo> InputWindowsManager::GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId)
{
    if (GetInputWindowsManagerInterface() != nullptr) {
        return GetInputWindowsManagerInterface()->GetWindowAndDisplayInfo(windowId, displayId);
    }
    return std::nullopt;
}

void InputWindowsManager::PrintDisplayInfo(const DisplayInfo displayInfo) {}

bool Rosen::SceneBoardJudgement::IsSceneBoardEnabled()
{
    if (GetInputWindowsManagerInterface() != nullptr) {
        return GetInputWindowsManagerInterface()->IsSceneBoardEnabled();
    }
    return false;
}

namespace MMI {
namespace {
constexpr int32_t CAST_INPUT_DEVICEID{ 0xAAAAAAFF };
constexpr int32_t CAST_SCREEN_DEVICEID{ 0xAAAAAAFE };
}  // namespace

std::string ReadJsonFile(const std::string &filePath)
{
    if (g_inputWindowManagerInterface != nullptr) {
        return GetInputWindowsManagerInterface()->ReadJsonFile(filePath);
    }
    return "";
}

class InputWindowsManagerOneTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void SetDown(void){};
};