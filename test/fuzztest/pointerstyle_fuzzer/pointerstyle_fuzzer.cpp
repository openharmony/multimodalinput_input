/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "pointerstyle_fuzzer.h"

#include "ipc_skeleton.h"
#include "input_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_STRING_LEN = 16;
constexpr size_t MAX_HOTAREA_COUNT = 4;
}
void UpdateDisplayInfo(FuzzedDataProvider &fdp, int32_t windowId)
{
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = fdp.ConsumeIntegral<int32_t>();

    WindowInfo windowInfo;
    windowInfo.id = windowId;
    windowInfo.pid = IPCSkeleton::GetCallingPid();
    windowInfo.uid = fdp.ConsumeIntegral<int32_t>();
    windowInfo.area.x = fdp.ConsumeIntegral<int32_t>();
    windowInfo.area.y = fdp.ConsumeIntegral<int32_t>();
    windowInfo.area.width = fdp.ConsumeIntegral<int32_t>();
    windowInfo.area.height = fdp.ConsumeIntegral<int32_t>();

    for (size_t i = 0; i < MAX_HOTAREA_COUNT; ++i) {
        Rect r1 {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(),
                 fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
        Rect r2 {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>(),
                 fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()};
        windowInfo.defaultHotAreas.push_back(r1);
        windowInfo.pointerHotAreas.push_back(r2);
    }

    DisplayInfo displayInfo;
    displayInfo.id = fdp.ConsumeIntegral<int32_t>();
    displayInfo.x = fdp.ConsumeIntegral<int32_t>();
    displayInfo.y = fdp.ConsumeIntegral<int32_t>();
    displayInfo.width = fdp.ConsumeIntegral<int32_t>();
    displayInfo.height = fdp.ConsumeIntegral<int32_t>();
    displayInfo.dpi = fdp.ConsumeIntegral<int32_t>();
    displayInfo.name = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);

    displayGroupInfo.windowsInfo.push_back(windowInfo);
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    UserScreenInfo userScreenInfo;
    ScreenInfo screenInfo;
    screenInfo.screenType = static_cast<ScreenType>(windowInfo.windowType);
    screenInfo.dpi = displayInfo.dpi;
    screenInfo.height = windowInfo.area.height;
    screenInfo.width = windowInfo.area.width;
    screenInfo.physicalWidth = fdp.ConsumeIntegral<int32_t>();
    screenInfo.physicalHeight = fdp.ConsumeIntegral<int32_t>();
    screenInfo.id = displayInfo.id;
    screenInfo.rotation = Rotation::ROTATION_0;
    screenInfo.tpDirection = Direction::DIRECTION0;
    screenInfo.uniqueId = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);

    userScreenInfo.screens.push_back(screenInfo);
    userScreenInfo.displayGroups.push_back(displayGroupInfo);

    InputManager::GetInstance()->UpdateDisplayInfo(userScreenInfo);
}

void PointerStyleFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    UpdateDisplayInfo(fdp, windowId);

    PointerStyle pointerStyle;
    pointerStyle.id = fdp.ConsumeIntegral<int32_t>();
    pointerStyle.size = fdp.ConsumeIntegral<int32_t>();
    pointerStyle.color = fdp.ConsumeIntegral<int32_t>();
    pointerStyle.options = fdp.ConsumeIntegral<int32_t>();

    InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle);
    InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle);
}

bool MmiServiceFuzzTest(FuzzedDataProvider &fdp)
{
    PointerStyleFuzzTest(fdp);
    return true;
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    OHOS::MMI::MmiServiceFuzzTest(fdp);
    return 0;
}