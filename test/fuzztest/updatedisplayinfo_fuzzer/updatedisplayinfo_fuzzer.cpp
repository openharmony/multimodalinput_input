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

#include "updatedisplayinfo_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UpdateDisplayInfoFuzzTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_STRING_LEN = 16;
} // namespace
void UpdateHotAreas(FuzzedDataProvider &fdp, WindowInfo &windowInfo)
{
    std::vector<Rect> defaultHotAreasInfo;
    std::vector<Rect> pointerHotAreasInfo;

    for (size_t j = 0; j < WindowInfo::MAX_HOTAREA_COUNT; ++j) {
        Rect defaultRect;
        defaultRect.x = fdp.ConsumeIntegral<int32_t>();
        defaultRect.y = fdp.ConsumeIntegral<int32_t>();
        defaultRect.width = fdp.ConsumeIntegral<int32_t>();
        defaultRect.height = fdp.ConsumeIntegral<int32_t>();
        defaultHotAreasInfo.push_back(defaultRect);

        Rect pointerRect;
        pointerRect.x = fdp.ConsumeIntegral<int32_t>();
        pointerRect.y = fdp.ConsumeIntegral<int32_t>();
        pointerRect.width = fdp.ConsumeIntegral<int32_t>();
        pointerRect.height = fdp.ConsumeIntegral<int32_t>();
        pointerHotAreasInfo.push_back(pointerRect);
    }
    windowInfo.defaultHotAreas = defaultHotAreasInfo;
    windowInfo.pointerHotAreas = pointerHotAreasInfo;

    std::vector<int32_t> pointerChangeAreasInfos;
    for (size_t j = 0; j < WindowInfo::POINTER_CHANGEAREA_COUNT; ++j) {
        pointerChangeAreasInfos.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    windowInfo.pointerChangeAreas = pointerChangeAreasInfos;

    std::vector<float> transformInfos;
    for (size_t j = 0; j < WindowInfo::WINDOW_TRANSFORM_SIZE; ++j) {
        transformInfos.push_back(fdp.ConsumeFloatingPoint<float>());
    }
    windowInfo.transform = transformInfos;
}

void UpdateDisplayInfoFuzzTest(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DisplayGroupInfo displayGroupInfo;
    int32_t displayWidth = fdp.ConsumeIntegral<int32_t>();
    int32_t displayHeight = fdp.ConsumeIntegral<int32_t>();
    displayGroupInfo.focusWindowId = fdp.ConsumeIntegral<int32_t>();

    std::vector<WindowInfo> windowsInfo;
    std::vector<DisplayInfo> displaysInfo;
    std::vector<ScreenInfo> screenInfos;

    for (size_t i = 0; i < WindowInfo::MAX_HOTAREA_COUNT + 1; ++i) {
        WindowInfo windowInfo;
        windowInfo.area.x = fdp.ConsumeIntegral<int32_t>();
        windowInfo.area.y = fdp.ConsumeIntegral<int32_t>();
        windowInfo.pid = fdp.ConsumeIntegral<int32_t>();
        windowInfo.uid = fdp.ConsumeIntegral<int32_t>();
        windowInfo.area.width = fdp.ConsumeIntegral<int32_t>();
        windowInfo.area.height = fdp.ConsumeIntegral<int32_t>();
        windowInfo.id = fdp.ConsumeIntegral<int32_t>();
        UpdateHotAreas(fdp, windowInfo);
        windowsInfo.push_back(windowInfo);

        DisplayInfo displayInfo;
        displayInfo.dpi = fdp.ConsumeIntegral<int32_t>();
        displayInfo.x = fdp.ConsumeIntegral<int32_t>();
        displayInfo.y = fdp.ConsumeIntegral<int32_t>();
        displayInfo.width = fdp.ConsumeIntegral<int32_t>();
        displayInfo.height = fdp.ConsumeIntegral<int32_t>();
        displayInfo.id = fdp.ConsumeIntegral<int32_t>();
        displayInfo.name = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
        std::string uniq = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
        displaysInfo.push_back(displayInfo);

        ScreenInfo screenInfo;
        screenInfo.screenType = static_cast<ScreenType>(windowInfo.windowType);
        screenInfo.dpi = displayInfo.dpi;
        screenInfo.height = windowInfo.area.height;
        screenInfo.width = windowInfo.area.width;
        screenInfo.physicalWidth = displayWidth;
        screenInfo.physicalHeight = displayHeight;
        screenInfo.id = displayInfo.id;
        screenInfo.rotation = Rotation::ROTATION_0;
        screenInfo.tpDirection = Direction::DIRECTION0;
        screenInfo.uniqueId = uniq;
        screenInfos.push_back(screenInfo);
    }

    displayGroupInfo.windowsInfo = windowsInfo;
    displayGroupInfo.displaysInfo = displaysInfo;

    UserScreenInfo userScreenInfo;
    userScreenInfo.displayGroups.push_back(displayGroupInfo);
    userScreenInfo.screens = screenInfos;

    InputManager::GetInstance()->UpdateDisplayInfo(userScreenInfo);
    MMI_HILOGD("Update display info success");
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    
    OHOS::MMI::UpdateDisplayInfoFuzzTest(data, size);
    return 0;
}