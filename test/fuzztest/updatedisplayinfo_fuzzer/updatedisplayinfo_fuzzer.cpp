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

#include <string>

#include "securec.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UpdateDisplayInfoFuzzTest" };
} // namespace
template<class T>
size_t GetObject(const uint8_t *data, size_t size, T &object)
{
    size_t objSize = sizeof(object);
    if (objSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objSize, data, objSize);
    if (ret != EOK) {
        return 0;
    }
    return objSize;
}

size_t GetString(const uint8_t *data, size_t size, char *object, size_t itemSize)
{
    if (itemSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, itemSize, data, itemSize);
    if (ret != EOK) {
        return 0;
    }
    return itemSize;
}

void UpdateHotAreas(const uint8_t* data, size_t size, WindowInfo &windowInfo)
{
    size_t startPos = 0;
    std::vector<Rect> defaultHotAreasInfo;
    std::vector<Rect> pointerHotAreasInfo;
    for (size_t j = 0; j < WindowInfo::MAX_HOTAREA_COUNT; ++j) {
        Rect defaultRect;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.y);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.height);
        defaultHotAreasInfo.push_back(defaultRect);
        Rect pointerRect;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.y);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.height);
        pointerHotAreasInfo.push_back(pointerRect);
    }
    windowInfo.pointerHotAreas = pointerHotAreasInfo;
    windowInfo.defaultHotAreas = defaultHotAreasInfo;
    std::vector<int32_t> pointerChangeAreasInfos;
    for (size_t j = 0; j < WindowInfo::POINTER_CHANGEAREA_COUNT; ++j) {
        int32_t temp = 0;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, temp);
        pointerChangeAreasInfos.push_back(temp);
    }
    windowInfo.pointerChangeAreas = pointerChangeAreasInfos;
    std::vector<float> transformInfos;
    for (size_t j = 0; j < WindowInfo::WINDOW_TRANSFORM_SIZE; ++j) {
        float temp = 0;
        startPos += GetObject<float>(data + startPos, size - startPos, temp);
        transformInfos.push_back(temp);
    }
    windowInfo.transform = transformInfos;
}

void UpdateDisplayInfoFuzzTest(const uint8_t* data, size_t size)
{
    DisplayGroupInfo displayGroupInfo;
    size_t startPos = 0;
    size_t stringSize = 4;
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.width);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.height);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.focusWindowId);
    std::vector<WindowInfo> windowsInfo;
    std::vector<DisplayInfo> displaysInfo;
    for (size_t i = 0; i < WindowInfo::MAX_HOTAREA_COUNT + 1; ++i) {
        WindowInfo windowInfo;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.y);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.pid);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.uid);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.height);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.id);
        UpdateHotAreas(data, size, windowInfo);
        windowsInfo.push_back(windowInfo);

        DisplayInfo displayInfo;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.dpi);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.y);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.height);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.id);
        char name[] = "name";
        startPos += GetString(data + startPos, size - startPos, name, stringSize);
        displayInfo.name = name;
        char uniq[] = "uniq";
        startPos += GetString(data + startPos, size - startPos, uniq, stringSize);
        displayInfo.uniq = uniq;
        displaysInfo.push_back(displayInfo);
    }
    displayGroupInfo.windowsInfo = windowsInfo;
    displayGroupInfo.displaysInfo = displaysInfo;
    InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo);
    MMI_HILOGD("Update display info success");
}
} // namespace MMI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::UpdateDisplayInfoFuzzTest(data, size);
    return 0;
}
