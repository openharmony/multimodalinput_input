/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "setmousescrollrows_fuzzer.h"

#include "securec.h"

#include "input_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SetMouseScrollRowsFuzzTest" };
} // namespace

// class IEventObserver : public MMI::MMIEventObserver {
// public:
//     void SyncBundleName(int32_t pid, int32_t uid, std::string bundleName, int32_t syncStatus) override;
// };

template<class T>
size_t GetObject(T &object, const uint8_t *data, size_t size)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

void SetMouseScrollRowsFuzzTest(const uint8_t* data, size_t size)
{
    size_t startPos = 0;
    int32_t rowsBefore;
    int32_t rowsAfter;
    startPos += GetObject<int32_t>(rowsBefore, data + startPos, size - startPos);
    MMI_HILOGD("SetMouseScrollRows start");
    InputManager::GetInstance()->SetMouseScrollRows(rowsBefore);
    InputManager::GetInstance()->GetMouseScrollRows(rowsAfter);
}

// void SetCustomCursorFuzzTest(const uint8_t* data, size_t size)
// {
//     size_t startPos = 0;
//     int32_t focusX;
//     startPos += GetObject<int32_t>(focusX, data + startPos, size - startPos);
//     int32_t focusY;
//     startPos += GetObject<int32_t>(focusY, data + startPos, size - startPos);
//     auto window = WindowUtilsTest::GetInstance()->GetWindow();
//     CHKPV(window);
//     uint32_t windowId = window->GetWindowId();
//     std::unique_ptr<OHOS::Media::PixelMap> pixelMap = InputManagerUtil::SetMouseIconTest(iconPath);
//     ASSERT_NE(pixelMap, nullptr);
//     InputManager::GetInstance()->SetMouseHotSpot(windowId, focusX, focusY);
//     InputManager::GetInstance()->SetCustomCursor(windowId, (void *)pixelMap.get(), focusX, focusY);
// }

void SetPointerSizeFuzzTest(const uint8_t* data, size_t size)
{
    size_t startPos = 0;
    int32_t pointerSizeBefore;
    int32_t pointerSizeAfter;
    startPos += GetObject<int32_t>(pointerSizeBefore, data + startPos, size - startPos);
    InputManager::GetInstance()->SetPointerSize(pointerSizeBefore);
    InputManager::GetInstance()->GetPointerSize(pointerSizeAfter);
}

void GetAllMmiSubscribedEventsFuzzTest(const uint8_t* data, size_t size)
{
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> map;
    MMI_HILOGD("GetAllMmiSubscribedEventsFuzzTest start");
    InputManager::GetInstance()->GetAllMmiSubscribedEvents(map);
}

// void NotifyNapOnlineFuzzTest(const uint8_t* data, size_t size)
// {
//     auto mmiObserver = std::make_shared<IEventObserver>();
//     MMI_HILOGD("NotifyNapOnlineFuzzTest start");
//     InputManager::GetInstance()->AddInputEventObserver(mmiObserver);
//     InputManager::GetInstance()->RemoveInputEventObserver(mmiObserver);
// }

void SetNapStatusFuzzTest(const uint8_t* data, size_t size)
{
    InputManager::GetInstance()->SetNapStatus(10,20,"name",2);
}

void SetHoverScrollStateFuzzTest(const uint8_t* data, size_t size)
{
    bool isHoverState = true;
    InputManager::GetInstance()->SetHoverScrollState(isHoverState);
    bool notHoverState = false;
    InputManager::GetInstance()->SetHoverScrollState(notHoverState);
    bool getHoverState = true;
    InputManager::GetInstance()->GetHoverScrollState(getHoverState);
}

void PointerColorFuzzTest(const uint8_t* data, size_t size)
{
    int32_t firstColor = 0xA946F1;
    InputManager::GetInstance()->SetPointerColor(firstColor);
    int32_t getColor = 3;
    InputManager::GetInstance()->GetPointerColor(getColor);
}

void ClearWindowPointerStyleFuzzTest(const uint8_t* data, size_t size)
{
    InputManager::GetInstance()->ClearWindowPointerStyle(0,0);
}

void SetKeyboardRepeatDelayFuzzTest(const uint8_t* data, size_t size)
{
    int32_t delayTime = 10;
    InputManager::GetInstance()->SetKeyboardRepeatDelay(delayTime);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::SetMouseScrollRowsFuzzTest(data, size);
    // OHOS::MMI::SetCustomCursorFuzzTest(data, size);
    OHOS::MMI::SetPointerSizeFuzzTest(data, size);
    OHOS::MMI::GetAllMmiSubscribedEventsFuzzTest(data, size);
    // OHOS::MMI::NotifyNapOnlineFuzzTest(data, size);
    OHOS::MMI::SetNapStatusFuzzTest(data, size);
    OHOS::MMI::SetHoverScrollStateFuzzTest(data, size);
    OHOS::MMI::PointerColorFuzzTest(data, size);
    OHOS::MMI::ClearWindowPointerStyleFuzzTest(data, size);
    OHOS::MMI::SetKeyboardRepeatDelayFuzzTest(data, size);
    return 0;
}

