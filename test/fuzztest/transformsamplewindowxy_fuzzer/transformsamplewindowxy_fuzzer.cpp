/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "event_resample.h"
#include "transformsamplewindowxy_fuzzer.h"
#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TransformSampleWindowXYFuzzTest"

namespace OHOS {
namespace MMI {
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

bool TransformSampleWindowXYFuzzTest(const uint8_t *data, size_t size)
{
    size_t startPos = 0;
    PointerEvent::PointerItem pointerItem;
    int32_t windowX;
    int32_t windowY;
    double logicX;
    double logicY;
    startPos += GetObject<int32_t>(windowX, data + startPos, size - startPos);
    startPos += GetObject<int32_t>(windowY, data + startPos, size - startPos);
    startPos += GetObject<double>(logicX, data + startPos, size - startPos);
    startPos += GetObject<double>(logicY, data + startPos, size - startPos);
    pointerItem.SetToolWindowX(windowX);
    pointerItem.SetToolWindowY(windowY);
    EventResample eventResample;
    eventResample.TransformSampleWindowXY(nullptr, pointerItem, logicX, logicY);
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::MMI::TransformSampleWindowXYFuzzTest(data, size);
    return 0;
}
