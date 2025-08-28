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

#include "pointer_event.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mmi_log.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEvent8FuzzTest"

namespace OHOS {
namespace MMI {
#define MAXBYTESIZE 50
void PointerEvent8FuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t eventType = provider.ConsumeIntegral<int32_t>();
    PointerEvent pointEvent(eventType);

    size_t bytesSize = provider.ConsumeIntegralInRange(1, MAXBYTESIZE);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    std::vector<uint8_t> enhanceData = provider.ConsumeBytes<uint8_t>(bytesSize);
    pointEvent.SetEnhanceData(enhanceData);
#endif

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    double fingerPrintDistanceX = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetFingerprintDistanceX(fingerPrintDistanceX);

    double fingerPrintDistanceY = provider.ConsumeFloatingPoint<double>();
    pointEvent.SetFingerprintDistanceY(fingerPrintDistanceY);
#endif

    bytesSize = provider.ConsumeIntegralInRange(1, MAXBYTESIZE);
    std::vector<uint8_t> buffer = provider.ConsumeBytes<uint8_t>(bytesSize);
    pointEvent.SetBuffer(buffer);

    MMI_HILOGD("PointerEvent8FuzzTest");
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

    OHOS::MMI::PointerEvent8FuzzTest(data, size);
    return 0;
}
