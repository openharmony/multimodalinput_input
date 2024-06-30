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

#ifndef FINGERPRINT_EVENT_PROCESSOR_H
#define FINGERPRINT_EVENT_PROCESSOR_H

#include <map>
#include <memory>

#include "libinput.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
class FingerprintEventProcessor {
    DECLARE_DELAYED_SINGLETON(FingerprintEventProcessor);

public:
    DISALLOW_COPY_AND_MOVE(FingerprintEventProcessor);
    bool IsFingerprintEvent(struct libinput_event* event);
    int32_t HandleFingerprintEvent(struct libinput_event* event);

    static constexpr int32_t FINGERPRINT_CODE_DOWN { 121 };
    static constexpr int32_t FINGERPRINT_CODE_UP { 122 };
    static constexpr int32_t FINGERPRINT_CODE_CLICK { 123 };
    static constexpr int32_t FINGERPRINT_CODE_RETOUCH { 124 };

private:
    int32_t AnalyseKeyEvent(struct libinput_event* event);
    int32_t AnalysePointEvent(struct libinput_event *event);

    const std::string FINGERPRINT_SOURCE_KEY { "fingerprint" };
    const std::string FINGERPRINT_SOURCE_POINT { "hw_fingerprint_mouse" };
};
#define FingerprintEventHdr ::OHOS::DelayedSingleton<FingerprintEventProcessor>::GetInstance()
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS
#endif // FINGERPRINT_EVENT_PROCESSOR_H