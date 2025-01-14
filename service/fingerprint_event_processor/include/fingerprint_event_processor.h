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

struct SmartKeySwitch {
    std::string keyString { "" };
    std::string valueString { "1" };
};

class FingerprintEventProcessor {
    DECLARE_DELAYED_SINGLETON(FingerprintEventProcessor);

public:
    DISALLOW_COPY_AND_MOVE(FingerprintEventProcessor);
    bool IsFingerprintEvent(struct libinput_event* event);
    int32_t HandleFingerprintEvent(struct libinput_event* event);
    void SetPowerAndVolumeKeyState(struct libinput_event* event);
    void SetScreenState(struct libinput_event* event);
    void SetPowerKeyState(struct libinput_event* event);

    static constexpr int32_t FINGERPRINT_CODE_DOWN { 121 };
    static constexpr int32_t FINGERPRINT_CODE_UP { 122 };
    static constexpr int32_t FINGERPRINT_CODE_CLICK { 123 };
    static constexpr int32_t FINGERPRINT_CODE_RETOUCH { 124 };
    static constexpr int32_t FINGERPRINT_CODE_CANCEL { 125 };

    static constexpr int32_t KEY_VOLUME_DOWN { 114 };
    static constexpr int32_t KEY_VOLUME_UP { 115 };
    static constexpr int32_t KEY_POWER { 116 };

private:
    int32_t AnalyseKeyEvent(struct libinput_event* event);
    int32_t AnalysePointEvent(struct libinput_event *event);
    int32_t SendFingerprintCancelEvent();
    void ChangeScreenMissTouchFlag(bool screenState, bool cancel);
    bool CheckMisTouchState();
    bool CheckScreenMisTouchState();
    bool CheckKeyMisTouchState();
    template <class T>
    void CreateStatusConfigObserver(T& item);
    void StartSmartKeyIfNeeded();
    void StartSmartKey(bool isShowDialog);
    void ProcessSlideEvent();
    void ProcessClickEvent();
    void ReportResSched(uint32_t resType, int64_t value);

    const std::string FINGERPRINT_SOURCE_KEY { "fingerprint" };
    const std::string FINGERPRINT_SOURCE_POINT { "hw_fingerprint_mouse" };

    using keyTimeMap = std::pair<int32_t, std::chrono::time_point<std::chrono::steady_clock>>;
    std::map<int32_t, keyTimeMap> keyStateMap_ {
        {
            114, {0, std::chrono::high_resolution_clock::now()},
        },
        {
            115, {0, std::chrono::high_resolution_clock::now()},
        },
        {
            116, {0, std::chrono::high_resolution_clock::now()},
        },
    };
    std::atomic_bool screenState_ { false };
    std::atomic_bool cancelState_ { false };
    std::atomic_bool fingerprintFlag_ {false};
    std::atomic_bool screenMissTouchFlag_ { false };
    std::atomic_bool isStartedSmartKeyBySlide_ { false };
    std::atomic_bool isStartedSmartKey_ { false };
    std::atomic_bool isCreatedObserver_ { false };
    std::mutex mutex_;
    struct SmartKeySwitch smartKeySwitch_;
};
#define FingerprintEventHdr ::OHOS::DelayedSingleton<FingerprintEventProcessor>::GetInstance()
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS
#endif // FINGERPRINT_EVENT_PROCESSOR_H