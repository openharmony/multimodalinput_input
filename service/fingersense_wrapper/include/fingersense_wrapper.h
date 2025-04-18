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

#ifndef FINGERSENSE_WRAPPER_H
#define FINGERSENSE_WRAPPER_H
#include "singleton.h"

namespace OHOS {
namespace MMI {
struct TouchInfo {
    float x { 0 };
    float y { 0 };
    int32_t touch_type { 0 };
};
class FingersenseWrapper final {
    DECLARE_DELAYED_SINGLETON(FingersenseWrapper);
public:
    DISALLOW_COPY_AND_MOVE(FingersenseWrapper);
    void InitFingerSenseWrapper();
    void SaveTouchInfo(float pointX, float pointY, int32_t toolType);
    int32_t CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType);
    typedef void (*SET_CURRENT_TOOL_TYPE)(struct TouchType, int32_t&);
    typedef void (*NOTIFY_TOUCH_UP)(struct TouchType*);
    typedef void (*ENABLE_FINGERSENSE)();
    typedef void (*DISABLE_FINGERSENSE)();
    typedef void (*SEND_FINGERSENSE_DISPLAYMODE)(int32_t);

    SET_CURRENT_TOOL_TYPE setCurrentToolType_ { nullptr };
    NOTIFY_TOUCH_UP notifyTouchUp_ { nullptr };
    ENABLE_FINGERSENSE enableFingersense_ { nullptr };
    DISABLE_FINGERSENSE disableFingerSense_ { nullptr };
    SEND_FINGERSENSE_DISPLAYMODE sendFingerSenseDisplayMode_ { nullptr };
private:
    void* fingerSenseWrapperHandle_ { nullptr };
    std::vector<TouchInfo> touchInfos_;
    bool IsEqual(float a, float b, float epsilon = 10.0);
    std::mutex lock_;
};

#define FINGERSENSE_WRAPPER ::OHOS::DelayedSingleton<FingersenseWrapper>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // FINGERSENSE_WRAPPER_H