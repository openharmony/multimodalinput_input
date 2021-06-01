/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MULTIMODAL_EVENT_H
#define MULTIMODAL_EVENT_H

#include <string>
#include <iostream>
#include <memory>

#include "parcel.h"

namespace OHOS {
struct MultimodalProperty {
    int highLevelEvent;
    std::string uuid;
    int sourceType;
    int occurredTime;
    std::string deviceId;
    int inputDeviceId;
    bool isHighLevelEvent;
};

class MultimodalEvent : public Parcelable {
public:
    void Initialize(MultimodalProperty &multimodalStruct);

    bool IsSameEvent(const std::string &id);

    bool IsHighLevelInput();

    int GetHighLevelEvent();

    int GetSourceDevice();

    std::string GetDeviceId();

    int GetInputDeviceId();

    int GetOccurredTime();

    std::string GetUuid();
    bool Marshalling(Parcel &parcel) const override;
    static MultimodalEvent *Unmarshalling(Parcel &parcel);

    static constexpr int UNSUPPORTED_DEVICE = -1;

    static constexpr int TOUCH_PANEL = 0;

    static constexpr int KEYBOARD = 1;

    static constexpr int MOUSE = 2;

    static constexpr int STYLUS = 3;

    static constexpr int BUILTIN_KEY = 4;

    static constexpr int ROTATION = 5;

    static constexpr int SPEECH = 6;

    static constexpr int DEFAULT_TYPE = -1;

    static constexpr int MUTE = 91;

    static constexpr int NAVIGATION_UP = 280;

    static constexpr int NAVIGATION_DOWN = 281;

    static constexpr int NAVIGATION_LEFT = 282;

    static constexpr int NAVIGATION_RIGHT = 283;

    static constexpr int DAY_MODE = 5;

    static constexpr int NIGHT_MODE = 4;
protected:
    virtual ~MultimodalEvent() = default;
    MultimodalProperty multiProperty_;
};
}  // namespace OHOS
#endif  // MULTIMODAL_EVENT_H