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

#ifndef MMI_TOUCHPAD_TRANSFORM_PROCESSOR_MOCK_H
#define MMI_TOUCHPAD_TRANSFORM_PROCESSOR_MOCK_H

#include "gmock/gmock.h"
#include "libinput.h"
#include "nocopyable.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
enum class MulFingersTap : int32_t {
    NO_TAP = 0,
    TRIPLE_TAP = 3,
    QUAD_TAP = 4,
    QUINT_TAP = 5,
};

class IMultiFingersTapHandler {
public:
    IMultiFingersTapHandler() = default;
    virtual ~IMultiFingersTapHandler() = default;

    virtual int32_t HandleMulFingersTap(struct libinput_event_touch*, int32_t) = 0;
    virtual MulFingersTap GetMultiFingersState() = 0;
    virtual void SetMultiFingersTapHdrDefault() = 0;
    virtual void SetMultiFingersTapHdrDefault(bool isAllDefault) = 0;
    virtual bool ClearPointerItems(std::shared_ptr<PointerEvent>) = 0;
    virtual bool CanAddToPointerMaps(struct libinput_event_touch*) = 0;
    virtual bool CanUnsetPointerItem(struct libinput_event_touch*) = 0;
};

class MultiFingersTapHandler final : public IMultiFingersTapHandler {
public:
    enum class TapTrends : int32_t {
        BEGIN = 0,
        DOWNING = 1,
        UPING = 2,
        NO_MULTAP = 3,
    };

    static std::shared_ptr<MultiFingersTapHandler> GetInstance();
    static void ReleaseInstance();

    MultiFingersTapHandler() = default;
    ~MultiFingersTapHandler() override = default;
    DISALLOW_COPY_AND_MOVE(MultiFingersTapHandler);

    MOCK_METHOD(int32_t, HandleMulFingersTap, (struct libinput_event_touch*, int32_t));
    MOCK_METHOD(MulFingersTap, GetMultiFingersState, ());
    MOCK_METHOD(void, SetMultiFingersTapHdrDefault, ());
    MOCK_METHOD(void, SetMultiFingersTapHdrDefault, (bool));
    MOCK_METHOD(bool, ClearPointerItems, (std::shared_ptr<PointerEvent>));
    MOCK_METHOD(bool, CanAddToPointerMaps, (struct libinput_event_touch*));
    MOCK_METHOD(bool, CanUnsetPointerItem, (struct libinput_event_touch*));

private:
    static std::shared_ptr<MultiFingersTapHandler> instance_;
};

#define MULTI_FINGERTAP_HDR MultiFingersTapHandler::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_TOUCHPAD_TRANSFORM_PROCESSOR_MOCK_H
