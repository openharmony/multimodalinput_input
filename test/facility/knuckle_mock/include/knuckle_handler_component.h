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

#ifndef MMI_KNUCKLE_HANDLER_COMPONENT_MOCK_H
#define MMI_KNUCKLE_HANDLER_COMPONENT_MOCK_H

#include <gmock/gmock.h>
#include <cstdint>

namespace OHOS {
namespace MMI {

struct TouchType {
    int32_t id { 0 };
    float x { 0 };
    float y { 0 };
    float touch_major { 0 };
    float touch_minor { 0 };
    float pressure { 0 };
    float orientation { 0 };
    float tool_major { 0 };
    float tool_minor { 0 };
    int32_t touch_kind { 0 };
    int32_t displayId { 0 };
};

class KnuckleHandlerComponent {
public:
    KnuckleHandlerComponent() = default;
    virtual ~KnuckleHandlerComponent() = default;

    static KnuckleHandlerComponent &GetInstance();

    void SetCurrentToolType(struct TouchType touchType, int32_t &toolType);
    void NotifyTouchUp(struct TouchType *rawTouch);
    bool SkipKnuckleDetect();
    void SaveTouchInfo(float pointX, float pointY, int32_t toolType);
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_KNUCKLE_HANDLER_COMPONENT_MOCK_H