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

#include "knuckle_handler_component.h"

namespace OHOS {
namespace MMI {

KnuckleHandlerComponent &KnuckleHandlerComponent::GetInstance()
{
    static KnuckleHandlerComponent inst;
    return inst;
}

void KnuckleHandlerComponent::SetCurrentToolType(struct TouchType touchType, int32_t &toolType)
{
    (void)touchType;
    (void)toolType;
}

void KnuckleHandlerComponent::NotifyTouchUp(struct TouchType *rawTouch)
{
    (void)rawTouch;
}

bool KnuckleHandlerComponent::SkipKnuckleDetect()
{
    return false;
}

void KnuckleHandlerComponent::SaveTouchInfo(float pointX, float pointY, int32_t toolType)
{
    (void)pointX;
    (void)pointY;
    (void)toolType;
}
} // namespace MMI
} // namespace OHOS