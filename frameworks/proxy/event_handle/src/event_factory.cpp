/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "event_factory.h"
#include "keyboard_event.h"
#include "touch_event.h"
#include "stylus_event.h"
#include "rotation_event.h"
#include "speech_event.h"
#include "builtinkey_event.h"

namespace OHOS {
template<class T>
MultimodalEventPtr Create()
{
    return MultimodalEventPtr(new T());
}

MultimodalEventPtr EventFactory::CreateEvent(int32_t eventType)
{
    switch (eventType) {
        case EVENT_MULTIMODAL:
            return Create<MultimodalEvent>();
        case EVENT_KEY:
            return Create<KeyEvent>();
        case EVENT_KEYBOARD:
            return Create<KeyBoardEvent>();
        case EVENT_MOUSE:
            return Create<MouseEvent>();
        case EVENT_MANIPULATION:
            return Create<ManipulationEvent>();
        case EVENT_TOUCH:
            return Create<TouchEvent>();
        case EVENT_STYLUS:
            return Create<StylusEvent>();
        case EVENT_ROTATION:
            return Create<RotationEvent>();
        case EVENT_SPEECH:
            return Create<SpeechEvent>();
        case EVENT_BUILTINKEY:
            return Create<BuiltinKeyEvent>();
        case EVENT_COMPOSITE:
            return Create<CompositeEvent>();
        default:
            return nullptr;
    }
    return nullptr;
}
}