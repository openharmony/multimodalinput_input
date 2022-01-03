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

#include "builtinkey_event.h"
#include "event_factory.h"
#include "keyboard_event.h"
#include "rotation_event.h"
#include "speech_event.h"
#include "stylus_event.h"
#include "touch_event.h"

namespace OHOS {
template<class T>
MultimodalEventPtr Create()
{
    return MultimodalEventPtr(new T());
}

MultimodalEventPtr EventFactory::CreateEvent(EventType eventType)
{
    switch (eventType) {
        case EventType::EVENT_MULTIMODAL:
            return Create<MultimodalEvent>();
        case EventType::EVENT_KEY:
            return Create<KeyEvent>();
        case EventType::EVENT_KEYBOARD:
            return Create<KeyBoardEvent>();
        case EventType::EVENT_MOUSE:
            return Create<MouseEvent>();
        case EventType::EVENT_MANIPULATION:
            return Create<ManipulationEvent>();
        case EventType::EVENT_TOUCH:
            return Create<TouchEvent>();
        case EventType::EVENT_STYLUS:
            return Create<StylusEvent>();
        case EventType::EVENT_ROTATION:
            return Create<RotationEvent>();
        case EventType::EVENT_SPEECH:
            return Create<SpeechEvent>();
        case EventType::EVENT_BUILTINKEY:
            return Create<BuiltinKeyEvent>();
        case EventType::EVENT_COMPOSITE:
            return Create<CompositeEvent>();
        default:
            return nullptr;
    }
    return nullptr;
}
}