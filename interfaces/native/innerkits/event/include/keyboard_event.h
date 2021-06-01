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

#ifndef KEYBOARD_EVENT_H
#define KEYBOARD_EVENT_H

#include "key_event.h"

namespace OHOS {
struct KeyBoardProperty {
    bool handledByIme;
    int unicode;
    bool isSingleNonCharacter;
    bool isTwoNonCharacters;
    bool isThreeNonCharacters;
};

class KeyBoardEvent :public KeyEvent {
public:
    void Initialize(MultimodalProperty &multiProperty, KeyProperty &keyProperty, KeyBoardProperty &keyBoardProperty);

    void EnableIme();

    void DisableIme();

    bool IsHandledByIme();

    virtual bool IsNoncharacterKeyPressed(int keycodeOne);

    virtual bool IsNoncharacterKeyPressed(int keycodeOne, int keycodeTwo);

    virtual bool IsNoncharacterKeyPressed(int keycodeOne, int keycodeTwo, int keycodeThree);

    virtual int GetUnicode();
    bool Marshalling(Parcel &parcel) const override;
    static KeyBoardEvent *Unmarshalling(Parcel &parcel);
protected:
    KeyBoardProperty keyBoardProperty_;
};
}  // namespace OHOS
#endif  // KEYBOARD_EVENT_H