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

#include  "keyboard_event.h"
namespace OHOS {
void KeyBoardEvent::Initialize(MultimodalProperty &multiProperty,
                               KeyProperty &keyProperty,
                               KeyBoardProperty &keyBoardProperty)
{
    KeyEvent::Initialize(multiProperty, keyProperty);
    keyBoardProperty_.handledByIme = keyBoardProperty.handledByIme;
    keyBoardProperty_.unicode = keyBoardProperty.unicode;
    keyBoardProperty_.isSingleNonCharacter = keyBoardProperty.isSingleNonCharacter;
    keyBoardProperty_.isTwoNonCharacters = keyBoardProperty.isTwoNonCharacters;
    keyBoardProperty_.isThreeNonCharacters = keyBoardProperty.isThreeNonCharacters;
}

void KeyBoardEvent::EnableIme()
{
}

void KeyBoardEvent::DisableIme()
{
}

bool KeyBoardEvent::IsHandledByIme()
{
    return keyBoardProperty_.handledByIme;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int keycodeOne)
{
    return keyBoardProperty_.isSingleNonCharacter;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int keycodeOne, int keycodeTwo)
{
    return keyBoardProperty_.isTwoNonCharacters;
}

bool KeyBoardEvent::IsNoncharacterKeyPressed(int keycodeOne, int keycodeTwo, int keycodeThree)
{
    return keyBoardProperty_.isThreeNonCharacters;
}

int KeyBoardEvent::GetUnicode()
{
    return keyBoardProperty_.unicode;
}

bool KeyBoardEvent::Marshalling(Parcel &parcel) const
{
    return false;
}

KeyBoardEvent *KeyBoardEvent::Unmarshalling(Parcel &parcel)
{
    return new (std::nothrow) KeyBoardEvent();
}
}
