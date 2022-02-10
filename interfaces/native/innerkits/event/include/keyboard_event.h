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
#ifndef KEYBOARD_EVENT_H
#define KEYBOARD_EVENT_H
#include "key_event_pre.h"

namespace OHOS {
class KeyBoardEvent : public KeyEvent {
public:
    virtual ~KeyBoardEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, bool handledByIme, int32_t unicode, bool isSingleNonCharacter, bool isTwoNonCharacters,
                    bool isThreeNonCharacters, bool isPressed, int32_t keyCode, int32_t keyDownDuration,
                    int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, uint64_t occurredTime,
                    const std::string& deviceId, int32_t inputDeviceId,  bool isHighLevelEvent,
                    uint16_t deviceUdevTags = 0, int32_t deviceEventType = 0, bool isIntercepted = true);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(KeyBoardEvent& keyBoardEvent);

    /**
    * Starts the input method editor (IME).
    *
    * @see #disableIme()
    * @see #isHandledByIme()
    * @since 1
    */
    void EnableIme();

    /**
     * Closes the IME.
     *
     * @see #enableIme()
     * @see #isHandledByIme()
     * @since 1
     */
    void DisableIme();

    /**
     * Checks whether the IME is in use.
     *
     * @return Returns {@code true} if the IME is in use; returns
     * {@code false} otherwise.@see #enableIme()
     * @see #disableIme()
     * @since 1
     */
    bool IsHandledByIme();

    /**
     * Checks whether a single input non-character key is pressed.
     *
     * <p>A non-character key is any key except those with visible
     * characters (such as A-Z, 0-9,space, comma, and period). Typical
     * examples are the Ctrl, Alt, and Shift keys.
     * @param keycode Indicates the keycode of the first non-character key.
     * @return Returns {@code true} if the input non-character key mapping
     * to the keycode is pressed; returns {@code false} otherwise.
     * @since 1
     */
    virtual bool IsNoncharacterKeyPressed(int32_t keycodeOne);

    /**
     * Checks whether two input non-character keys are both pressed.
     *
     * <p>A non-character key is any key except those with visible characters
     *  (such as A-Z, 0-9,space, comma, and period). Typical examples are
     * the Ctrl, Alt, and Shift keys.
     * @param keycode1 Indicates the keycode of the first non-character key.
     * @param keycode2 Indicates the keycode of the second non-character key.
     * @return Returns {@code true} if the two input non-character keys
     * mapping to the keycodes are pressed; returns {@code false} otherwise.
     * @since 1
     */
    virtual bool IsNoncharacterKeyPressed(int32_t keycodeOne, int32_t keycodeTwo);

    /**
     * Checks whether three input non-character keys are all pressed.
     *
     * <p>A non-character key is any key except those with visible characters
     * (such as A-Z, 0-9,space, comma, and period). Typical examples are the
     *  Ctrl, Alt, and Shift keys.
     * @param keycode1 Indicates the keycode of the first non-character key.
     * @param keycode2 Indicates the keycode of the second non-character key.
     * @param keycode3 Indicates the keycode of the third non-character key.
     * @return Returns {@code true} if the three input non-character keys
     * mapping to the keycodes are pressed; returns {@code false} otherwise.
     * @since 1
     */
    virtual bool IsNoncharacterKeyPressed(int32_t keycodeOne, int32_t keycodeTwo, int32_t keycodeThree);

    /**
    * Obtains the Unicode mapping to a key.
    *
    * <p>A Unicode code is a combination of keys and non-character keys.
    *
    * @return Returns the Unicode mapping to the key; returns 0 if there
    * is no matching Unicode.
    * @since 1
    */
    virtual int32_t GetUnicode() const;
private:
    bool mHandledByIme_ = false;
    int32_t mUnicode_ = 0;
};
}
#endif // KEYBOARD_EVENT_H