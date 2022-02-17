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

#ifndef SPEECH_EVENT_H
#define SPEECH_EVENT_H

#include "multimodal_event.h"
#include "nocopyable.h"

namespace OHOS {
enum SpeechEnum {
    /**
    * Indicates the action of setting the switch to the ON state.
    *
    * @since 1
    */
    ACTION_SWITCH_ON = 1,

    /**
    * Indicates the action of setting the switch to the OFF state.
    *
    * @since 1
    */
    ACTION_SWITCH_OFF = 2,

    /**
    * Indicates the action of hitting a hot word.
    *
    * @since 1
    */
    ACTION_HIT_HOTWORD = 3,

    /**
    * Indicates the scene where the action is performed for a video.
    *
    * @since 1
    */
    SCENES_VIDEO = 4,

    /**
    * Indicates the scene where the action is performed for an audio.
    *
    * @since 1
    */
    SCENES_AUDIO = 5,

    /**
    * Indicates the scene where the action is performed for a page.
    *
    * @since 1
    */
    SCENES_PAGE = 6,

    /**
    * Indicates the scene where the action is performed for a switch.
    *
    * @since 1
    */
    SCENES_SWITCH = 7,

    /**
    * Indicates the common scene where voice action is performed.
    *
    * @since 1
    */
    SCENES_COMMON = 8,

    /**
    * Indicates the exact match mode.
    *
    * @since 1
    */
    MATCH_MODE_EXACT = 9,

    /**
    * Indicates the fuzzy match mode.
    *
    * @since 1
    */
    MATCH_MODE_FUZZY = 10
};

/**
 * Defines speech events. You can use this class to obtain the speech
 * recognition result.
 * <p>The system offers the speech recognition capability to recognize
 * user speeches and sends the recognition result to you as an event.
 * This event carries such information as the recognized speech action,
 * hot words.
 * @see MultimodalEvent
 * @since 3
 */
class SpeechEvent : public MMI::MultimodalEvent {
public:
    SpeechEvent() = default;
    DISALLOW_COPY_AND_MOVE(SpeechEvent);
    virtual ~SpeechEvent();
    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(int32_t windowId, int32_t action, int32_t scene, int32_t mode, const std::string& actionProperty,
                    int32_t highLevelEvent, const std::string& uuid, int32_t sourceType, int32_t occurredTime,
                    const std::string& deviceId, int32_t inputDeviceId, bool isHighLevelEvent,
                    uint16_t deviceUdevTags = 0);

    /**
    * initialize the object.
    *
    * @return void
    * @since 1
    */
    void Initialize(SpeechEvent& speechEvent);

    /**
     * Obtains the action of this speech event.
     *
     * @return Returns the action of this event. The value can be
     * {@link #ACTION_SWITCH_ON},{@link #ACTION_SWITCH_OFF}
     *  or {@link #ACTION_HIT_HOTWORD}.
     * @since 1
     */
    virtual int32_t GetAction() const;

    /**
     * Obtains the scene where the action is performed.
     *
     * @return Returns the scene, which can be {@link #SCENES_VIDEO},
     * {@link #SCENES_AUDIO},{@link #SCENES_PAGE}, {@link #SCENES_SWITCH}
     *  or {@link #SCENES_COMMON}.
     * @since 1
     */
    virtual int32_t GetScene() const;

    /**
     * Obtains the property value carried in {@code action}.
     *
     * @return Returns the property value carried in {@code action}.
     * @since 1
     */
    virtual std::string GetActionProperty() const;

    /**
    * Obtains the match mode for the current recognition result.
    *
    * @return Returns the match mode for the current recognition result,
    * which can be{@link #MATCH_MODE_EXACT} or {@link #MATCH_MODE_FUZZY}.
    * @since 1
    */
    virtual int32_t GetMatchMode() const;

private:
    int32_t mAction_ = 0;
    int32_t mScene_ = 0;
    int32_t mMode_ = 0;
    std::string mActionProperty_ = "";
};
} // namespace OHOS
#endif // SPEECH_EVENT_H