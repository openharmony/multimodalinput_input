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

#include "multimodal_event.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
MultimodalEvent::~MultimodalEvent() {}
void MultimodalEvent::Initialize(int32_t windowId, int32_t highLevelEvent, const std::string& uuid, int32_t sourceType,
                                 uint64_t occurredTime, const std::string& deviceId, int32_t inputDeviceId,
                                 bool isHighLevelEvent, uint16_t deviceUdevTags, bool isIntercepted)
{
    mWindowId_ = windowId;
    mUuid_ = uuid;
    mOccurredTime_ = occurredTime;
    mSourceDevice_ = DeviceTypeTransform(sourceType);
    mHighLevelEvent_ = highLevelEvent;
    mDeviceId_ = deviceId;
    mInputDeviceId_ = inputDeviceId;
    mIsHighLevelEvent_ = isHighLevelEvent;
    mDeviceUdevTags_ = deviceUdevTags;
    mEventType_ =  sourceType;
    isIntercepted_ = isIntercepted;
}

void MultimodalEvent::Initialize(const MultimodalEvent& multimodalEvent)
{
    mWindowId_ = multimodalEvent.GetWindowID();
    mUuid_ = multimodalEvent.GetUuid();
    mOccurredTime_ = multimodalEvent.GetOccurredTime();
    mSourceDevice_ = multimodalEvent.GetSourceDevice();
    mHighLevelEvent_ = multimodalEvent.GetHighLevelEvent();
    mDeviceId_ = multimodalEvent.GetDeviceId();
    mInputDeviceId_ = multimodalEvent.GetInputDeviceId();
    mIsHighLevelEvent_ = multimodalEvent.IsHighLevelInput();
    mDeviceUdevTags_ = multimodalEvent.GetDeviceUdevTags();
    mEventType_ =  multimodalEvent.GetEventType();
}

/*
 * Checks whether the current event is the same as the event with the specified UUID.
 *
 * @param id Specifies UUID of the event to be checked.
 * @return Returns {@code true} if the current event is the same as the event with the
 * specified UUID; returns {@code false} otherwise.
 * @since 1
 */
bool MultimodalEvent::IsSameEvent(const std::string& id)
{
    return mUuid_ == id;
}

/*
 * Checks whether a high-level event can be generated with the current event.
 *
 * @return Returns {@code true} if a high-level event can be generated with the current
 * event; returns {@code false} otherwise.
 * @hide
 * @since 1
 */
bool MultimodalEvent::IsHighLevelInput() const
{
    return mIsHighLevelEvent_;
}

/*
 * Obtains the high-level event generated with the current event.
 * The event type is mainly used for triggering of a callback.
 *
 * @return Returns a high-level event if one has been generated; returns
 * {@link #DEFAULT_TYPE} otherwise.
 * @hide
 * @since 1
 */
int32_t MultimodalEvent::GetHighLevelEvent() const
{
    return mHighLevelEvent_;
}

/*
 * Obtains the type of the input device that generates the current event.
 *
 * @return Returns the type of the input device that generates the event.
 * The return values are as
 * follows:{@link #UNSUPPORTED_DEVICE}: no input device.Generally,
 * this is the default value.
 * {@link #TOUCH_PANEL}: touch panel
 * {@link #KEYBOARD}: keyboard
 * {@link #MOUSE}: mouse
 * {@link #STYLUS}: stylus
 * {@link #BUILTIN_KEY}: built-in key
 * {@link #ROTATION}: rotation component
 * {@link #SPEECH}: speech component
 * @since 3
 */
int32_t MultimodalEvent::GetSourceDevice() const
{
    return mSourceDevice_;
}

int32_t MultimodalEvent::GetEventType() const
{
    return mEventType_;
}

/*
 * Obtains the ID of the bearing device for the input device that
 * generates the current event.
 * <p>For example, if two mouse devices are connected to the same device,
 * this device is the bearing device of the two mouse devices.
 * @return Returns the ID of the bearing device for the input device
 * that generates the current event; returns {@code null} if there is
 * no input device.
 * @see #getInputDeviceId()
 * @since 1
 */
std::string MultimodalEvent::GetDeviceId() const
{
    return mDeviceId_;
}

/*
 * Obtains the ID of the input device that generates the current event.
 *
 * <p>An input device is identified by a unique ID. For example, when
 * two mouse devices generate an event respectively, the device ID in
 * the generated events are different. Thisallows your application to use the
 * device ID to identify the actual input device.
 * @return Returns the ID of the input device that generates the current
 * event; returns{@code -1} if there is no input device.
 * @see #getDeviceId()
 * @since 1
 */
int32_t MultimodalEvent::GetInputDeviceId() const
{
    return mInputDeviceId_;
}

/*
 * Obtains the time when the current event is generated.
 *
 * @return Returns the time (in ms) when the current event is generated.
 * @since 1
 */
uint64_t MultimodalEvent::GetOccurredTime() const
{
    return mOccurredTime_;
}

/**
 * Obtains the device tags.
 *
 * @return Returns the device tags when the current event is generated.
 * @since 1
 */
uint16_t MultimodalEvent::GetDeviceUdevTags() const
{
    return mDeviceUdevTags_;
}

std::string MultimodalEvent::GetUuid() const
{
    return mUuid_;
}

int32_t MultimodalEvent::GetWindowID() const
{
    return mWindowId_;
}

bool MultimodalEvent::IsIntercepted() const
{
    return isIntercepted_;
}

bool MultimodalEvent::marshalling()
{
    return false;
}

bool MultimodalEvent::unmarshalling()
{
    return false;
}

int32_t MultimodalEvent::DeviceTypeTransform(int32_t sourceType) const
{
    int32_t deviceType = UNSUPPORTED_DEVICE;

    switch (sourceType) {
        case DEVICE_TYPE_TOUCH_PANEL: {
            deviceType = TOUCH_PANEL;
            break;
        }
        case DEVICE_TYPE_KEYBOARD: {
            deviceType = KEYBOARD;
            break;
        }
        case DEVICE_TYPE_MOUSE: {
            deviceType = MOUSE;
            break;
        }
        case DEVICE_TYPE_STYLUS: {
            deviceType = STYLUS;
            break;
        }
        case DEVICE_TYPE_BUILTIN_KEY: {
            deviceType = BUILTIN_KEY;
            break;
        }
        case DEVICE_TYPE_ROTATION: {
            deviceType = ROTATION;
            break;
        }
        case DEVICE_TYPE_AI_SPEECH: {
            deviceType = SPEECH;
            break;
        }
        case DEVICE_TYPE_JOYSTICK: {
            deviceType = JOYSTICK;
            break;
        }
        case DEVICE_TYPE_TOUCHPAD: {
            deviceType = TOUCH_PAD;
            break;
        }
        case DEVICE_TYPE_KNUCKLE: {
            deviceType = KNUCKLE;
            break;
        }
        default: {
            deviceType = UNSUPPORTED_DEVICE;
            break;
        }
    }
    return deviceType;
}
}
}
