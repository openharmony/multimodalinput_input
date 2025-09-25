/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_EVENT_H
#define INPUT_EVENT_H

#include "parcel.h"

namespace OHOS {
namespace MMI {
class InputEvent : public Parcelable {
public:
    /**
     * Unknown action. It is usually used as the initial value.
     *
     * @since 9
     */
    static constexpr int32_t ACTION_UNKNOWN = 0;

    /**
     * Cancel the action. It indicates that a consecutive input event is cancelled.
     *
     * @since 9
     */
    static constexpr int32_t ACTION_CANCEL = 1;

    /**
     * The actual type of the current input event is the basic type (InputEvent type).
     *
     * @since 9
     */
    static constexpr int32_t EVENT_TYPE_BASE = 0X00000000;

    /**
     * The actual type of the current input event is KeyEvent or its derived class.
     *
     * @since 9
     */
    static constexpr int32_t EVENT_TYPE_KEY = 0X00010000;

    /**
     * The actual type of the current input event is PointerEvent or its derived class.
     *
     * @since 9
     */
    static constexpr int32_t EVENT_TYPE_POINTER = 0X00020000;

    /**
     * The actual type of the current input event is AxisEvent or its derived class.
     *
     * @since 9
     */
    static constexpr int32_t EVENT_TYPE_AXIS = 0X00030000;

    /**
     * The actual type of the current input event is FingerprintEvent or its derived class.
     *
     * @since 12
     */
    static constexpr int32_t EVENT_TYPE_FINGERPRINT = 0X00040000;

    /**
     * The multimodal input service sends input events to the interceptor and listener. This is the default value.
     *
     * @since 9
     */
    static constexpr uint32_t EVENT_FLAG_NONE = 0x00000000;

    /**
     * The multimodal input service does not intercept the input event.
     *
     * @since 9
     */
    static constexpr uint32_t EVENT_FLAG_NO_INTERCEPT = 0x00000001;

    /**
     * The multimodal input service does not listen for the input event.
     *
     * @since 9
     */
    static constexpr uint32_t EVENT_FLAG_NO_MONITOR = 0x00000002;

    /**
     * The multimodal input event from simulation.
     *
     * @since 10
     */
    static constexpr uint32_t EVENT_FLAG_SIMULATE = 0x00000004;

    /**
     * The multimodal input service hide pointer.
     *
     * @since 12
     */
    static constexpr uint32_t EVENT_FLAG_HIDE_POINTER = 0x00000008;

    static constexpr uint32_t EVENT_FLAG_RAW_POINTER_MOVEMENT = 0x00000010;
    static constexpr uint32_t EVENT_FLAG_TOUCHPAD_POINTER = 0x00000020;
    static constexpr uint32_t EVENT_FLAG_PRIVACY_MODE = 0x00000040;
    static constexpr uint32_t EVENT_FLAG_ACCESSIBILITY = 0x00000100;

    /**
     * The multimodal input event from navigation window.
     *
     * @since 12
     */
    static constexpr uint32_t EVENT_FLAG_SIMULATE_NAVIGATION = 0x00000200;

    static constexpr uint32_t EVENT_FLAG_GENERATE_FROM_REAL = 0x00000400;
    
    static constexpr uint32_t EVENT_FLAG_SHOW_CUSOR_WITH_TOUCH = 0x00000600;

    static constexpr uint32_t EVENT_FLAG_VIRTUAL_TOUCHPAD_POINTER = 0x00001000;

      /**
     * The multimodal input event for device enter focus flag.
     *
       * @since 19
      */
    static constexpr uint32_t EVENT_FLAG_KEYBOARD_ENTER_FOCUS = 0x00002000;
     /**
      * The multimodal input event for device exit focus flag.
     *
     * @since 19
     */
    static constexpr uint32_t EVENT_FLAG_KEYBOARD_EXIT_FOCUS = 0x00004000;

    static constexpr uint32_t EVENT_FLAG_GESTURE_SUPPLEMENT = 0x00008000;

    static constexpr uint32_t EVENT_FLAG_KEYBOARD_ESCAPE = 0x00080000;

    static constexpr uint32_t EVENT_FLAG_UITEST = 0x00010000;

    static constexpr uint32_t EVENT_FLAG_DISABLE_PULL_THROW = 0x00020000;

    static constexpr uint32_t EVENT_FLAG_DISABLE_USER_ACTION = 0x00040000;
    /**
     * The multimodal input event for the device to enable the intercom mode flag.
     *
     * @since 21
     */
    static constexpr uint32_t EVENT_MEETIME = 0x00090000;

    /**
     * Indicates an unknown input source type. It is usually used as the initial value.
     *
     * @since 9
     */
    static constexpr int32_t SOURCE_TYPE_UNKNOWN = 0;

    /**
     * Indicates that the input source generates events similar to mouse cursor movement,
     * button press and release, and wheel scrolling.
     *
     * @since 9
     */
    static constexpr int32_t SOURCE_TYPE_MOUSE = 1;

    /**
     * Indicates that the input source generates a touchscreen multi-touch event.
     *
     * @since 9
     */
    static constexpr int32_t SOURCE_TYPE_TOUCHSCREEN = 2;

    /**
     * Indicates that the input source generates a touchpad multi-touch event.
     *
     * @since 9
     */
    static constexpr int32_t SOURCE_TYPE_TOUCHPAD = 3;

    /**
     * Indicates joystick-like events generated by the input source, such as button pressing, button lifting,
     * and wheel scrolling.
     *
     * @since 9
     */
    static constexpr int32_t SOURCE_TYPE_JOYSTICK = 4;

    /**
     * Indicates that the input source generates a fingerprint event.
     *
     * @since 12
     */
    static constexpr int32_t SOURCE_TYPE_FINGERPRINT = 5;

    /**
     * Indicates that the input source generates a crown event.
     *
     * @since 12
     */
    static constexpr int32_t SOURCE_TYPE_CROWN = 6;

    /**
     * Indicates that the input source generates left and right hand event.
     *
     * @since 16
     */
    static constexpr int32_t SOURCE_TYPE_MSDP_HAND_OPTINON = 7;

    /**
     * Indicates that the input source generates a x-key event.
     *
     * @since 16
     */
    static constexpr int32_t SOURCE_TYPE_X_KEY = 8;

public:
    /**
     * Copy constructor function for InputEvent
     *
     * @since 9
     */
    InputEvent(const InputEvent &other);

    /**
     * Virtual destructor of InputEvent
     *
     * @since 9
     */
    virtual ~InputEvent();

    virtual InputEvent& operator=(const InputEvent& other) = delete;
    DISALLOW_MOVE(InputEvent);

    /**
     * Create InputEvent object
     *
     * @since 9
     */
    static std::shared_ptr<InputEvent> Create();

    /**
     * @brief Converts an input event type into a string.
     * @param Indicates the input event type.
     * @return Returns the string converted from the input event type.
     * @since 9
     */
    static const char* EventTypeToString(int32_t eventType);

    /**
     * @brief Resets an input event to the initial state.
     * @return void
     * @since 9
     */
    virtual void Reset();

    virtual std::string ToString();

    /**
     * @brief Obtains the unique ID of an input event.
     * @return Returns the unique ID of the input event.
     * @since 9
     */
    int32_t GetId() const;

    /**
     * @brief Sets the unique ID of an input event.
     * @param id Indicates the unique ID.
     * @return void
     * @since 9
     */
    void SetId(int32_t id);

    /**
     * @brief Updates the unique ID of an input event.
     * @return void
     * @since 9
     */
    void UpdateId();

    /**
     * @brief Obtains the time when the action for this input event occurs.
     * @return Returns the time when the action for this input event occurs.
     * @since 9
     */
    int64_t GetActionTime() const;

    /**
     * @brief Sets the time when the action for this input event occurs.
     * @param actionTime Indicates the time when the action for this input event occurs.
     * @return void
     * @since 9
     */
    void SetActionTime(int64_t actionTime);

    /**
     * @brief Get the time when sensor perceive the event.
     * @param sensorTime Indicates the time when sensor event occurs.
     * @return void
     * @since 9
     */
    void SetSensorInputTime(uint64_t sensorTime);

    /**
     * @brief Set the time for sensor when the action for this input event occurs.
     * @return Returns the time when sensor perceive the event.
     * @since 9
     */
    uint64_t GetSensorInputTime() const;

    /**
     * @brief Obtains the action for this input event.
     * @return Returns the action for this input event.
     * @since 9
     */
    int32_t GetAction() const;

    /**
     * @brief Sets the action for this input event.
     * @param action Indicates the action for the input event.
     * @return void
     * @since 9
     */
    void SetAction(int32_t action);

    /**
     * @brief Obtains the time when the action for the first input event in a series of related input events occurs.
     * @return Returns the time when the action for the first input event occurs.
     * @since 9
     */
    int64_t GetActionStartTime() const;

    /**
     * @brief Sets the time when the action for the first input event in a series of related input events occurs.
     * @param time Indicates the time when the action for the first input event occurs.
     * @return void
     * @since 9
     */
    void SetActionStartTime(int64_t time);

    /**
     * @brief Obtains the unique ID of the device that generates this input event.
     * @return Returns the unique ID of the device.
     * @since 9
     */
    int32_t GetDeviceId() const;

    /**
     * @brief Sets the unique ID of the device that generates this input event.
     * @param deviceId Indicates the unique ID of the device.
     * @return void
     * @since 9
     */
    void SetDeviceId(int32_t deviceId);

    /**
     * @brief Obtains the source type of this event.
     * @return Returns the source type.
     * @since 9
     */
    int32_t GetSourceType() const;

    /**
     * @brief Sets the source type for this event.
     * @param sourceType Indicates the source type to set.
     * @return void
     * @since 9
     */
    void SetSourceType(int32_t sourceType);

    /**
     * @brief Dumps the source type of this pointer input event as a string.
     * @return Returns the pointer to the string.
     * @since 9
     */
    const char* DumpSourceType() const;

    /**
     * @brief Obtains the ID of the target display for an input event.
     * @return Returns the ID of the target display.
     * @since 9
     */
    int32_t GetTargetDisplayId() const;

    /**
     * @brief Sets the ID of the target screen for an input event.
     * @param displayId Indicates the ID of the target display.
     * @return void
     * @since 9
     */
    void SetTargetDisplayId(int32_t displayId);

    /**
     * @brief Obtains the ID of the target window for an input event.
     * @return Returns the ID of the target window.
     * @since 9
     */
    int32_t GetTargetWindowId() const;

    /**
     * @brief Sets the ID of the target window for an input event.
     * @param windowId Indicates the ID of the target window.
     * @return void
     * @since 9
     */
    void SetTargetWindowId(int32_t windowId);

    /**
     * @brief Obtains the ID of the agent window for an input event.
     * @return Returns the ID of the agent window.
     * @since 9
     */
    int32_t GetAgentWindowId() const;

    /**
     * @brief Sets the ID of the agent window for an input event.
     * @param windowId Indicates the ID of the agent window.
     * @return void
     * @since 9
     */
    void SetAgentWindowId(int32_t windowId);

    /**
     * @brief Obtains the type of the this input event.
     * @return Returns the type of the this input event.
     * @since 9
     */
    int32_t GetEventType() const;

    /**
     * @brief Obtains all flags of an input event.
     * @return Returns the flags of the input event.
     * @since 9
     */
    uint32_t GetFlag() const;

    /**
     * @brief Checks whether a flag has been set for an input event.
     * @param flag Indicates the flag of the input event.
     * @return Returns <b>true</b> if a flag has been set; returns <b>false</b> otherwise.
     * @since 9
     */
    bool HasFlag(uint32_t flag);

    /**
     * @brief Checks whether a flag the same as expected for an input event.
     * @param flag Indicates the flag of the input event.
     * @return Returns <b>true</b> if a flag the same as expected; returns <b>false</b> otherwise.
     * @since 19
     */
    bool IsFlag(uint32_t flag);

    /**
     * @brief Adds a flag for an input event.
     * @param flag Indicates the flag of the input event.
     * @return void
     * @since 9
     */
    void AddFlag(uint32_t flag);

    /**
     * @brief Clears all flags of an input event.
     * @return void
     * @since 9
     */
    void ClearFlag();

    /**
     * @brief Clears all flags of an input event.
     * @param flag Indicates the flag of the input event.
     * @return void
     * @since 12
     */
    void ClearFlag(uint32_t flag);

    /**
     * @brief Marks an input event as completed.
     * This method can only be called once.
     * @return void
     * @since 9
     */
    void MarkProcessed();

    /**
     * @brief Sets the callback invoked when an input event is processed.
     * This method is not available for third-party applications.
     * @return void
     * @since 9
     */
    void SetProcessedCallback(std::function<void(int32_t, int64_t)> callback);

    /**
     * @brief Sets the extra data of an input event.
     * @param data the extra data.
     * @param length data length in bytes.
     * @return void
     * @since 10
     */
    void SetExtraData(const std::shared_ptr<const uint8_t[]> data, uint32_t length);

    /**
     * @brief Obtains the extra data of an input event.
     * @param data the extra data.
     * @param length data length in bytes.
     * @return void
     * @since 10
     */
    void GetExtraData(std::shared_ptr<const uint8_t[]> &data, uint32_t &length) const;

    /**
     * @brief Checks whether the "Processed feedback" of this event is enabled or not.
     * @return Returns <b>true</b> if we need a "Processed feedback" for this event;
     * returns <b>false</b> otherwise.
     * @since 12
     */
    bool IsMarkEnabled() const;

    /**
     * @brief Sets the markEnabled_ field of an input event.
     * @param markEnabled Indicates whether we need a "Processed feedback" or not for this event.
     * @return void
     * @since 12
     */
    void SetMarkEnabled(bool markEnabled);

    /**
     * @brief Converts a input event action into a short string.
     * @param Indicates the input event action.
     * @return Returns the string converted from the input action.
     * @since 12
    */
    static std::string_view ActionToShortStr(int32_t action);
public:
    /**
     * @brief Writes data to a <b>Parcel</b> object.
     * @param out Indicates the object into which data will be written.
     * @return Returns <b>true</b> if the data is successfully written; returns <b>false</b> otherwise.
     * @since 9
     */
    bool WriteToParcel(Parcel &out) const;
    bool Marshalling(Parcel &out) const;

    /**
     * @brief Reads data from a <b>Parcel</b> object.
     * @param in Indicates the object from which data will be read.
     * @return Returns <b>true</b> if the data is successfully read; returns <b>false</b> otherwise.
     * @since 9
     */
    bool ReadFromParcel(Parcel &in);
    static InputEvent *Unmarshalling(Parcel &in);

protected:
    /**
     * @brief Constructs an input event object by using the specified input event type. Generally, this method
     * is used to construct a base class object when constructing a derived class object.
     * @since 9
     */
    explicit InputEvent(int32_t eventType);

private:
    int32_t eventType_ { -1 };
    int32_t id_ { -1 };
    int64_t actionTime_ { -1 };
    uint64_t sensorInputTime_ { 0 };
    int32_t action_ { -1 };
    int64_t actionStartTime_ { -1 };
    int32_t deviceId_ { -1 };
    int32_t sourceType_ { SOURCE_TYPE_UNKNOWN };
    int32_t targetDisplayId_ { -1 };
    int32_t targetWindowId_ { -1 };
    int32_t agentWindowId_ { -1 };
    uint32_t bitwise_ { 0 };
    bool markEnabled_ { true };
    std::shared_ptr<const uint8_t[]> extraData_;
    uint32_t extraDataLength_ { 0 };
    std::function<void(int32_t, int64_t)> processedCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_H
