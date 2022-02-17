/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <functional>
#include <memory>
#include <mutex>
#include "nocopyable.h"
#include "parcel.h"

namespace OHOS {
namespace MMI {
class InputEvent {
public:
    // Unknown action. Usually used to indicate the initial value of the input event action
    static const int32_t ACTION_UNKNOWN = 0;
    // Cancel the action. Used to indicate that a continuous input event is cancelled
    static const int32_t ACTION_CANCEL = 1;

    // The actual type of the current input event is the basic type (InputEvent type)
    static const int32_t EVENT_TYPE_BASE = 0X00000000;
    // The actual type of the current input event is the KeyEvent type or its derived class
    static const int32_t EVENT_TYPE_KEY = 0X00010000;
    // The actual type of the current input event is the PointerEvent type or its derived class
    static const int32_t EVENT_TYPE_POINTER = 0X00020000;
    // The actual type of the current input event is the AxisEvent type or its derived class
    static const int32_t EVENT_TYPE_AXIS = 0X00030000;

    static const int32_t EVENT_FLAG_NONE = 0;
    static const int32_t EVENT_FLAG_NO_INTERCEPT = 1;

    static const int32_t DEFALUTID = -1;

public:
    InputEvent(const InputEvent& other);
    virtual ~InputEvent();
    virtual InputEvent& operator=(const InputEvent& other) = delete;
    DISALLOW_MOVE(InputEvent);
    static std::shared_ptr<InputEvent> Create();

    void Reset();
    /*
     * Get or set the unique identifier of the input event,
     * which is globally unique after being processed by the input service
     * Under normal circumstances, do not need to set
     */
    int32_t GetId() const;
    void SetId(int32_t id);

    /* *
     * Get or set the time when the current action occurred.
     * The default value is the object creation time
     * Under normal circumstances, do not need to set
     */
    int32_t GetActionTime() const;
    void SetActionTime(int32_t actionTime);

    /*
     * Get or set the current action
     */
    int32_t GetAction() const;
    void SetAction(int32_t action);

    /*
     * Action start time.
     * For instantaneous actions, it is consistent with the time when the action occurred.
     * For continuous actions, it indicates the start time of the continuous action
     */
    int32_t GetActionStartTime() const;
    void SetActionStartTime(int32_t time);

    /*
     * Get or set the unique identifier of the input device that reports the input event
     * The default value is 0, which means that the non-real device reports
     */
    int32_t GetDeviceId() const;
    void SetDeviceId(int32_t deviceId);

    /*
     * Gets or sets the target display ID of the input event.
     * The default is -1, which means that it is dynamically determined by the input service
     */
    int32_t GetTargetDisplayId() const;
    void SetTargetDisplayId(int32_t displayId);

    /*
     * Gets or sets the description window id of the input event.
     * The default value is -1, and the target window is determined by the input service.
     */
    int32_t GetTargetWindowId() const;
    void SetTargetWindowId(int32_t windowId);

    /*
     * Gets or sets the id of the input event agent window.
     * The input event originally sent to the target window will be sent to the proxy window.
     * The default value is -1. Indicates determined by the input service. External users should not set this value.
     */
    int32_t GetAgentWindowId() const;
    void SetAgentWindowId(int32_t windowId);

    /*
     * The actual type of the current input event.
     * Valid values are EVENT_TYPE_BASE, EVENT_TYPE_KEY, EVENT_TYPE_POINTER, EVENT_TYPE_AXIS
     */
    int32_t GetEventType() const;
    const char* DumpEventType() const;

    int32_t GetFlag() const;

    bool HasFlag(int32_t flag);

    void AddFlag(int32_t flag);

    void ClearFlag();

    void UpdateId();

    /*
     * Mark input event processing completed.
     * This method can only be called once.
     */
    void MarkProcessed();

    /*
     * Set the callback function when the input event is processed.
     * External users should not call this interface
     */
    void SetProcessedCallback(std::function<void(int32_t)> callback);

public:
    bool WriteToParcel(Parcel &out) const;
    bool ReadFromParcel(Parcel &in);

protected:
    explicit InputEvent(int32_t eventType);

protected:
    int32_t eventType_;
    int32_t id_;
    int32_t actionTime_;
    int32_t action_;
    int32_t actionStartTime_;
    int32_t deviceId_;
    int32_t targetDisplayId_;
    int32_t targetWindowId_;
    int32_t agentWindowId_;
    int32_t flag_;
    std::function<void(int32_t)> processedCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_H