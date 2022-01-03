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

import { Callback } from './basic';

declare namespace inputEventClient {
  enum EventCallback {
    ON_SHOW_MENU = 0,
    ON_SEND = 1,
    ON_COPY = 2,
    ON_PASTE = 3,
    ON_CUT = 4,
    ON_UNDO = 5,
    ON_REFRESH = 6,
    ON_CANCEL = 8,
    ON_ENTER = 9,
    ON_PREVIOUS = 10,
    ON_NEXT = 11,
    ON_BACK = 12,
    ON_PRINT = 13,
    ON_ANSWER = 14,
    ON_REFUSE = 15,
    ON_HANGUP = 16,
    ON_TELEPHONE_CONTROL = 17,
    ON_PLAY  = 18,
    ON_PAUSE = 19,
    ON_MEDIA_CONTROL = 20,
  };
  
  export interface MultimodalEvent {
    /**
     * the UUID of the event.
     * @since 1
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     */
    uuid: string;
  
    /**
     * The time when the current event is generated.
     * @since 1
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     */
    occurredTime: number;
  
    /**
     * The type of the input device that generates the current event.
     * @since 1
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     */
    sourceDevice: number;
  
    /**
     * The ID of the bearing device for the input device that generates the current event.
     * @since 1
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     */
    inputDeviceId: number;
  
    /**
     * Is it event type enum.
     * @since 1
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     */
    type: EventCallback;
  }
  
  type EventType = 'showMenu' | 'send' | 'copy' | 'paste' | 'cut' | 'undo' | 'refresh' | 'cancel' | 'enter' |
    'previous' | 'next' | 'back' | 'print' | 'answer' | 'refuse' | 'hangup' | 'telephoneControl' | 'play' |
    'pause' | 'mediaControl';

  // 注册接口
  function on(type: EventType, callback: Callback<MultimodalEvent>): void;

  //反注册接口
  function off(type: EventType, callback: Callback<MultimodalEvent>): void;


  type SourceType = 'keyboard' | 'mouse' | 'touchpad' | 'touchscreen' | 'tablet' | 'joystick' | 'accelerometer' |
    'tabletpad' | 'pointingstick' | 'trackball' | 'switch';

    /**
     * Defines the information about an input device.
     *
     * @sysCap MultimodalEvent API
     * @param name Name of the input device.
     * @param sources Source type supported by the input device. For example, if a keyboard is attached with a touchpad, the device has two input sources: keyboard and touchpad.
     */
  interface InputDeviceData {
    name: string;
    sources : Array<SourceType>;
  }

	  /**
     * Obtains the IDs of all input devices.
     *
     * @since 8
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     * @permission N/A
     * @param callback callback function, receive reported data
     */
    function getDeviceIds(callback: AsyncCallback<Array<number>>): void;

    /**
     * Obtain the information about an input device.
     *
     * @since 8
     * @sysCap MultimodalEvent API
     * @devices keyboard, mouse, touchscreen, trackpad, joystick, rotation, AI, sensor, stylus, remotecontrol, trackball.
     * @permission N/A
     * @param deviceId ID of the input device whose information is to be obtained.
     * @param callback callback function, receive reported data
     */
    function getDevice(deviceId: number, callback: AsyncCallback<InputDeviceData>): void;
}

export default inputEventClient;