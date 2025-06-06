/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import hilog from '@ohos.hilog'
import { Callback, AsyncCallback } from '@ohos.base';
import { BusinessError } from "@ohos.base"

export namespace inputDevice {
    loadLibrary("ani_input_device");

    export native function getDeviceListInner(): Array<number>;
    export native function getDeviceInfoInner(deviceId: number): InputDeviceData;

    export native function on(type: 'change', listener: Callback<DeviceListener>): void;

  /**
   * Add or remove device
   * @typedef { 'add' | 'remove' }
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 9
   */
  type ChangedType = 'add' | 'remove';

  /**
   * The type of input device
   * @typedef { 'keyboard' | 'mouse' | 'touchpad' | 'touchscreen' | 'joystick' | 'trackball' }
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 9
   */
  type SourceType = 'keyboard' | 'mouse' | 'touchpad' | 'touchscreen' | 'joystick' | 'trackball';

  /**
   * Axis Type of the input event
   * @typedef { 'touchmajor'| 'touchminor' | 'orientation' | 'x' | 'y' | 'pressure' | 'toolminor' | 'toolmajor' | 'null' }
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 9
   */
  type AxisType =
    'touchmajor'
    | 'touchminor'
    | 'orientation'
    | 'x'
    | 'y'
    | 'pressure'
    | 'toolminor'
    | 'toolmajor'
    | 'null';

  /**
   * @enum { number }
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 9
   */
  enum KeyboardType {
    /**
     * None
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    NONE = 0,

    /**
     * Unknown key
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    UNKNOWN = 1,

    /**
     * Alphabetical keyboard
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    ALPHABETIC_KEYBOARD = 2,

    /**
     * Digital keyboard
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    DIGITAL_KEYBOARD = 3,

    /**
     * Stylus
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    HANDWRITING_PEN = 4,

    /**
     * Remote control
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    REMOTE_CONTROL = 5
  }

  /**
   * Enumerates function keys.
   * 
   * @enum { number }
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 15
   */
  enum FunctionKey {
    /**
     * CapsLock key. Enabling or disabling the CapsLock key is allowed only for input keyboard extensions.
     *
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 15
     */
    CAPS_LOCK = 1
  }

  /**
   * Defines the listener for input device events.
   *
   * @interface DeviceListener
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 9
   */
  interface DeviceListener {
    /**
     * Type of the input device event. The options are add and remove.
     *
     * @type { ChangedType }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    type: ChangedType;

    /**
     * ID of the input device for the reported input device event.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    deviceId: number;
  }

  interface AxisRange {
    /**
     * Input source type of the axis. For example, if a mouse reports an x-axis event,
     * the source of the x-axis is the mouse.
     *
     * @type { SourceType }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    source: SourceType;

    /**
     * Type of the axis. for example, the x-axis, y-axis, and pressure axis.
     *
     * @type { AxisType }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    axis: AxisType;

    /**
     * Maximum value of the data reported on this axis.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    max: number;

    /**
     * Minimum value of the data reported on this axis.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    min: number;

    /**
     * Fuzz value of the data reported on this axis.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    fuzz: number;

    /**
     * Flat value of the data reported on this axis.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    flat: number;

    /**
     * Resolution value of the data reported on this axis.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    resolution: number;
  }

  /**
   * Defines the information about an input device.
   *
   * @interface InputDeviceData
   * @syscap SystemCapability.MultimodalInput.Input.InputDevice
   * @since 8
   */
  interface InputDeviceData {
    /**
     * Id of the input device.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    id: number;

    /**
     * Name of the input device.
     *
     * @type { string }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    name: string;

    /**
     * Source type supported by the input device. For example, if a keyboard is attached with a touchpad,
     * the device has two input sources: keyboard and touchpad.
     *
     * @type { Array<SourceType> }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    sources: Array<SourceType>;

    /**
     * Axis range of the input device.
     *
     * @type { Array<AxisRange> }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 8
     */
    axisRanges: Array<AxisRange>;

    /**
     * Bus of the input device.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    bus: number;

    /**
     * Product of the input device.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    product: number;

    /**
     * Vendor of the input device.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    vendor: number;

    /**
     * Version of the input device.
     *
     * @type { number }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    version: number;

    /**
     * Physical path of the input device.
     *
     * @type { string }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    phys: string;

    /**
     * Unique identifier of the input device.
     *
     * @type { string }
     * @syscap SystemCapability.MultimodalInput.Input.InputDevice
     * @since 9
     */
    uniq: string;
  }

  class InputDeviceDataImpl implements InputDeviceData {
    private nativePtr:long = 0;
    constructor(context:long) {
      hilog.info(0x0000, 'input_device', "in constructor, context is ", context)
      this.nativePtr = context;
    }

  setEmptyAxisRanges(): void {
    this.axisRanges = new Array<AxisRange>();
  }

    id: number;
    name: string;
    sources: Array<SourceType>;
    axisRanges: Array<AxisRange>;
    bus: number;
    product: number;
    vendor: number;
    version: number;
    phys: string;
    uniq: string;
  }

  class AxisRangeImpl implements AxisRange {
    private nativePtr:long = 0;
    constructor(context:long) {
      hilog.info(0x0000, 'input_device', "in constructor, context is ", context)
      this.nativePtr = context;
    }

    source: SourceType;
    axis: AxisType;
    max: number;
    min: number;
    fuzz: number;
    flat: number;
    resolution: number;
  }

  class DeviceListenerImpl implements DeviceListener {
    type: ChangedType;
    deviceId: number;
  }

  function getDeviceList(callback: AsyncCallback<Array<number>>): void {
    let p1 = taskpool.execute(getDeviceListInner);
    p1.then((data: NullishType) => {
        let r =  data as Array<number>;
        let err : BusinessError<void>
        callback(err, r);
    }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        let data = new Array<number>;
        callback(err, data);
    });
  }

  function getDeviceList(): Promise<Array<number>> {
    let p = new Promise<Array<number>>((resolve: (v: Array<number>) => void,
      reject: (error: Error) => void) => {
        let p1 = taskpool.execute(getDeviceListInner);
        p1.then((e :NullishType)=>{
          let r =  e as Array<number>;
          resolve(r);
        }).catch((error: Error) : Array<number> => {
          reject(error);
        });
    });
    return p;
  }

  function getDeviceInfo(deviceId: number, callback: AsyncCallback<InputDeviceData>): void {
    let p1 = taskpool.execute(getDeviceInfoInner, deviceId);
    p1.then((data: NullishType) => {
        let r =  data as InputDeviceData;
        let err : BusinessError<void>
        callback(err, r);
    }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        let data = new InputDeviceDataImpl(0);
        callback(err, data);
    });
  }
  function getDeviceInfo(deviceId: number): Promise<InputDeviceData> {
    let p = new Promise<InputDeviceData>((resolve: (v: InputDeviceData) => void,
      reject: (error: Error) => void) => {
        let p1 = taskpool.execute(getDeviceInfoInner, deviceId);
        p1.then((e :NullishType)=>{
          let r =  e as InputDeviceData;
          resolve(r);
        }).catch((error: Error) : InputDeviceData => {
          reject(error);
        });
    });
    return p;
  }
  function getDeviceInfoSync(deviceId: number): InputDeviceData {
    return getDeviceInfoInner(deviceId);
  }
}
