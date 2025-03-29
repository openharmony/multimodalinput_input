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
import { AsyncCallback } from "@ohos.base"
import { BusinessError } from "@ohos.base"
import image from '@ohos.multimedia.image';

export namespace pointer {
  loadLibrary("ani_pointer");

  export native function setPointerStyleInner(windowId: number, pointerStyle: PointerStyle): int;

  export enum PointerStyle {
    DEFAULT,
    EAST,
    WEST,
    SOUTH,
    NORTH,

    /**
     * East-west arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    WEST_EAST,

    /**
     * North-south arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    NORTH_SOUTH,

    /**
     * North-east arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    NORTH_EAST,

    /**
     * North-west arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    NORTH_WEST,

    /**
     * South-east arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    SOUTH_EAST,

    /**
     * South-west arrow
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    SOUTH_WEST,

    /**
     * Northeast and southwest adjustment
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    NORTH_EAST_SOUTH_WEST,

    /**
     * Northwest and southeast adjustment
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    NORTH_WEST_SOUTH_EAST,

    /**
     * Cross (accurate selection)
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    CROSS,

    /**
     * Copy
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    CURSOR_COPY,

    /**
     * Forbid
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    CURSOR_FORBID,

    /**
     * Sucker
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    COLOR_SUCKER,

    /**
     * Grabbing hand
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    HAND_GRABBING,

    /**
     * Opening hand
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    HAND_OPEN,

    /**
     * Hand-shaped pointer
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    HAND_POINTING,

    /**
     * Help
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    HELP,

    /**
     * Move
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MOVE,

    /**
     * Left and right resizing
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    RESIZE_LEFT_RIGHT,

    /**
     * Up and down resizing
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    RESIZE_UP_DOWN,

    /**
     * Screenshot crosshair
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    SCREENSHOT_CHOOSE,

    /**
     * Screenshot
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    SCREENSHOT_CURSOR,

    /**
     * Text selection
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    TEXT_CURSOR,

    /**
     * Zoom in
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    ZOOM_IN,

    /**
     * Zoom out
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    ZOOM_OUT,

    /**
     * Scrolling east
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_EAST,

    /**
     * Scrolling west
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_WEST,

    /**
     * Scrolling south
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_SOUTH,

    /**
     * Scrolling north
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_NORTH,

    /**
     * Scrolling north and south
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_NORTH_SOUTH,

    /**
     * Scrolling northeast
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_NORTH_EAST,

    /**
     * Scrolling northwest
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_NORTH_WEST,

    /**
     * Scrolling southeast
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_SOUTH_EAST,

    /**
     * Scrolling southwest
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_SOUTH_WEST,

    /**
     * Moving as a cone in four directions
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 9
     */
    MIDDLE_BTN_NORTH_SOUTH_WEST_EAST,

    /**
     * Horizontal text selection
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 10
     */
    HORIZONTAL_TEXT_CURSOR,

    /**
     * Precise selection
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 10
     */
    CURSOR_CROSS,

    /**
     * Cursor with circle style
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 10
     */
    CURSOR_CIRCLE,

    /**
     * Loading state with dynamic cursor
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 10
     */
    /**
     * Loading state with dynamic cursor
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @atomicservice
     * @since 12
     */
    LOADING,

    /**
     * Running state with dynamic cursor
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 10
     */
    /**
     * Running state with dynamic cursor
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @atomicservice
     * @since 12
     */
    RUNNING,

    /**
     * Scrolling east and west
     *
     * @syscap SystemCapability.MultimodalInput.Input.Pointer
     * @since 16
     */
    MIDDLE_BTN_EAST_WEST
  }

  export function setPointerStyle(windowId: number, pointerStyle: PointerStyle, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(setPointerStyleInner, windowId, pointerStyle);
      p1.then((data: NullishType) => {
        let ret =  data as int;
        hilog.info(0x0000, 'pointer', "setPointerStyleInner callback then. ret is " + ret);
        let err : BusinessError<void>
        callback(err, undefined);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        callback(err, undefined);
      });
  }

  export function setPointerStyle(windowId: number, pointerStyle: PointerStyle): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void,
        reject: (error: Object) => void) : void => {
        let p1 = taskpool.execute(setPointerStyleInner, windowId, pointerStyle);
          p1.then((e :NullishType) : void=>{
            let r = e as int;
            hilog.info(0x0000, 'pointer', "setPointerStyleInner Promise, ret is: " + r);
            resolve(undefined);
        }).catch((err: Error) : void => {
          reject(err);
        });
      });
      return p;
  }

  export function setPointerStyleSync(windowId: number, pointerStyle: PointerStyle): void {
    setPointerStyleInner(windowId, pointerStyle);
  }
}