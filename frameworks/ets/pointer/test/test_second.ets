/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


import pointer from '@ohos.multimodalInput.pointer';
import image from '@ohos.multimedia.image';
import { AsyncCallback, BusinessError } from '@ohos.base';

const Tag:String = "pointer"
const WAIT_OPER: long = 2000;
// You can use the command `hdc shell hidumper -s WindowManagerService -a '-a'` to view window IDs
const WINDOW_ID: int = 17;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

function test_getMouseScrollRows_callback() {
    let fun_name = 'test_getMouseScrollRows_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getMouseScrollRows(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getMouseScrollRows_promise() {
    let fun_name = 'test_getMouseScrollRows_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getMouseScrollRows().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadScrollSwitch_callback() {
    let fun_name = 'test_setTouchpadScrollSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadScrollSwitch(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadScrollSwitch_promise() {
    let fun_name = 'test_setTouchpadScrollSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadScrollSwitch(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadScrollSwitch_callback() {
    let fun_name = 'test_getTouchpadScrollSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadScrollSwitch(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadScrollSwitch_promise() {
    let fun_name = 'test_getTouchpadScrollSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadScrollSwitch().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadScrollDirection_callback() {
    let fun_name = 'test_setTouchpadScrollDirection_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadScrollDirection(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadScrollDirection_promise() {
    let fun_name = 'test_setTouchpadScrollDirection_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadScrollDirection(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadScrollDirection_callback() {
    let fun_name = 'test_getTouchpadScrollDirection_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadScrollDirection(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadScrollDirection_promise() {
    let fun_name = 'test_getTouchpadScrollDirection_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadScrollDirection().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadTapSwitch_callback() {
    let fun_name = 'test_setTouchpadTapSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadTapSwitch(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadTapSwitch_promise() {
    let fun_name = 'test_setTouchpadTapSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadTapSwitch(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadTapSwitch_callback() {
    let fun_name = 'test_getTouchpadTapSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadTapSwitch(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadTapSwitch_promise() {
    let fun_name = 'test_getTouchpadTapSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadTapSwitch().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadPointerSpeed_callback() {
    let fun_name = 'test_setTouchpadPointerSpeed_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadPointerSpeed(1, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadPointerSpeed_promise() {
    let fun_name = 'test_setTouchpadPointerSpeed_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadPointerSpeed(10).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadPointerSpeed_callback() {
    let fun_name = 'test_getTouchpadPointerSpeed_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadPointerSpeed(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadPointerSpeed_promise() {
    let fun_name = 'test_getTouchpadPointerSpeed_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadPointerSpeed().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadPinchSwitch_callback() {
    let fun_name = 'test_setTouchpadPinchSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadPinchSwitch(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadPinchSwitch_promise() {
    let fun_name = 'test_setTouchpadPinchSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadPinchSwitch(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadPinchSwitch_callback() {
    let fun_name = 'test_getTouchpadPinchSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadPinchSwitch(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadPinchSwitch_promise() {
    let fun_name = 'test_getTouchpadPinchSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadPinchSwitch().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadSwipeSwitch_callback() {
    let fun_name = 'test_setTouchpadSwipeSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadSwipeSwitch(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadSwipeSwitch_promise() {
    let fun_name = 'test_setTouchpadSwipeSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadSwipeSwitch(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadSwipeSwitch_callback() {
    let fun_name = 'test_getTouchpadSwipeSwitch_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadSwipeSwitch(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadSwipeSwitch_promise() {
    let fun_name = 'test_getTouchpadSwipeSwitch_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadSwipeSwitch().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadRightClickType_callback() {
    let fun_name = 'test_setTouchpadRightClickType_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadRightClickType(pointer.RightClickType.TOUCHPAD_RIGHT_BUTTON, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadRightClickType_promise() {
    let fun_name = 'test_setTouchpadRightClickType_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadRightClickType(pointer.RightClickType.TOUCHPAD_RIGHT_BUTTON).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadRightClickType_callback() {
    let fun_name = 'test_getTouchpadRightClickType_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: pointer.RightClickType|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadRightClickType(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadRightClickType_promise() {
    let fun_name = 'test_getTouchpadRightClickType_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: pointer.RightClickType) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadRightClickType().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setCustomCursor_promise() {
    let fun_name = 'test_setCustomCursor_promise';
    console.log(Tag, `into func ${fun_name}`);
    let width: int = 64;
    let height: int = 64;
    const buffer = new ArrayBuffer(width * height * 4); // RGBA_8888
    const pixelView = new Uint8Array(buffer);
    for (let i = 0; i < pixelView.length; i += 4) {
        pixelView[i] = 0xFF;  // Set the RGBA channel values
        pixelView[i+1] = 0x00;
        pixelView[i+2] = 0x00;
        pixelView[i+3] = 0xFF; // opaque
    }
    const opts: image.InitializationOptions = {
        editable: true,
        pixelFormat: image.PixelMapFormat.RGBA_8888,
        size: { width: width, height: height }
    };
    let img = image.createPixelMapSync(buffer, opts);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setCustomCursor(WINDOW_ID, img, 25, 25).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    img.release();
    console.log(Tag, `out func ${fun_name}`);
}

function test_setCustomCursor_sync() {
    let fun_name = 'test_setCustomCursor_sync';
    console.log(Tag, `into func ${fun_name}`);
    let width: int = 64;
    let height: int = 64;
    const buffer = new ArrayBuffer(width * height * 4); // RGBA_8888
    const pixelView = new Uint8Array(buffer);
    for (let i = 0; i < pixelView.length; i += 4) {
        pixelView[i] = (i % 12 < 4) ? 0xFF : 0x00;
        pixelView[i+1] = (i % 12 >= 4 && i % 12 < 8) ? 0xFF : 0x00;
        pixelView[i+2] = (i % 12 >= 8) ? 0xFF : 0x00;
        pixelView[i+3] = 0xFF;
    }
    const opts: image.InitializationOptions = {
        editable: true,
        pixelFormat: image.PixelMapFormat.RGBA_8888,
        size: { width: width, height: height }
    };
    let img = image.createPixelMapSync(buffer, opts);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setCustomCursorSync(WINDOW_ID, img, 25, 25);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    img.release();
    console.log(Tag, `out func ${fun_name}`);
}

function test_setCustomCursor_CursorConfig_promise() {
    let fun_name = 'test_setCustomCursor_CursorConfig_promise';
    console.log(Tag, `into func ${fun_name}`);
    let width: int = 64;
    let height: int = 64;
    const buffer = new ArrayBuffer(width * height * 4);
    const pixelView = new Uint8Array(buffer);
    for (let i = 0; i < pixelView.length; i += 4) {
        pixelView[i] =  0x00;
        pixelView[i+1] = 0xFF;
        pixelView[i+2] = 0xFF;
        pixelView[i+3] = 0xFF;
    }
    const opts: image.InitializationOptions = {
        editable: true,
        pixelFormat: image.PixelMapFormat.RGBA_8888,
        size: { width: width, height: height }
    };
    let cursor: pointer.CustomCursor =  {pixelMap: image.createPixelMapSync(buffer, opts), focusX: 25, focusY: 25};
    let config :pointer.CursorConfig =  {followSystem: false};
    try {
        pointer.setCustomCursor(WINDOW_ID, cursor, config);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    cursor.pixelMap.release();
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadDoubleTapAndDragState_callback() {
    let fun_name = 'test_setTouchpadDoubleTapAndDragState_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setTouchpadDoubleTapAndDragState(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setTouchpadDoubleTapAndDragState_promise() {
    let fun_name = 'test_setTouchpadDoubleTapAndDragState_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setTouchpadDoubleTapAndDragState(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadDoubleTapAndDragState_callback() {
    let fun_name = 'test_getTouchpadDoubleTapAndDragState_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getTouchpadDoubleTapAndDragState(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getTouchpadDoubleTapAndDragState_promise() {
    let fun_name = 'test_getTouchpadDoubleTapAndDragState_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getTouchpadDoubleTapAndDragState().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    console.log(Tag + ` out main`);
}