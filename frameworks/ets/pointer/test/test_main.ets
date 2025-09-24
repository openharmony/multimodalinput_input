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

function test_setPointerSpeed_callback() {
    let fun_name = 'test_setPointerSpeed_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setPointerSpeed(2, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerSpeed_promise() {
    let fun_name = 'test_setPointerSpeed_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setPointerSpeed(10).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerSpeed_sync() {
    let fun_name = 'test_setPointerSpeed_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        pointer.setPointerSpeedSync(7);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSpeed_callback() {
    let fun_name = 'test_getPointerSpeed_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getPointerSpeed(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSpeed_promise() {
    let fun_name = 'test_getPointerSpeed_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getPointerSpeed().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSpeed_sync() {
    let fun_name = 'test_getPointerSpeed_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = pointer.getPointerSpeedSync();
        console.log(Tag, `${fun_name} ret info:${info}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerStyle_callback() {
    let fun_name = 'test_setPointerStyle_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setPointerStyle(WINDOW_ID,  pointer.PointerStyle.CROSS);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerStyle_promise() {
    let fun_name = 'test_setPointerStyle_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setPointerStyle(WINDOW_ID, pointer.PointerStyle.CROSS).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerStyle_sync() {
    let fun_name = 'test_setPointerStyle_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        pointer.setPointerStyleSync(WINDOW_ID, pointer.PointerStyle.CROSS);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerStyle_callback() {
    let fun_name = 'test_getPointerStyle_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: pointer.PointerStyle|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getPointerStyle(WINDOW_ID, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerStyle_promise() {
    let fun_name = 'test_getPointerStyle_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: pointer.PointerStyle) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getPointerStyle(WINDOW_ID).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerStyle_sync() {
    let fun_name = 'test_getPointerStyle_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = pointer.getPointerStyleSync(WINDOW_ID);
        console.log(Tag, `${fun_name} ret info:${info}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerVisible_callback() {
    let fun_name = 'test_setPointerVisible_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setPointerVisible(false);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerVisible_promise() {
    let fun_name = 'test_setPointerVisible_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setPointerVisible(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerVisible_sync() {
    let fun_name = 'test_setPointerVisible_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        pointer.setPointerVisibleSync(true);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_isPointerVisible_callback() {
    let fun_name = 'test_isPointerVisible_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.isPointerVisible(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_isPointerVisible_promise() {
    let fun_name = 'test_isPointerVisible_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.isPointerVisible().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_isPointerVisible_sync() {
    let fun_name = 'test_getPointerVisible_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = pointer.isPointerVisibleSync();
        console.log(Tag, `${fun_name} ret info:${info}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerColor_callback() {
    let fun_name = 'test_setPointerColor_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setPointerColor(0xF6C800);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerColor_promise() {
    let fun_name = 'test_setPointerColor_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setPointerColor(0x00FF00).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerColor_sync() {
    let fun_name = 'test_setPointerColor_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        pointer.setPointerColorSync(0x0000FF);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerColor_callback() {
    let fun_name = 'test_getPointerColor_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getPointerColor(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerColor_promise() {
    let fun_name = 'test_getPointerColor_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getPointerColor().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerColor_sync() {
    let fun_name = 'test_getPointerColor_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = pointer.getPointerColorSync();
        console.log(Tag, `${fun_name} ret info:${info}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerSize_callback() {
    let fun_name = 'test_setPointerSize_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setPointerSize(2);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerSize_promise() {
    let fun_name = 'test_setPointerSize_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setPointerSize(3).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setPointerSize_sync() {
    let fun_name = 'test_setPointerSize_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        pointer.setPointerSizeSync(1);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSize_callback() {
    let fun_name = 'test_getPointerSize_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getPointerSize(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSize_promise() {
    let fun_name = 'test_getPointerSize_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getPointerSize().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getPointerSize_sync() {
    let fun_name = 'test_getPointerSize_sync';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = pointer.getPointerSizeSync();
        console.log(Tag, `${fun_name} ret info:${info}`);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setMousePrimaryButton_callback() {
    let fun_name = 'test_setMousePrimaryButton_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setMousePrimaryButton(pointer.PrimaryButton.RIGHT, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setMousePrimaryButton_promise() {
    let fun_name = 'test_setMousePrimaryButton_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setMousePrimaryButton(pointer.PrimaryButton.RIGHT).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getMousePrimaryButton_callback() {
    let fun_name = 'test_getMousePrimaryButton_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: pointer.PrimaryButton|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getMousePrimaryButton(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getMousePrimaryButton_promise() {
    let fun_name = 'test_getMousePrimaryButton_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: pointer.PrimaryButton) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getMousePrimaryButton().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setHoverScrollState_callback() {
    let fun_name = 'test_setHoverScrollState_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setHoverScrollState(true, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setHoverScrollState_promise() {
    let fun_name = 'test_setHoverScrollState_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setHoverScrollState(true).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getHoverScrollState_callback() {
    let fun_name = 'test_getHoverScrollState_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: boolean|undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err},info:${info}`);
        };
        pointer.getHoverScrollState(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_getHoverScrollState_promise() {
    let fun_name = 'test_getHoverScrollState_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: boolean) => {
            console.log(Tag, `func ${fun_name} callback info:${info}`);
        };
        pointer.getHoverScrollState().then(fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setMouseScrollRows_callback() {
    let fun_name = 'test_setMouseScrollRows_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag, `func ${fun_name} callback,err:${err}`);
        };
        pointer.setMouseScrollRows(1, fnCallBack);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_setMouseScrollRows_promise() {
    let fun_name = 'test_setMouseScrollRows_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag, `func ${fun_name} callback`);
        };
        pointer.setMouseScrollRows(20).then(fnCallBack);
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