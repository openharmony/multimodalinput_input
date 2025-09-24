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

import inputDevice from '@ohos.multimodalInput.inputDevice';
import { KeyCode } from '@ohos.multimodalInput.keyCode';
import { AsyncCallback, BusinessError } from '@ohos.base';

const Tag:String = "inputDevice"
const  OVERTIME_QUERY: long = 3000;
const   WAIT_OPER: long = 60000;
function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}

function test_on_off_change() {
    let fun_name: string = 'test_on_off_change';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: inputDevice.DeviceListener) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.onChange(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        inputDevice.offChange(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on ${fun_name}`);
}

function test_getDeviceList_promise() {
    let fun_name: string = 'test_getDeviceList_promise';
    console.log(Tag, `into func ${fun_name}`);
    try {
         inputDevice.getDeviceList().then((data: Array<int>):void => {
            console.log(Tag, `${fun_name} callback :${JSON.stringify(data)}`);
        });
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getDeviceList_callback() {
    let fun_name: string = 'test_getDeviceList_callback';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack: AsyncCallback<Array<int>> = (err: BusinessError<void>|null, info: Array<Int>|undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err} info:${JSON.stringify(info)}`);
        };
        inputDevice.getDeviceList(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getDeviceInfo_callback() {
    let deviceId: int = 0;
    let fun_name: string = `test_getDeviceInfo_callback ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack: AsyncCallback<inputDevice.InputDeviceData> = (err: BusinessError<void>|null, info: inputDevice.InputDeviceData|undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err} info:${JSON.stringify(info)}`);
        };
        inputDevice.getDeviceInfo(deviceId, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `${fun_name} end`);
}

function test_getDeviceInfo_Promise() {
    let deviceId: int = 0;
    let fun_name: string = `test_getDeviceInfo_Promise ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: inputDevice.InputDeviceData) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.getDeviceInfo(deviceId).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getDeviceInfo_sync() {
    let deviceId: int = 0;
    let fun_name: string = `test_getDeviceInfo_sync ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let info = inputDevice.getDeviceInfoSync(deviceId);
        console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_supportKeys_promise() {
    let deviceId: int = 0;
    let fun_name: string = `test_supportKeys_promise ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let keys: Array<KeyCode> = [KeyCode.KEYCODE_VOLUME_UP, KeyCode.KEYCODE_POWER];
        let fnCallBack = (info: Array<boolean>) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.supportKeys(deviceId, keys).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_supportKeys_callback() {
    let deviceId: int = 0;
    let fun_name: string = `test_supportKeys_callback ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let keys: Array<KeyCode> = [KeyCode.KEYCODE_CAMERA];
        let fnCallBack = (err: BusinessError<void>|null, info: Array<boolean> |undefined ) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err}, info:${JSON.stringify(info)}`);
        };
        inputDevice.supportKeys(deviceId, keys, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_supportKeys_sync() {
    let deviceId: int = 0;
    let fun_name: string = `test_supportKeys_sync ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let keys: Array<KeyCode> = [KeyCode.KEYCODE_A];
        let ret = inputDevice.supportKeysSync(deviceId, keys);
         console.log(Tag,  `${fun_name} on success ${JSON.stringify(ret)}`);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardType_promise() {
    let deviceId: int = 0;
    let fun_name: string = `test_getKeyboardType_promise ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: inputDevice.KeyboardType) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.getKeyboardType(deviceId).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardType_callback() {
    let deviceId: int = 0;
    let fun_name: string = `test_getKeyboardType_callback ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info:inputDevice.KeyboardType|undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err}, info:${info}`);
        };
        inputDevice.getKeyboardType(deviceId, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardType_sync() {
    let deviceId: int = 0;
    let fun_name: string = `test_getKeyboardType_sync ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let ret = inputDevice.getKeyboardTypeSync(deviceId);
         console.log(Tag,  `${fun_name} on success ${JSON.stringify(ret)}`);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

// The default value is 500ms, and the adjustment range is [300ms, 1000ms].
function test_setKeyboardRepeatDelay_promise() {
    let delay: int = 350;
    let fun_name: string = `test_setKeyboardRepeatDelay_promise ${delay}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDevice.setKeyboardRepeatDelay(delay).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_setKeyboardRepeatDelay_callback() {
    let delay: int = 350;
    let fun_name: string = `test_setKeyboardRepeatDelay_callback ${delay}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack =  (err: BusinessError<void>|null, data: undefined)  => {
            console.log(Tag,  `Monitor ${fun_name} on success err:${err}`);
        };
        inputDevice.setKeyboardRepeatDelay(delay, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardRepeatDelay_promise() {
    let fun_name: string = `test_getKeyboardRepeatDelay_promise}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} info:${info}`);
        };
        inputDevice.getKeyboardRepeatDelay().then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardRepeatDelay_callback() {
    let fun_name: string = `test_getKeyboardRepeatDelay_callback`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err}, info:${info}`);
        };
        inputDevice.getKeyboardRepeatDelay(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardRepeatRate_promise() {
    let fun_name: string = `test_getKeyboardRepeatRate_promise`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: int) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.getKeyboardRepeatRate().then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getKeyboardRepeatRate_callback() {
    let fun_name: string = `test_getKeyboardRepeatRate_callback`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: int|undefined ) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} err:${err}, info:${JSON.stringify(info)}`);
        };
        inputDevice.getKeyboardRepeatRate(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}
// Keyboard key repetition rate, default value 50ms/time, adjustable range [36ms/time, 100ms/time].
function test_setKeyboardRepeatRate_promise() {
    let rate: int = 50;
    let fun_name: string = `test_setKeyboardRepeatRate_promise ${rate}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDevice.setKeyboardRepeatRate(rate).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_setKeyboardRepeatRate_callback() {
    let rate: int = 45;
    let fun_name: string = `test_setKeyboardRepeatRate_callback ${rate}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (err: BusinessError<void>|null, info: undefined) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDevice.setKeyboardRepeatRate(rate, fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_getIntervalSinceLastInput_promise() {
    let fun_name: string = `test_getIntervalSinceLastInput_promise`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = (info: long) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.getIntervalSinceLastInput().then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_setInputDeviceEnabled_promise() {
    let deviceId: int = 1;
    let fun_name: string = `test_setInputDeviceEnabled_promise ${deviceId}`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let fnCallBack = () => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDevice.setInputDeviceEnabled(deviceId, true).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_setFunctionKeyEnabled_promise() {
    let fun_name: string = `test_setFunctionKeyEnabled_promise`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let funcKey = inputDevice.FunctionKey.CAPS_LOCK;
        let fnCallBack = () => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
        };
        inputDevice.setFunctionKeyEnabled(funcKey, true).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function test_isFunctionKeyEnabled_promise() {
    let fun_name: string = `test_isFunctionKeyEnabled_promise`;
    console.log(Tag, `into func ${fun_name}`);
    try {
        let funcKey = inputDevice.FunctionKey.CAPS_LOCK;
        let fnCallBack = (info: boolean) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputDevice.isFunctionKeyEnabled(funcKey).then(fnCallBack);
        wait(OVERTIME_QUERY);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
     console.log(Tag, `${fun_name} end`);
}

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    console.log(Tag + ` out main`);
}