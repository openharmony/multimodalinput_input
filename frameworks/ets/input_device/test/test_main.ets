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
        inputDevice.on('change', fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(WAIT_OPER);
        console.log(Tag, `${fun_name} end wait`);
        inputDevice.off('change', fnCallBack);
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

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    console.log(Tag + ` out main`);
}