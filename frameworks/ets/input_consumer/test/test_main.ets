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


import inputConsumer from '@ohos.multimodalInput.inputConsumer';
import { KeyCode } from '@ohos.multimodalInput.keyCode';
import { KeyEvent } from '@ohos.multimodalInput.keyEvent';

const Tag:String = "inputConsumer"
const   WAIT_OPER: long = 60000;

function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}


function test_on_off_key() {
    let func_name = `test_on_off_key`;
    console.log(Tag, `into func ${func_name}`);
    let leftAltKey = KeyCode.KEYCODE_ALT_LEFT;
    let tabKey = KeyCode.KEYCODE_TAB;
    let keyOptions: inputConsumer.KeyOptions = {
        preKeys: [ leftAltKey ],
        finalKey: tabKey,
        isFinalKeyDown: true,
        finalKeyDownDuration: 0
    };
    let callback = (info: inputConsumer.KeyOptions) => {
        console.log(Tag, `into ${func_name} callback info: ${info}`);
    }
    try {
        inputConsumer.onKey(keyOptions, callback);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    wait(WAIT_OPER);
    try {
        console.log(Tag + ` inputConsumer.off key beign====>`);
        inputConsumer.offKey(keyOptions, callback);
        console.log(Tag + ` inputConsumer.off key end====>`);
    }catch (error) {
        console.error(Tag, `${func_name} off, error: ${error}`);
    }
    console.log(Tag, `leave func ${func_name}`);
}

function test_setShieldStatus() {
    let func_name = `test_setShieldStatus`;
    console.log(Tag, `into func ${func_name}`);
    try {
        let mode = inputConsumer.ShieldMode.FACTORY_MODE;
        inputConsumer.setShieldStatus(mode, true);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    console.log(Tag, `leave func ${func_name}`);
}

function test_getShieldStatus() {
    let func_name = `test_getShieldStatus`;
    console.log(Tag, `into func ${func_name}`);
    try {
        let mode = inputConsumer.ShieldMode.FACTORY_MODE;
        let info = inputConsumer.getShieldStatus(mode);
        console.log(Tag, `func ${func_name} result:${info}`);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    console.log(Tag, `leave func ${func_name}`);
}

function test_getAllSystemHotkeys() {
    let func_name = `test_getAllSystemHotkeys`;
    console.log(Tag, `into func ${func_name}`);
    try {
        let fnCallBack = ( info: Array<inputConsumer.HotkeyOptions>) => {
            console.log(Tag, `into ${func_name} callback info: ${JSON.stringify(info)}`);
        };
        let info = inputConsumer.getAllSystemHotkeys().then(fnCallBack);
        console.log(Tag, `func ${func_name} result:${info}`);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    console.log(Tag, `leave func ${func_name}`);
}

function test_on_off_hotkeyChange() {
    let func_name = `test_on_off_hotkeyChange`;
    console.log(Tag, `into func ${func_name}`);
    let leftCtrlKey = KeyCode.KEYCODE_CTRL_LEFT;
    let zKey = KeyCode.KEYCODE_Z;
    let hotkeyOptions: inputConsumer.HotkeyOptions = {
        preKeys: [ leftCtrlKey ],
        finalKey: zKey,
        isRepeat: true
    };
    let callback = (info: inputConsumer.HotkeyOptions) => {
        console.log(`${func_name} callback info: ${JSON.stringify(info)}`);
    }
    try {
        inputConsumer.onHotkeyChange(hotkeyOptions, callback);
        wait(WAIT_OPER);
        console.log(Tag + `${func_name} off beign====>`);
        inputConsumer.offHotkeyChange(hotkeyOptions, callback);
        console.log(Tag + ` ${func_name} off end====>`);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    console.log(Tag, `leave func ${func_name}`);
}

function test_on_off_keyPressed() {
    let func_name = `test_on_off_keyPressed`;
    console.log(Tag, `into func ${func_name}`);
    let leftCtrlKey = KeyCode.KEYCODE_CTRL_LEFT;
    let zKey = KeyCode.KEYCODE_Z;
     let options: inputConsumer.KeyPressedConfig = {
        key: KeyCode.KEYCODE_A,
        action: 1,
        isRepeat: false,
    }
    let callback = (event: KeyEvent) => {
        console.log(`${func_name} callback event: ${JSON.stringify(event)}`);
    }
    try {
        inputConsumer.onKeyPressed(options, callback);
        wait(WAIT_OPER);
    } catch (error) {
        console.error(Tag, `${func_name} failed, error: ${error}`);
    }
    console.log(Tag + `${func_name} off beign====>`);
    inputConsumer.offKeyPressed(callback);
    console.log(Tag + ` ${func_name} off end====>`);
    console.log(Tag, `leave func ${func_name}`);
}

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    test_on_off_key();
    console.log(Tag + ` out main`);
}