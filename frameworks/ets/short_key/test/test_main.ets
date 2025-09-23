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


import shortKey  from '@ohos.multimodalInput.shortKey';
import { AsyncCallback, BusinessError } from '@ohos.base';

const Tag:String = "shortKey"
const WAIT_OPER: long = 2000;

function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}


function test_setKeyDownDuration_callabck() {
    let fun_name = 'test_setKeyDownDuration_callabck';
    console.log(Tag, `into func ${fun_name} `);
    try {
        let fnCallBack = (err: BusinessError<void>|null, data: undefined ) => {
            console.log(Tag,  `${fun_name} AsyncCallback err:{err}`);
        };
         shortKey.setKeyDownDuration("screenshot", 500, fnCallBack);
         wait(WAIT_OPER);
    } catch (err) {
        console.log(Tag, `catch error:`, err);
    }
    console.log(Tag, `out func ${fun_name} `);
}

function test_setKeyDownDuration_promise() {
    let fun_name = 'test_setKeyDownDuration_promise';
    console.log(Tag, `into func ${fun_name} `);
    try {
        let fnCallBack = () => {
            console.log(Tag,  `${fun_name} callback`);
        };
        shortKey.setKeyDownDuration("screenshot", 500).then(fnCallBack);
        wait(WAIT_OPER);
    } catch (err) {
        console.log(Tag, `catch error:`, err);
    }
    console.log(Tag, `out func ${fun_name} `);
}

function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    console.log(Tag + ` out main`);
}