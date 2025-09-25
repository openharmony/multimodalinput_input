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

import inputEventClient from '@ohos.multimodalInput.inputEventClient';
import * as touchEvent  from '@ohos.multimodalInput.touchEvent';
import * as mouseEvent from '@ohos.multimodalInput.mouseEvent';

const Tag:String = "inputEventClient"
const OVERTIME_QUERY: long = 3000;

function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}


function test_injectKeyEvent() {
    let fun_name = 'test_injectKeyEvent';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let backKeyUp: inputEventClient.KeyEventData = {
            keyEvent : {
                isPressed: false,
                keyCode: 2,
                keyDownDuration: 0,
                isIntercepted: false
           }
        };
        inputEventClient.injectKeyEvent(backKeyUp);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_injectEvent() {
    let fun_name = 'test_injectEvent';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let backKeyUp: inputEventClient.KeyEvent = {
            isPressed: false,
            keyCode: 2,
            keyDownDuration: 0,
            isIntercepted: false
        };
        let keyEventInfo: inputEventClient.KeyEventInfo = {
            KeyEvent: backKeyUp
        }
        inputEventClient.injectEvent(keyEventInfo);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_injectMouseEvent() {
    let fun_name = 'test_injectMouseEvent';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let mouseButtonUp: inputEventClient.MouseEventData = {
            mouseEvent:  {
                id: 0,
                deviceId: 1,
                actionTime: 2,
                screenId: 1,
                windowId: 0,
                action: mouseEvent.Action.BUTTON_UP,
                screenX: 100,
                screenY: 200,
                windowX: 100,
                windowY: 200,
                rawDeltaX: 200,
                rawDeltaY: 200,
                button: mouseEvent.Button.RIGHT,
                pressedButtons: [],
                axes: [],
                pressedKeys: [],
                ctrlKey: false,
                altKey: false,
                shiftKey: false,
                logoKey: false,
                fnKey: false,
                capsLock: false,
                numLock: false,
                scrollLock: false,
                toolType: mouseEvent.ToolType.MOUSE
         }
        };
        inputEventClient.injectMouseEvent(mouseButtonUp);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_injectTouchEvent() {
    let fun_name = 'test_injectTouchEvent';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let touchEventUp: inputEventClient.TouchEventData = {
            touchEvent: {
                action: touchEvent.Action.DOWN,
                sourceType: touchEvent.SourceType.TOUCH_SCREEN,
                touch: {
                    id: 1,
                    pressedTime: 1,
                    screenX: 0,
                    screenY: 0,
                    windowX: 0,
                    windowY: 0,
                    pressure: 0,
                    width: 0,
                    height: 0,
                    tiltX: 0,
                    tiltY: 0,
                    toolX: 0,
                    toolY: 0,
                    toolWidth: 0,
                    toolHeight: 0,
                    rawX: 0,
                    rawY: 0,
                    toolType: touchEvent.ToolType.FINGER
                    },
                touches: [],
                id: 0,
                deviceId: 0,
                actionTime: 0,
                screenId: 0,
                windowId: 0
        }
        }
        inputEventClient.injectTouchEvent(touchEventUp);
    } catch (error) {
        console.error(Tag, `${fun_name} failed, error: ${error}`);
    }
    console.log(Tag, `out func ${fun_name}`);
}

function test_permitInjection() {
    let fun_name = 'test_permitInjection';
    console.log(Tag, `into func ${fun_name}`);
    try {
        let result: boolean = true;
        inputEventClient.permitInjection(result);
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