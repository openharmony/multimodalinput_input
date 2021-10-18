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
import router from '@system.router';
import inputEventClient from '@ohos.multimodalInput.inputEventClient';

const REGISTERED_EVENT_SUCCESS = 1;
const REGISTERED_EVENT_EXIST = 2;
const REGISTERED_EVENT_INVALID_PARAMETER = -1;
const REGISTERED_EVENT_NOT_EXIST = 3;

const API_LIST_NUM = 60;

export default {
  data: {
    windowId: 0,
    apiTitle: '注册事件',
    apiList: [],
    eventHandle: null,
    eventInfo: {
      '0': 'showMenu',
      '1': 'send' ,
      '2': 'copy' ,
      '3': 'paste' ,
      '4': 'cut' ,
      '5': 'undo' ,
      '6': 'refresh' ,
      '8': 'cancel' ,
      '9': 'enter' ,
      '10': 'previous' ,
      '11': 'next' ,
      '12': 'back' ,
      '13': 'print' ,
      '14': 'answer' ,
      '15': 'refuse' ,
      '16': 'hangup' ,
      '17': 'telephoneControl' ,
      '18': 'play' ,
      '19': 'pause' ,
      '20': 'mediaControl' ,
   },
    dividerInfo: '-------------------------------------------------------------',
  },

  // 时间戳转换
  formatTime(time) {
    let timer = Math.floor(time / 1000);  // 传递过来的时间戳都是微妙
    let date = new Date(timer);
    let Y = date.getFullYear();
    let M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1);
    let D = (date.getDate() < 10 ? '0' + date.getDate() : date.getDate());
    let h = (date.getHours() < 10 ? '0' + date.getHours() : date.getHours());
    let m = (date.getMinutes() < 10 ? '0' + date.getMinutes() : date.getMinutes());
    let s = (date.getSeconds() < 10 ? '0' + date.getSeconds() : date.getSeconds());
    return `${Y}-${M}-${D} ${h}:${m}:${s}`;
  },

  getEventType(type) {
    let value = 'undefine type';
    if (this.eventInfo.hasOwnProperty(type)) {
      value = this.eventInfo[type];
    }
    return value;
  },

  addApiDivider() {
    if (this.apiList.length == 0) {
       return;
    }
    this.apiList.push(this.dividerInfo);
  },

  addApiList(itemName, itemData) {
    console.log(`inputEventClient::eventHandle: ${itemName}:${itemData}`)
    if (this.apiList.length > API_LIST_NUM) {
      this.apiList = [];
    }
    let itemInfo = `${itemName}: ${itemData}`;
    this.apiList.push(itemInfo);
  },

  eventHandle(event) {
    this.addApiDivider();
    this.addApiList('type', this.getEventType(event.type));
    this.addApiList('uuid', event.uuid);
    this.addApiList('sourceDevice', event.sourceDevice);
    this.addApiList('inputDeviceId', event.inputDeviceId);
    this.addApiList('occurredTime', this.formatTime(event.occurredTime));
  },

  onEventReg() {
    this.addApiDivider();
    for(let type in this.eventInfo) {
      let name = this.eventInfo[type];
      console.log(`inputEventClient::onEventReg: name=${name}`)
      let ret = inputEventClient.on(this.windowId, name, this.eventHandle);
      let braces="{}"
      let info =`on(${this.windowId}, '${name}', (event)=>${braces})`;

      if(ret == REGISTERED_EVENT_SUCCESS){
        this.addApiList(info,'订阅成功('+ret+')');
      } else if (ret == REGISTERED_EVENT_EXIST) {
        this.addApiList(info, '订阅已存在('+ret+')');
      } else if (ret == REGISTERED_EVENT_INVALID_PARAMETER) {
        this.addApiList(info, '订阅参数错误('+ret+')');
      } else {
        this.addApiList(info, '订阅参失败('+ret+')');
      }
    }
  },

  onEventUnreg() {
    this.addApiDivider();
    for(let type in this.eventInfo) {
      let name = this.eventInfo[type];
      console.log(`inputEventClient::onEventUnreg: name=${name}`)
      let ret = inputEventClient.off(this.windowId, name, this.eventHandle);
      let braces="{}"
      let info =`off(${this.windowId}, '${name}', (event)=>${braces})`;

      if(ret == REGISTERED_EVENT_SUCCESS){
        this.addApiList(info,'去订阅成功('+ret+')');
      } else if (ret == REGISTERED_EVENT_NOT_EXIST) {
        this.addApiList(info, '去订阅不存在('+ret+')');
      } else if (ret == REGISTERED_EVENT_INVALID_PARAMETER) {
        this.addApiList(info, '去订阅参数错误('+ret+')');
      } else {
        this.addApiList(info, '去订阅失败('+ret+')');
      }
    }
  },

  onClickGoIndex() {
    router.push({
      uri: 'pages/index/index',
    });
  },

  onClearData() {
    this.apiList = [];
  },

  onShow() {
    this.windowId = Math.floor(Math.random()*100)
    this.apiList = [];
  },

  onHide() {
    this.onEventUnreg();
  },
}

