// Copyright (c) 2021 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// you can obtain one at http://mozilla.org/MPL/2.0/.

import 'chrome://resources/cr_elements/cr_icon_button/cr_icon_button.m.js';
import 'chrome://resources/cr_elements/hidden_style_css.m.js';
import 'chrome://resources/cr_elements/shared_vars_css.m.js';
import 'chrome://resources/cr_elements/mwb_shared_style.js';
import 'chrome://resources/cr_elements/mwb_shared_vars.js';
import 'chrome://resources/polymer/v3_0/iron-selector/iron-selector.js';

import {assertNotReached} from 'chrome://resources/js/assert.m.js';
import {loadTimeData} from 'chrome://resources/js/load_time_data.m.js';
import {html, PolymerElement} from 'chrome://resources/polymer/v3_0/polymer/polymer_bundled.min.js';
import {listenOnce} from 'chrome://resources/js/util.m.js';

import {WalletPanelApiProxy, WalletPanelApiProxyImpl} from './wallet_panel_api_proxy.js';

import './strings.js';

/** @type {!Set<string>} */
const navigationKeys = new Set(['ArrowDown', 'ArrowUp']);

export class WalletPanelAppElement extends PolymerElement {
  static get is() {
    return 'wallet-panel-app';
  }

  static get template() {
    return html`{__html_template__}`;
  }

  static get properties() {
    return {
    };
  }

  constructor() {
    super();
    /** @private {!WalletPanelApiProxy} */
    this.apiProxy_ = WalletPanelApiProxyImpl.getInstance();

    /** @private {!Function} */
    this.visibilityChangedListener_ = () => {
      if (document.visibilityState === 'visible') {
        this.checkShowUI();
      }
    };
  }

  /** @override */
  connectedCallback() {
    super.connectedCallback();
    document.addEventListener(
        'visibilitychange', this.visibilityChangedListener_);

    if (document.visibilityState === 'visible') {
      this.checkShowUI();
    }
  }

  /** @override */
  disconnectedCallback() {
    super.disconnectedCallback();
    document.removeEventListener(
        'visibilitychange', this.visibilityChangedListener_);
  }

  checkShowUI() {
    setTimeout(() => this.apiProxy_.showUI(), 0);
  }
}

customElements.define(WalletPanelAppElement.is, WalletPanelAppElement);
