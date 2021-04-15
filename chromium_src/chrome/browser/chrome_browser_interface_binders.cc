/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#define PopulateChromeWebUIFrameBinders \
  PopulateChromeWebUIFrameBinders_ChromiumImpl
#include "../../../../chrome/browser/chrome_browser_interface_binders.cc"
#undef PopulateChromeWebUIFrameBinders

#include "brave/browser/ui/webui/brave_wallet_panel_ui.h"
#include "brave/browser/ui/webui/wallet_panel/wallet_panel.mojom.h"

namespace chrome {
namespace internal {

void PopulateChromeWebUIFrameBinders(
    mojo::BinderMapWithContext<content::RenderFrameHost*>* map) {
  PopulateChromeWebUIFrameBinders_ChromiumImpl(map);
  RegisterWebUIControllerInterfaceBinder<
      wallet_panel::mojom::PageHandlerFactory, BraveWalletPanelUI>(map);
}

}  // namespace internal
}  // namespace chrome
