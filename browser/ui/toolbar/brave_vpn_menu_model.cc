/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "brave/browser/ui/toolbar/brave_vpn_menu_model.h"

#include "base/feature_list.h"
#include "brave/app/brave_command_ids.h"
#include "brave/components/brave_vpn/common/features.h"
#include "brave/components/brave_vpn/common/pref_names.h"
#include "brave/grit/brave_generated_resources.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_commands.h"
#include "components/prefs/pref_service.h"

#if BUILDFLAG(IS_WIN)
#include "brave/components/brave_vpn/common/wireguard/win/storage_utils.h"
#endif

BraveVPNMenuModel::BraveVPNMenuModel(Browser* browser,
                                     PrefService* profile_prefs)
    : SimpleMenuModel(nullptr),
      profile_prefs_(profile_prefs),
      browser_(browser) {
  set_delegate(this);
  Build();
}

BraveVPNMenuModel::~BraveVPNMenuModel() = default;

void BraveVPNMenuModel::Build() {
  AddItemWithStringId(IDC_TOGGLE_BRAVE_VPN, IDS_BRAVE_VPN_MENU);
  AddSeparator(ui::NORMAL_SEPARATOR);
  AddItemWithStringId(IDC_TOGGLE_BRAVE_VPN_TOOLBAR_BUTTON,
                      IsBraveVPNButtonVisible()
                          ? IDS_BRAVE_VPN_HIDE_VPN_BUTTON_MENU_ITEM
                          : IDS_BRAVE_VPN_SHOW_VPN_BUTTON_MENU_ITEM);
#if BUILDFLAG(IS_WIN)
  if (base::FeatureList::IsEnabled(
          brave_vpn::features::kBraveVPNUseWireguardService)) {
    AddItemWithStringId(IDC_TOGGLE_BRAVE_VPN_TRAY_ICON,
                        IsTrayIconEnabled()
                            ? IDS_BRAVE_VPN_HIDE_VPN_TRAY_ICON_MENU_ITEM
                            : IDS_BRAVE_VPN_SHOW_VPN_TRAY_ICON_MENU_ITEM);
  }
#endif  // BUILDFLAG(IS_WIN)
  AddItemWithStringId(IDC_SEND_BRAVE_VPN_FEEDBACK,
                      IDS_BRAVE_VPN_SHOW_FEEDBACK_MENU_ITEM);
  AddItemWithStringId(IDC_ABOUT_BRAVE_VPN, IDS_BRAVE_VPN_ABOUT_VPN_MENU_ITEM);
  AddItemWithStringId(IDC_MANAGE_BRAVE_VPN_PLAN,
                      IDS_BRAVE_VPN_MANAGE_MY_PLAN_MENU_ITEM);
}

void BraveVPNMenuModel::ExecuteCommand(int command_id, int event_flags) {
  chrome::ExecuteCommand(browser_, command_id);
}

bool BraveVPNMenuModel::IsBraveVPNButtonVisible() const {
  return profile_prefs_->GetBoolean(brave_vpn::prefs::kBraveVPNShowButton);
}

#if BUILDFLAG(IS_WIN)
bool BraveVPNMenuModel::IsTrayIconEnabled() const {
  if (tray_icon_enabled_for_testing_.has_value()) {
    return tray_icon_enabled_for_testing_.value();
  }

  return brave_vpn::wireguard::IsVPNTrayIconEnabled();
}
#endif
