/* Copyright (c) 2019 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "brave/browser/ui/views/toolbar/bookmark_button.h"

#include <utility>

#include "chrome/app/chrome_command_ids.h"
#include "chrome/browser/ui/color/chrome_color_id.h"
#include "chrome/browser/ui/view_ids.h"
#include "chrome/browser/ui/views/toolbar/toolbar_view.h"
#include "chrome/grit/generated_resources.h"
#include "components/omnibox/browser/vector_icons.h"
#include "components/strings/grit/components_strings.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/metadata/metadata_impl_macros.h"
#include "ui/gfx/paint_vector_icon.h"

BraveBookmarkButton::BraveBookmarkButton(PressedCallback callback)
    : ToolbarButton(std::move(callback)) {
  SetID(VIEW_ID_STAR_BUTTON);
  set_tag(IDC_BOOKMARK_THIS_TAB);
}

BraveBookmarkButton::~BraveBookmarkButton() = default;

void BraveBookmarkButton::SetToggled(bool on) {
  active_ = on;
  UpdateImageAndText();
}

void BraveBookmarkButton::UpdateImageAndText() {
  const ui::ColorProvider* color_provider = GetColorProvider();
  SkColor icon_color = color_provider->GetColor(kColorToolbarButtonIcon);
  const gfx::VectorIcon& icon =
      active_ ? omnibox::kStarActiveIcon : omnibox::kStarIcon;
  SetImageModel(
      views::Button::STATE_NORMAL,
      ui::ImageModel::FromVectorIcon(icon, icon_color, GetIconSize()));

  int tooltip_id = active_ ? IDS_TOOLTIP_STARRED : IDS_TOOLTIP_STAR;
  SetTooltipText(l10n_util::GetStringUTF16(tooltip_id));
}

BEGIN_METADATA(BraveBookmarkButton)
END_METADATA
