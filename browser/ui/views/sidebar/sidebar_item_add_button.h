/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ITEM_ADD_BUTTON_H_
#define BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ITEM_ADD_BUTTON_H_

#include "base/scoped_observation.h"
#include "brave/browser/ui/views/sidebar/sidebar_button_view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/widget/widget_observer.h"

class BraveBrowser;

class SidebarItemAddButton : public SidebarButtonView,
                             public views::WidgetObserver {
 public:
  explicit SidebarItemAddButton(BraveBrowser* browser);
  ~SidebarItemAddButton() override;

  SidebarItemAddButton(const SidebarItemAddButton&) = delete;
  SidebarItemAddButton& operator=(const SidebarItemAddButton&) = delete;

  // SidebarButtonView overrides:
  void OnMouseEntered(const ui::MouseEvent& event) override;
  void OnGestureEvent(ui::GestureEvent* event) override;

  // views::WidgetObserver overrides:
  void OnWidgetDestroying(views::Widget* widget) override;

 private:
  void ShowBubble();

  BraveBrowser* browser_;
  base::ScopedObservation<views::Widget, views::WidgetObserver> observation_{
      this};
};

#endif  // BRAVE_BROWSER_UI_VIEWS_SIDEBAR_SIDEBAR_ITEM_ADD_BUTTON_H_
