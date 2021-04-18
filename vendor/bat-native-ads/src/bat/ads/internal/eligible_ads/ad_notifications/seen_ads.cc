/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/eligible_ads/ad_notifications/seen_ads.h"

#include <cstdint>
#include <map>
#include <string>

#include "bat/ads/internal/client/client.h"
#include "bat/ads/internal/eligible_ads/round_robin_ads.h"
#include "bat/ads/internal/logging.h"

namespace ads {
namespace ad_notifications {

CreativeAdNotificationList FilterSeenAdsAndRoundRobinIfNeeded(
    const CreativeAdNotificationList& ads) {
  // TODO(tmancey): DI reader/writer
  const std::map<std::string, uint64_t> seen_ads =
      Client::Get()->GetSeenAdNotifications();

  CreativeAdNotificationList eligible_ads = FilterSeenAds(ads, seen_ads);

  if (eligible_ads.empty()) {
    BLOG(1, "All ads have been shown, so round robin");
    Client::Get()->ResetSeenAdNotifications(ads);
    eligible_ads = ads;
  }

  return eligible_ads;
}

}  // namespace ad_notifications
}  // namespace ads
