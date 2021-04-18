/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/eligible_ads/ad_notifications/seen_advertisers.h"

#include <cstdint>
#include <map>
#include <string>

#include "bat/ads/internal/client/client.h"
#include "bat/ads/internal/eligible_ads/round_robin_advertisers.h"
#include "bat/ads/internal/logging.h"

namespace ads {
namespace ad_notifications {

CreativeAdNotificationList FilterSeenAdvertisersAndRoundRobinIfNeeded(
    const CreativeAdNotificationList& ads) {
  const std::map<std::string, uint64_t> seen_advertisers =
      Client::Get()->GetSeenAdvertisers();

  CreativeAdNotificationList eligible_ads =
      FilterSeenAdvertisers(ads, seen_advertisers);

  if (eligible_ads.empty()) {
    BLOG(1, "All advertisers have been shown, so round robin");
    Client::Get()->ResetSeenAdvertisers(ads);
    eligible_ads = ads;
  }

  return eligible_ads;
}

}  // namespace ad_notifications
}  // namespace ads
