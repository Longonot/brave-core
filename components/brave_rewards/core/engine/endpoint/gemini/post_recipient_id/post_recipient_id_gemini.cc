/* Copyright (c) 2021 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "brave/components/brave_rewards/core/engine/endpoint/gemini/post_recipient_id/post_recipient_id_gemini.h"

#include <optional>
#include <utility>

#include "base/base64.h"
#include "base/check.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/uuid.h"
#include "brave/components/brave_rewards/core/engine/rewards_engine.h"
#include "brave/components/brave_rewards/core/engine/util/environment_config.h"
#include "brave/components/brave_rewards/core/engine/util/url_loader.h"
#include "net/http/http_status_code.h"

namespace brave_rewards::internal::endpoint::gemini {

PostRecipientId::PostRecipientId(RewardsEngine& engine) : engine_(engine) {}

PostRecipientId::~PostRecipientId() = default;

std::string PostRecipientId::GetUrl() {
  return engine_->Get<EnvironmentConfig>()
      .gemini_api_url()
      .Resolve("/v1/payments/recipientIds")
      .spec();
}

mojom::Result PostRecipientId::ParseBody(const std::string& body,
                                         std::string* recipient_id) {
  DCHECK(recipient_id);

  std::optional<base::Value::Dict> value = base::JSONReader::ReadDict(body);
  if (!value) {
    engine_->LogError(FROM_HERE) << "Invalid JSON";
    return mojom::Result::FAILED;
  }

  const base::Value::Dict& dict = *value;
  const auto* result = dict.FindString("result");
  if (!result || *result != "OK") {
    engine_->LogError(FROM_HERE) << "Failed creating recipient_id";
    return mojom::Result::FAILED;
  }

  const auto* id = dict.FindString("recipient_id");
  if (!id) {
    engine_->LogError(FROM_HERE) << "Response missing a recipient_id";
    return mojom::Result::FAILED;
  }

  *recipient_id = *id;
  return mojom::Result::OK;
}

std::string PostRecipientId::GeneratePayload() {
  base::Value::Dict payload;
  payload.Set("label", kRecipientLabel);

  std::string json;
  base::JSONWriter::Write(payload, &json);
  return base::Base64Encode(json);
}

void PostRecipientId::Request(const std::string& token,
                              PostRecipientIdCallback callback) {
  auto request = mojom::UrlRequest::New();
  request->url = GetUrl();
  request->method = mojom::UrlMethod::POST;
  request->headers = {"Authorization: Bearer " + token,
                      "X-GEMINI-PAYLOAD: " + GeneratePayload()};

  engine_->Get<URLLoader>().Load(
      std::move(request), URLLoader::LogLevel::kDetailed,
      base::BindOnce(&PostRecipientId::OnRequest, base::Unretained(this),
                     std::move(callback)));
}

void PostRecipientId::OnRequest(PostRecipientIdCallback callback,
                                mojom::UrlResponsePtr response) {
  DCHECK(response);

  auto header = response->headers.find("www-authenticate");
  if (header != response->headers.end()) {
    std::string auth_header = header->second;
    if (auth_header.find("unverified_account") != std::string::npos) {
      return std::move(callback).Run(mojom::Result::NOT_FOUND, "");
    }
  }

  switch (response->status_code) {
    case net::HTTP_OK:
      break;
    case net::HTTP_NOT_FOUND:
      std::move(callback).Run(mojom::Result::NOT_FOUND, "");
      return;
    case net::HTTP_UNAUTHORIZED:
    case net::HTTP_FORBIDDEN:
      std::move(callback).Run(mojom::Result::EXPIRED_TOKEN, "");
      return;
    default:
      std::move(callback).Run(mojom::Result::FAILED, "");
      return;
  }

  std::string recipient_id;
  mojom::Result result = ParseBody(response->body, &recipient_id);
  std::move(callback).Run(result, std::move(recipient_id));
}

}  // namespace brave_rewards::internal::endpoint::gemini
