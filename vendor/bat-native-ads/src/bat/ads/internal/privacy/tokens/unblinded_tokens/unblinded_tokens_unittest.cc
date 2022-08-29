/* Copyright (c) 2020 The Brave Authors. All rights reserved.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "bat/ads/internal/privacy/tokens/unblinded_tokens/unblinded_tokens.h"

#include <string>
#include <vector>

#include "bat/ads/internal/base/unittest/unittest_base.h"
#include "bat/ads/internal/privacy/tokens/unblinded_tokens/unblinded_tokens_unittest_util.h"

// npm run test -- brave_unit_tests --filter=BatAds*

namespace ads {
namespace privacy {

class BatAdsUnblindedTokensTest : public UnitTestBase {
 protected:
  BatAdsUnblindedTokensTest() = default;

  ~BatAdsUnblindedTokensTest() override = default;
};

TEST_F(BatAdsUnblindedTokensTest, GetToken) {
  // Arrange
  SetUnblindedTokens(10);

  // Act
  const UnblindedTokenInfo& unblinded_token = GetUnblindedTokens()->GetToken();

  // Assert
  const std::string expected_unblinded_token_base64 =
      "PLowz2WF2eGD5zfwZjk9p76HXBLDKMq/3EAZHeG/fE2XGQ48jyte+Ve50ZlasOuY"
      "L5mwA8CU2aFMlJrt3DDgC3B1+VD/uyHPfa/+bwYRrpVH5YwNSDEydVx8S4r+BYVY";
  UnblindedTokenInfo expected_unblinded_token =
      CreateUnblindedToken(expected_unblinded_token_base64);

  EXPECT_EQ(expected_unblinded_token, unblinded_token);
}

TEST_F(BatAdsUnblindedTokensTest, GetAllTokens) {
  // Arrange
  SetUnblindedTokens(8);

  // Act
  const UnblindedTokenList& unblinded_tokens =
      GetUnblindedTokens()->GetAllTokens();

  // Assert
  const std::vector<std::string> expected_unblinded_tokens_base64 = {
      R"~(PLowz2WF2eGD5zfwZjk9p76HXBLDKMq/3EAZHeG/fE2XGQ48jyte+Ve50ZlasOuYL5mwA8CU2aFMlJrt3DDgC3B1+VD/uyHPfa/+bwYRrpVH5YwNSDEydVx8S4r+BYVY)~",
      R"~(hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K)~",
      R"~(bbpQ1DcxfDA+ycNg9WZvIwinjO0GKnCon1UFxDLoDOLZVnKG3ufruNZi/n8dO+G2AkTiWkUKbi78xCyKsqsXnGYUlA/6MMEOzmR67rZhMwdJHr14Fu+TCI9JscDlWepa)~",
      R"~(OlDIXpWRR1/B+1pjPbLyc5sx0V+d7QzQb4NDGUI6F676jy8tL++u57SF4DQhvdEpBrKID+j27RLrbjsecXSjR5oieuH4Bx5mHqTb/rAPI6RpaAXtfXYrCYbf7EPwHTMU)~",
      R"~(Y579V5BUcCzAFj6qNX7YnIr+DvH0mugb/nnY5UINdjxziyDJlejJwi0kPaRGmqbVT3+B51lpErt8e66z0jTbAxBfhtXKARFKtGH8WccB6NfCa85XHBmlcuv1+zcFPDJi)~",
      R"~(+MPQfSo6UcaZNWtfmbd5je9UIr+FVrCWHl6I5C1ZFD7y7bjP/yz7flTjV+l5mKulbCvsRna7++MhbBz6iC0FvVZGYXLeLn2HSAM7cDgqyW6SEuPzlDeZT6kkTNI7JcQm)~",
      R"~(CRXUzo7S0X//u0RGsO534vCoIbrsXgbzLfWw8CLML0CkgMltEGxM6XwBTICl4dqqfhIcLhD0f1WFod7JpuEkj5pW/rg7nl48EX6nmekgd3D2Hz8JgJnSarzP/8+3l+MW)~",
      R"~(hQ+6+jh5DUUBFhhGn7bPLDjqrUIKNi/T8QDt1x01bcW9PLADg6aS73dzrVBsHav44+4q1QhFE/93u0KHVtZ1RPKMqkt8MIiC6RG575102nGRTJDA2kSOgUM75hjDsI8z)~"};
  UnblindedTokenList expected_unblinded_tokens =
      CreateUnblindedTokens(expected_unblinded_tokens_base64);

  EXPECT_EQ(expected_unblinded_tokens, unblinded_tokens);
}

TEST_F(BatAdsUnblindedTokensTest, GetTokensAsList) {
  // Arrange
  SetUnblindedTokens(8);

  // Act
  const base::Value::List list = GetUnblindedTokens()->GetTokensAsList();
  const UnblindedTokenList unblinded_tokens =
      GetUnblindedTokens()->GetAllTokens();
  EXPECT_EQ(list.size(), unblinded_tokens.size());

  for (const auto& item : list) {
    const base::Value::Dict* dict = item.GetIfDict();
    ASSERT_TRUE(dict);

    UnblindedTokenInfo unblinded_token;

    const std::string* unblinded_token_base64 =
        dict->FindString("unblinded_token");
    ASSERT_TRUE(unblinded_token_base64);
    unblinded_token.value = cbr::UnblindedToken(*unblinded_token_base64);

    const std::string* public_key_base64 = dict->FindString("public_key");
    ASSERT_TRUE(public_key_base64);
    unblinded_token.public_key = cbr::PublicKey(*public_key_base64);

    ASSERT_TRUE(unblinded_token.is_valid());

    EXPECT_TRUE(GetUnblindedTokens()->TokenExists(unblinded_token));
  }
}

TEST_F(BatAdsUnblindedTokensTest, GetTokensAsListWithEmptyList) {
  // Arrange
  const base::Value::List list = GetUnblindedTokens()->GetTokensAsList();

  // Assert
  EXPECT_TRUE(list.empty());
}

TEST_F(BatAdsUnblindedTokensTest, SetTokens) {
  // Arrange
  const UnblindedTokenList unblinded_tokens = GetUnblindedTokens(10);

  // Act
  GetUnblindedTokens()->SetTokens(unblinded_tokens);

  // Assert
  const UnblindedTokenList& expected_unblinded_tokens =
      GetUnblindedTokens()->GetAllTokens();

  EXPECT_EQ(expected_unblinded_tokens, unblinded_tokens);
}

TEST_F(BatAdsUnblindedTokensTest, SetTokensWithEmptyList) {
  // Arrange
  const UnblindedTokenList unblinded_tokens;

  // Act
  GetUnblindedTokens()->SetTokens(unblinded_tokens);

  // Assert
  EXPECT_TRUE(privacy::GetUnblindedTokens()->IsEmpty());
}

TEST_F(BatAdsUnblindedTokensTest, SetTokensFromList) {
  // Arrange
  const base::Value list = GetUnblindedTokensAsList(5);

  // Act
  GetUnblindedTokens()->SetTokensFromList(list.GetList());

  // Assert
  const UnblindedTokenList& unblinded_tokens =
      GetUnblindedTokens()->GetAllTokens();

  const std::vector<std::string> expected_unblinded_tokens_base64 = {
      R"~(PLowz2WF2eGD5zfwZjk9p76HXBLDKMq/3EAZHeG/fE2XGQ48jyte+Ve50ZlasOuYL5mwA8CU2aFMlJrt3DDgC3B1+VD/uyHPfa/+bwYRrpVH5YwNSDEydVx8S4r+BYVY)~",
      R"~(hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K)~",
      R"~(bbpQ1DcxfDA+ycNg9WZvIwinjO0GKnCon1UFxDLoDOLZVnKG3ufruNZi/n8dO+G2AkTiWkUKbi78xCyKsqsXnGYUlA/6MMEOzmR67rZhMwdJHr14Fu+TCI9JscDlWepa)~",
      R"~(OlDIXpWRR1/B+1pjPbLyc5sx0V+d7QzQb4NDGUI6F676jy8tL++u57SF4DQhvdEpBrKID+j27RLrbjsecXSjR5oieuH4Bx5mHqTb/rAPI6RpaAXtfXYrCYbf7EPwHTMU)~",
      R"~(Y579V5BUcCzAFj6qNX7YnIr+DvH0mugb/nnY5UINdjxziyDJlejJwi0kPaRGmqbVT3+B51lpErt8e66z0jTbAxBfhtXKARFKtGH8WccB6NfCa85XHBmlcuv1+zcFPDJi)~"};

  UnblindedTokenList expected_unblinded_tokens;
  for (const auto& unblinded_token_base64 : expected_unblinded_tokens_base64) {
    UnblindedTokenInfo unblinded_token;
    unblinded_token.value = cbr::UnblindedToken(unblinded_token_base64);
    unblinded_token.public_key =
        cbr::PublicKey("RJ2i/o/pZkrH+i0aGEMY1G9FXtd7Q7gfRi3YdNRnDDk=");
    ASSERT_TRUE(unblinded_token.is_valid());

    expected_unblinded_tokens.push_back(unblinded_token);
  }

  EXPECT_EQ(expected_unblinded_tokens, unblinded_tokens);
}

TEST_F(BatAdsUnblindedTokensTest, SetTokensFromListWithEmptyList) {
  // Arrange
  const base::Value list = GetUnblindedTokensAsList(0);

  // Act
  GetUnblindedTokens()->SetTokensFromList(list.GetList());

  // Assert
  EXPECT_TRUE(privacy::GetUnblindedTokens()->IsEmpty());
}

TEST_F(BatAdsUnblindedTokensTest, AddTokens) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  const UnblindedTokenList unblinded_tokens = GetRandomUnblindedTokens(5);
  GetUnblindedTokens()->AddTokens(unblinded_tokens);

  // Assert
  for (const auto& unblinded_token : unblinded_tokens) {
    EXPECT_TRUE(GetUnblindedTokens()->TokenExists(unblinded_token));
  }
}

TEST_F(BatAdsUnblindedTokensTest, DoNotAddDuplicateTokens) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  const UnblindedTokenList duplicate_unblinded_tokens = GetUnblindedTokens(1);
  GetUnblindedTokens()->AddTokens(duplicate_unblinded_tokens);

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(3, count);
}

TEST_F(BatAdsUnblindedTokensTest, AddTokensCount) {
  // Arrange
  SetUnblindedTokens(5);

  // Act
  const UnblindedTokenList random_unblinded_tokens =
      GetRandomUnblindedTokens(3);
  GetUnblindedTokens()->AddTokens(random_unblinded_tokens);

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(8, count);
}

TEST_F(BatAdsUnblindedTokensTest, AddTokensWithEmptyList) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  GetUnblindedTokens()->AddTokens({});

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(3, count);
}

TEST_F(BatAdsUnblindedTokensTest, RemoveTokenCount) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  const std::string unblinded_token_base64 =
      "hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6"
      "NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K";

  const UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  GetUnblindedTokens()->RemoveToken(unblinded_token);

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(2, count);
}

TEST_F(BatAdsUnblindedTokensTest, RemoveToken) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  std::string unblinded_token_base64 =
      "hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6"
      "NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K";

  const UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  GetUnblindedTokens()->RemoveToken(unblinded_token);

  // Assert
  EXPECT_FALSE(GetUnblindedTokens()->TokenExists(unblinded_token));
}

TEST_F(BatAdsUnblindedTokensTest, DoNotRemoveTokensThatDoNotExist) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  std::string unblinded_token_base64 =
      "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
      "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
  UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  GetUnblindedTokens()->RemoveToken(unblinded_token);

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(3, count);
}

TEST_F(BatAdsUnblindedTokensTest, DoNotRemoveTheSameTokenTwice) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  std::string unblinded_token_base64 =
      "hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6"
      "NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K";

  const UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  GetUnblindedTokens()->RemoveToken(unblinded_token);
  GetUnblindedTokens()->RemoveToken(unblinded_token);

  // Assert
  const int count = GetUnblindedTokens()->Count();
  EXPECT_EQ(2, count);
}

TEST_F(BatAdsUnblindedTokensTest, RemoveMatchingTokens) {
  // Arrange
  UnblindedTokenList unblinded_tokens = SetUnblindedTokens(3);
  UnblindedTokenInfo unblinded_token = unblinded_tokens.back();
  unblinded_tokens.pop_back();

  // Act
  GetUnblindedTokens()->RemoveTokens(unblinded_tokens);

  // Assert
  const std::vector<std::string> expected_unblinded_tokens_base64 = {
      "bbpQ1DcxfDA+ycNg9WZvIwinjO0GKnCon1UFxDLoDOLZVnKG3ufruNZi/n8dO+G2"
      "AkTiWkUKbi78xCyKsqsXnGYUlA/6MMEOzmR67rZhMwdJHr14Fu+TCI9JscDlWepa"};
  const UnblindedTokenList expected_unblinded_tokens =
      CreateUnblindedTokens(expected_unblinded_tokens_base64);

  unblinded_tokens = GetUnblindedTokens()->GetAllTokens();

  EXPECT_EQ(expected_unblinded_tokens, unblinded_tokens);
}

TEST_F(BatAdsUnblindedTokensTest, RemoveAllTokens) {
  // Arrange
  SetUnblindedTokens(7);

  // Act
  GetUnblindedTokens()->RemoveAllTokens();

  // Assert
  EXPECT_TRUE(privacy::GetUnblindedTokens()->IsEmpty());
}

TEST_F(BatAdsUnblindedTokensTest, RemoveAllTokensWithEmptyList) {
  // Arrange

  // Act
  GetUnblindedTokens()->RemoveAllTokens();

  // Assert
  EXPECT_TRUE(privacy::GetUnblindedTokens()->IsEmpty());
}

TEST_F(BatAdsUnblindedTokensTest, TokenExists) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  std::string unblinded_token_base64 =
      "hfrMEltWLuzbKQ02Qixh5C/DWiJbdOoaGaidKZ7Mv+cRq5fyxJqemE/MPlARPhl6"
      "NgXPHUeyaxzd6/Lk6YHlfXbBA023DYvGMHoKm15NP/nWnZ1V3iLkgOOHZuk80Z4K";

  const UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  // Assert
  const bool exists = GetUnblindedTokens()->TokenExists(unblinded_token);

  EXPECT_TRUE(exists);
}

TEST_F(BatAdsUnblindedTokensTest, TokenDoesNotExist) {
  // Arrange
  SetUnblindedTokens(3);

  // Act
  std::string unblinded_token_base64 =
      "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
      "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
  UnblindedTokenInfo unblinded_token =
      CreateUnblindedToken(unblinded_token_base64);

  // Assert
  const bool exists = GetUnblindedTokens()->TokenExists(unblinded_token);

  EXPECT_FALSE(exists);
}

TEST_F(BatAdsUnblindedTokensTest, Count) {
  // Arrange
  SetUnblindedTokens(6);

  // Act
  const int count = GetUnblindedTokens()->Count();

  // Assert
  EXPECT_EQ(6, count);
}

TEST_F(BatAdsUnblindedTokensTest, IsEmpty) {
  // Arrange

  // Act
  const bool is_empty = GetUnblindedTokens()->IsEmpty();

  // Assert
  EXPECT_TRUE(is_empty);
}

TEST_F(BatAdsUnblindedTokensTest, IsNotEmpty) {
  // Arrange
  SetUnblindedTokens(9);

  // Act
  const bool is_empty = GetUnblindedTokens()->IsEmpty();

  // Assert
  EXPECT_FALSE(is_empty);
}

}  // namespace privacy
}  // namespace ads
