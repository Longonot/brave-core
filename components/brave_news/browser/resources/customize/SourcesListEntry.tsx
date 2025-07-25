// Copyright (c) 2022 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

import Flex from '$web-common/Flex'
import { getLocale } from '$web-common/locale'
import * as React from 'react'
import styled from 'styled-components'
import { useChannelSubscribed, usePublisher, usePublisherFollowed } from '../shared/Context'
import { channelIcons as ChannelIcons } from '../shared/Icons'
import { getTranslatedChannelName } from '../shared/channel'

interface Props {
  publisherId: string
}

const ToggleButton = styled.button`
  all: unset;
  flex: 0 0 auto;
  cursor: pointer;
  color: var(--brave-color-text02);
  &:hover {
    text-decoration: underline;
  }
  &:active {
    color: var(--brave-color-interactive08);
  }
  &:focus-visible {
    outline: 1px solid var(--brave-color-focusBorder);
    outline-offset: 4px;
  }
`

const Container = styled(Flex)`
  padding: 10px 0;

  &:not(:hover, :has(:focus-visible)) ${ToggleButton} {
    opacity: 0;
  }
`

const FavIconContainer = styled.div`
  flex: 0 0 24px;
  height: 24px;
  flex-shrink: 0;
  border-radius: 100px;
  color: #6B7084;

  img {
    width: 100%;
    height: 100%;
  }
`

const Text = styled.span`
  flex: 1 1 0;
  word-break: break-word;
  font-size: 14px;
  font-weight: 500;
`

const ChannelNameText = styled(Text)`
  font-weight: 600;
`

function FavIcon (props: { publisherId: string }) {
  const publisher = usePublisher(props.publisherId)
  const faviconUrl = publisher.faviconUrl?.url
  const [error, setError] = React.useState(false)

  React.useEffect(() => {
    setError(false)
  }, [faviconUrl])

  return (
    <FavIconContainer>
      {faviconUrl && !error && <img loading='lazy' src={`chrome://image?url=${encodeURIComponent(faviconUrl)}`} onError={() => setError(true)} />}
    </FavIconContainer>
  )
}

export function FeedListEntry (props: Props) {
  const publisher = usePublisher(props.publisherId)
  const { setFollowed } = usePublisherFollowed(props.publisherId)

  return (
    <Container direction="row" justify="space-between" align='center' gap={8}>
      <FavIcon publisherId={props.publisherId} />
      <Text>{publisher.publisherName}</Text>
      <ToggleButton onClick={() => setFollowed(false)}>
        {getLocale(S.BRAVE_NEWS_FOLLOW_BUTTON_FOLLOWING)}
      </ToggleButton>
    </Container>
  )
}

export function ChannelListEntry (props: { channelName: string }) {
  const { setSubscribed } = useChannelSubscribed(props.channelName)

  return (
    <Container direction="row" justify='space-between' align='center' gap={8}>
      <FavIconContainer>
        {ChannelIcons[props.channelName] ?? ChannelIcons.default}
      </FavIconContainer>
      <ChannelNameText>{getTranslatedChannelName(props.channelName)}</ChannelNameText>
      <ToggleButton onClick={() => setSubscribed(false)}>
        {getLocale(S.BRAVE_NEWS_FOLLOW_BUTTON_FOLLOWING)}
      </ToggleButton>
    </Container>
  )
}
