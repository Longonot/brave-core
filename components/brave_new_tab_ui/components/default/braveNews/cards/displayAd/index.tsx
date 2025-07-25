// Copyright (c) 2021 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

import { getLocale } from '$web-common/locale'
import VisibilityTimer from '$web-common/visibilityTimer'
import * as React from 'react'
import { GetDisplayAdContent, OnViewedDisplayAd, OnVisitDisplayAd } from '../..'
import { DisplayAd } from '../../../../../../brave_news/browser/resources/shared/api'
import * as Card from '../../cardSizes'
import { useVisitDisplayAdClickHandler } from '../../useReadArticleClickHandler'
import useScrollIntoView from '../../useScrollIntoView'
import CardImage from '../CardImage'
import * as Styles from './style'
import useTriggerOnNearViewport from './useTriggerOnNearViewport'

type Props = {
  shouldScrollIntoView?: boolean
  getContent: GetDisplayAdContent
  onVisitDisplayAd: OnVisitDisplayAd
  onViewedDisplayAd: OnViewedDisplayAd
}

export default function CardDisplayAd (props: Props) {
  // Content is retrieved when the element is close to the viewport
  const [content, setContent] = React.useState<DisplayAd | undefined | null>(undefined)
  const [cardRef] = useScrollIntoView(props.shouldScrollIntoView || false)
  const onClick = useVisitDisplayAdClickHandler(props.onVisitDisplayAd, content ? { ad: content } : undefined)
  const innerRef = React.useRef<HTMLElement>(null)
  // Setup an observer to track amount of time viewed
  React.useEffect(() => {
    if (!innerRef.current || !content || !props.onViewedDisplayAd) {
      return
    }
    // Detect when card is viewed, and send an action.
    let onItemViewed = props.onViewedDisplayAd
    const observer = new VisibilityTimer(() => {
      onItemViewed({ ad: content })
    }, 1000, innerRef.current)
    observer.startTracking()
    return () => {
      observer.stopTracking()
    }
  }, [innerRef.current, props.onViewedDisplayAd, content?.uuid])
  // Ask for and render the ad only when we're scrolled close to it
  const handleOnNearViewport = React.useCallback(async () => {
    // Get the ad and display it
    const { ad } = await props.getContent()
    // Request may not actually come back with an ad
    if (ad) {
      setContent(ad)
    }
  }, [props.getContent, setContent])
  const handleOnNearViewportRef = React.useRef<Function>(handleOnNearViewport)
  handleOnNearViewportRef.current = handleOnNearViewport
  const [contentTrigger] = useTriggerOnNearViewport(handleOnNearViewportRef)
  // Render content trigger
  if (!content) {
    // verbose ref type conversion due to https://stackoverflow.com/questions/61102101/cannot-assign-refobjecthtmldivelement-to-refobjecthtmlelement-instance
    return <div ref={contentTrigger}><div ref={cardRef as unknown as React.RefObject<HTMLDivElement>} /></div>
  }
  const imageUrl = content.image.paddedImageUrl?.url || content.image.imageUrl?.url
  // Render ad when one is available for this unit
  // TODO(petemill): Avoid nested links
  return (
    <Card.Large ref={innerRef}>
      <Styles.BatAdLabel href='chrome://rewards'>
        {getLocale('braveNewsDisplayAdLabel')}
      </Styles.BatAdLabel>
      <a onClick={onClick} href={content.targetUrl.url} ref={cardRef}>
        <CardImage
          imageUrl={imageUrl}
          isPromoted={true}
        />
        <Card.Content>
          <Styles.Header>
            <Card.Heading>
              {content.title}
            </Card.Heading>
            <Styles.CallToAction onClick={onClick}>
              {content.ctaText}
            </Styles.CallToAction>
          </Styles.Header>
          {
            <Card.Source>
              <Card.Publisher>
                {content.description}
              </Card.Publisher>
            </Card.Source>
          }
        </Card.Content>
      </a>
    </Card.Large>
  )
}
