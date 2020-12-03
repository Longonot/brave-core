/** Copyright (c) 2020 The Brave Authors. All rights reserved.
  * This Source Code Form is subject to the terms of the Mozilla Public
  * License, v. 2.0. If a copy of the MPL was not distributed with this file,
  * You can obtain one at http://mozilla.org/MPL/2.0/.
  */

package org.chromium.chrome.browser.dialogs;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;

import org.chromium.base.ContextUtils;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.chrome.R;
import org.chromium.chrome.browser.BraveAdsNativeHelper;
import org.chromium.chrome.browser.ChromeTabbedActivity;
import org.chromium.chrome.browser.app.BraveActivity;
import org.chromium.chrome.browser.notifications.BraveOnboardingNotification;
import org.chromium.chrome.browser.profiles.Profile;
import org.chromium.chrome.browser.tab.TabLaunchType;

public class BraveAdsNotificationDialog {

    static AlertDialog mAdsDialog;
    static String mNotificationId;
    static final int MIN_DISTANCE = 80;
    static float mYDown = 0.0f;
    static float mYUp = 0.0f;

    public static void displayAdsNotification(Context context, final String notificationId,
            final String origin, final String title, final String body) {
        try {
            if (mAdsDialog != null) {
                mAdsDialog.dismiss();
            }
        } catch (IllegalArgumentException e) {
          mAdsDialog = null;
        }
        AlertDialog.Builder b = new AlertDialog.Builder(context);

        LayoutInflater inflater = LayoutInflater.from(context);
        b.setView(inflater.inflate(R.layout.brave_ads_custom_notification, null));
        mAdsDialog = b.create();

        mAdsDialog.show();

        Window window = mAdsDialog.getWindow();
        WindowManager.LayoutParams wlp = window.getAttributes();

        wlp.gravity = Gravity.TOP;
        wlp.dimAmount = 0.0f;
        wlp.flags |= WindowManager.LayoutParams.FLAG_DIM_BEHIND;

        mAdsDialog.setCanceledOnTouchOutside(false);
        mAdsDialog.setCancelable(false);

        window.setAttributes(wlp);
        window.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT));

        window.setFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL);

        window.findViewById(R.id.brave_ads_custom_notification_popup)
                .setOnTouchListener(new View.OnTouchListener() {
                    @Override
                    public boolean onTouch(View v, MotionEvent event) {
                        float deltaY;
                        float y;
                        switch (event.getAction()) {
                            case MotionEvent.ACTION_DOWN:
                                mYDown = event.getY();
                                break;
                            case MotionEvent.ACTION_MOVE:
                                y = event.getY();
                                deltaY = mYDown - y;
                                if (deltaY > 0) {
                                    v.animate().translationY(-1 * deltaY);
                                }
                                break;
                            case MotionEvent.ACTION_UP:
                                mYUp = event.getY();
                                if (mYDown != 0.0f) {
                                    deltaY = mYDown - mYUp;
                                } else {
                                    return false;
                                }
                                if (deltaY > MIN_DISTANCE) {
                                    mAdsDialog.dismiss();
                                    mAdsDialog = null;
                                    BraveAdsNativeHelper.nativeAdNotificationDismissed(
                                            Profile.getLastUsedRegularProfile(), mNotificationId,
                                            true);
                                    mNotificationId = null;
                                } else {
                                    // Reset back to starting position
                                    v.animate().translationY(0);
                                }
                                break;
                        }
                        return true;
                    }
                });

        ((TextView) mAdsDialog.findViewById(R.id.brave_ads_custom_notification_header)).setText(title);
        ((TextView) mAdsDialog.findViewById(R.id.brave_ads_custom_notification_body)).setText(body);

        mNotificationId = notificationId;

        mAdsDialog.findViewById(R.id.brave_ads_custom_notification_popup).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // We don't take the user to the page in this class, native code handles opening a new tab for us.
                if (mNotificationId.equals(BraveOnboardingNotification.BRAVE_ONBOARDING_NOTIFICATION_TAG)) {
                    mAdsDialog.dismiss();
                    mAdsDialog = null;
                    ChromeTabbedActivity chromeTabbedActivity = BraveActivity.getChromeTabbedActivity();
                    if (chromeTabbedActivity != null) {
                        chromeTabbedActivity.getTabCreator(false).launchUrl(origin, TabLaunchType.FROM_CHROME_UI);
                    }
                } else {
                    mAdsDialog.dismiss();
                    mAdsDialog = null;
                    BraveAdsNativeHelper.nativeAdNotificationClicked(Profile.getLastUsedRegularProfile(), mNotificationId);
                }
                mNotificationId = null;
            }
        });
    }

    @CalledByNative
    public static void displayAdsNotification(final String notificationId,
            final String origin, final String title, final String body) {
        BraveAdsNotificationDialog.displayAdsNotification(
            BraveActivity.getBraveActivity(),
            notificationId,
            origin,
            title,
            body
        );
    }

    @CalledByNative
    private static void closeAdsNotification(final String notificationId) {
        try {
            if (mNotificationId != null && mNotificationId.equals(notificationId) && mAdsDialog != null) {
                mAdsDialog.dismiss();
                BraveAdsNativeHelper.nativeAdNotificationDismissed(Profile.getLastUsedRegularProfile(), mNotificationId, false);
                mAdsDialog = null;
            }
        } catch (IllegalArgumentException e) {
            mAdsDialog = null;
        }

    }
}
