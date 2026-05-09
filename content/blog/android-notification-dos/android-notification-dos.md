---
title: "Android Notification DoS: When a GIF Crashes Your Phone (CVE-2025-48631 Incomplete Fix)"
date: 2026-05-09T11:16:51+05:30
Description: "CVE-2025-48631 was marked as fixed in Android's December 2025 bulletin — but the fix was incomplete. Here's how I found the bypass."
Tags: [android, dos, cve]
Categories: []
DisableComments: false
cover:
  image: /android-notification-dos/macshot-clipboard-093E0501-95D2-413C-AB5E-A2FE6D0EA7CE.png
  alt: "CVE-2025-48631 removed from Android Security Bulletin due to incomplete fix"
  relative: false
---

## Intro

In December 2025 I decided to try something different, a long pending goal of mine I wanted to start looking at the Android OS itself. I figured the best way to get started was to go through the Android Security Bulletin and study the types of issues being reported and fixed by the Android security team. I went through the December 2025 bulletin and one vulnerability stood out to me, CVE-2025-48631, a critical Denial-of-Service in the notification image decoding pipeline. The fix included a sample malformed GIF which made it very easy to test. What started as a simple reproduction exercise turned into discovering that the fix was incomplete, and that the vulnerability was still triggering on the latest patched version of Android.

## # CVE-2025-48631 — The Original Fix

CVE-2025-48631 was a DoS vulnerability in `LocalImageResolver.java`. The issue was that the image decoder had no hard limit on the dimensions of images it would process. An attacker could send a notification containing a GIF with maximum GIF dimensions (65535×65535 pixels) and the device would attempt to decode it, exhausting all available memory and crashing.

The fix Google introduced added a constant `DEFAULT_DECODE_HARD_LIMIT_PX = 4096` and a check in the `onHeaderDecoded()` listener that throws a `RuntimeException` if either dimension of the image exceeds 4096 pixels. The fix also included a test GIF with 16000×16000 dimensions to verify the exception is raised properly.

Reproducing this seemed like the simplest starting point for me. I create a sample oversized image with 65535x65535 dimension and sent it to a device running a firmware version before the December patch, and the device crashed. SystemUI went down, restarted, and I could recover by rebooting. That was the expected behavior.

## # The Surprise — Still Crashing on the December Patch

Then I tried the same thing on a device running the December 2025 security patch. I expected it to be fine. It was not.

The device crashed the same way — SystemUI went down and kept restarting. I pulled the logcat and this is what I saw:

```
System.err: java.io.IOException: java.lang.RuntimeException: Image dimensions (65535x65535) exceed the maximum allowed size.
```

So the fix IS triggering. The dimension check is being hit. The exception is being thrown. And yet the device is still crashing. That was confusing enough that I decided I had to dig deeper.

## # Root Cause — The Incomplete Fix

The fix for CVE-2025-48631 added the dimension check, but it was not added to the private method `resolveImage(ImageDecoder.Source, int, int)` inside `LocalImageResolver.java` at lines 219–251. This is the exact method that gets called when a notification image is decoded through the notification pipeline.

```java
// Line 219–251 — VULNERABLE
private static Drawable resolveImage(ImageDecoder.Source source, int maxWidth, int maxHeight) {
    try {
        return ImageDecoder.decodeDrawable(source, (decoder, info, unused) -> {
            if (maxWidth <= 0 || maxHeight <= 0) {   // Never true in attack path
                return;
            }

            final Size size = info.getSize();
            if (size.getWidth() <= maxWidth && size.getHeight() <= maxHeight) {
                return;  // No scaling needed
            }

            // Scaling logic
            if (size.getWidth() > size.getHeight()) {
                if (size.getWidth() > maxWidth) {
                    final int targetHeight = size.getHeight() * maxWidth / size.getWidth();
                    decoder.setTargetSize(maxWidth, targetHeight);
                }
            } else {
                if (size.getHeight() > maxHeight) {
                    final int targetWidth = size.getWidth() * maxHeight / size.getHeight();
                    decoder.setTargetSize(targetWidth, maxHeight);
                }
            }
        });
    } catch (IOException | Resources.NotFoundException e) {
        Log.d(TAG, "Couldn't use ImageDecoder for drawable, falling back to non-resized load.");
        return null;
    }
}
```

The method calls `decoder.setTargetSize(480, 480)` which changes `mDesiredWidth` and `mDesiredHeight` inside `ImageDecoder`. The problem is that this does not stop the underlying native codec from allocating a full-resolution internal buffer for the source image.

Looking at the native side in `ImageDecoder.cpp`:

```cpp
// https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/hwui/jni/ImageDecoder.cpp;l=337-358
static jobject ImageDecoder_nDecodeBitmap(JNIEnv* env, jobject /*clazz*/, jlong nativePtr, ...) {
    SkImageInfo bitmapInfo = decoder->getOutputInfo();
    //...//
    SkBitmap bm;
    if (!bm.setInfo(bitmapInfo)) {  // sets info to 480x480
        doThrowIOE(env, "Failed to setInfo properly");
        return nullptr;
    }

    sk_sp<Bitmap> nativeBitmap;
    //...//
    nativeBitmap = Bitmap::allocateHeapBitmap(&bm); // allocates 480×480×4 = ~0.87 MB

    //...//
    SkCodec::Result result = decoder->decode(bm.getPixels(), bm.rowBytes()); // OOM OCCURS HERE
```

And inside `hwui/ImageDecoder.cpp`:

```cpp
// https://cs.android.com/android/platform/superproject/+/android-latest-release:frameworks/base/libs/hwui/hwui/ImageDecoder.cpp;l=398-451
if (scale || handleOrigin || mCropRect) {
    SkBitmap tmp;
    if (!tmp.setInfo(decodeInfo.makeAlphaType(...)))  // L446: sets to 65535×65535
        { return SkCodec::kInternalError; }

    if (!Bitmap::allocateHeapBitmap(&tmp)) {           // L451: ALLOCATES 65535×65535×4 = ~16 GB
        return SkCodec::kInternalError;                // Returns kInternalError, not OOM
    }
    decodePixels = tmp.getPixels();
    decodeRowBytes = tmp.rowBytes();
}
```

For codecs that do not support native downsampling — GIF and PNG being the main ones — the native decoder has to allocate a full-resolution internal pixel buffer before it can scale down to the target size. 65535 × 65535 × 4 bytes is around 16 GB. The device does not have 16 GB of RAM. The OOM happens at the native layer before the target size even gets applied.

## # Attack Chain

```
Attacker sends malicious GIF via Google Messages (RCS)
        │
        ▼
NotificationManagerService enqueues the notification
        │
        ▼
SystemUI receives the notification
        │
        ▼
NotificationInlineImageResolver.resolveImage(Uri uri)               ← L124
    └── LocalImageResolver.resolveImage(uri, context, maxW, maxH)   ← L155
            └── resolveImage(source, maxWidth, maxHeight)            ← L219  ★ VULNERABLE ★
                    └── ImageDecoder.decodeDrawable(source, listener)← L221
                            └── callHeaderDecoded(listener, src)     [sets targetSize to 480]
                            └── decodeBitmapInternal() / AnimatedImageDrawable()
                                    └── nDecodeBitmap(65535×65535 → OOM)
```

The victim just needs to receive the message. No interaction needed. SystemUI crashes and restarts, and on restart it re-processes the cached notification in Google Messages, which triggers the same crash again. On flagship devices with more RAM the crash loop had a 5–6 second delay between each cycle, visible as a flickering UI. On lower-RAM devices it was crashing and restarting almost instantly.

The worst part is that Google Messages notifications persist after reboot, so the crash loop resumes every time the device boots up. The device becomes stuck in a loop until the message is cleared, which is not straightforward when the UI keeps crashing.

Here is the PoC — from a second device I send an RCS message with the malformed GIF to the victim device, and this is what happens:

<video src=/android-notification-dos/poc.mp4 width="480" height="320" controls></video>

## # Suggested Fix

The fix is to add the hard dimension limit check inside the `onHeaderDecoded` listener in `resolveImage`, before any scaling logic runs, and to also add `RuntimeException` to the catch block so a dimension rejection is handled gracefully:

```java
 private static Drawable resolveImage(ImageDecoder.Source source, int maxWidth, int maxHeight) {
     try {
         return ImageDecoder.decodeDrawable(source, (decoder, info, unused) -> {
+            final Size size = info.getSize();
+
+            if (size.getWidth() > DEFAULT_DECODE_HARD_LIMIT_PX
+                    || size.getHeight() > DEFAULT_DECODE_HARD_LIMIT_PX) {
+                throw new RuntimeException(
+                        "Image dimensions (" + size.getWidth() + "x" + size.getHeight()
+                                + ") exceed the maximum allowed size.");
+            }
+
             if (maxWidth <= 0 || maxHeight <= 0) {
                 return;
             }

-            final Size size = info.getSize();
             if (size.getWidth() <= maxWidth && size.getHeight() <= maxHeight) {
                 return;
             }
             // ... rest of scaling logic unchanged ...
         });
-    } catch (IOException | Resources.NotFoundException e) {
+    } catch (IOException | Resources.NotFoundException | RuntimeException e) {
         Log.d(TAG, "Couldn't use ImageDecoder for drawable, falling back to non-resized load.");
         return null;
     }
 }
```

## # Reporting to Google — Round One

I filed the report on December 17, 2025. The device used for testing was:

```
google/akita/akita:16/BP4A.251205.006/14401865:user/release-keys
```

Google's initial response:

> When we first received your report, our team initially saw some stability issues. However, during further investigation by our engineers, we were unable to reproduce the persistent crash or the device being locked out on the latest versions of Android. On current software, the system correctly identifies and handles images that exceed the allowed size.
>
> Because we could not confirm the security impact on current builds, we decided this does not qualify as a security vulnerability. However, we really appreciate the time and effort you put into this report. To recognize your hard work, we have decided to keep your reward at the "Critical" level.

Then on January 8, 2026 Google quietly updated the December security bulletin:

> CVE-2025-48631 has been removed due to an incomplete fix for Android 16 25Q4, all other Android versions are fine. Partners may keep this fix. An updated fix will be required as part of ASB#2026-03 Android Security Bulletin.

When I saw this I assumed they had internally identified the same root cause I found and that the March 2026 patch would include a proper fix.

## # March 2026 — Still Not Fixed

March 2026 security bulletin dropped. I checked the patch. No additional fix was introduced for this code path. I tested on the latest March build and the vulnerability was still triggering. I filed the report again with the full root cause analysis, the native code path, the suggested fix, and the PoC video showing the crash loop on the latest patched build.

Google's response this time:

> After a thorough technical assessment by our engineering team, the determination remains that this issue will be closed as Won't Fix.

Their reasoning was the same as before — they were unable to reproduce the persistent crash loop on current software builds.

I pushed back. I pointed out that the PoC video shows the crash happening on the March 2026 security patch and that triggering a remote crash loop, even if it is recoverable, should be considered a security impact. A remote attacker being able to brick your phone for the duration of a message existing in your inbox is not nothing.

On the question of disclosure, Google gave me the green light:

> Since we do not have a pending remediation for this issue, you are welcome to proceed with your blog post. We appreciate the high quality of your research and the detail you put into your root cause analysis.

So here we are.

## # Closing Thoughts

My main issue with the outcome is the framing around "persistent crash loop." On my test devices I reproduced a persistent crash loop triggered by receiving a single RCS message, requiring only a reboot and clearing the notification to recover, but the fact that the device is unusable until that is done and that the crash re-triggers on boot is not a benign stability issue in my view. The attack surface is zero-click and reachable via any messaging app that generates MessagingStyle notifications and supports MMS/RCS.

The incomplete fix story is also worth paying attention to. CVE-2025-48631 was patched, pulled from the bulletin, re-scheduled for March, never shipped. The private `resolveImage` method at L219 still does not have the dimension guard. If you are on Android and using Google Messages today, this is still the state of the code.

Anyway, I learned a lot going through the AOSP source and the native decoder internals, and that was the whole point of starting this research. Hopefully this writeup is useful to someone. See you in the next one.

#### Timeline
- Dec 2025 — Began reviewing the December 2025 Android Security Bulletin
- Dec 17, 2025 — First report filed with Android Security Team (issue tracker: https://issuetracker.google.com/issues/469775511)
- Jan 2026 — Google responds: unable to reproduce persistent crash, awards "Critical" reward anyway
- Jan 8, 2026 — Google removes CVE-2025-48631 from December bulletin; notes incomplete fix for Android 16 25Q4, fix rescheduled for March 2026 ASB
- Mar 2026 — March security bulletin ships with no fix for this code path
- Mar 2026 — Second report filed with updated root cause, PoC on latest March build
- May 2026 — Google closes as Won't Fix; authorizes public disclosure
