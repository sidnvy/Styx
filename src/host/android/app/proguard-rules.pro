# Keep JNI entry points invoked by libstyx_android.so (src/crates/styx-android).
-keep class com.styx.host.NativeHost {
    public static native <methods>;
}
-keep class com.styx.host.AndroidPlatform {
    public java.lang.String loadCredentials();
    public void storeCredentials(java.lang.String);
    public void forgetCredentials();
    public java.lang.String execute(java.lang.String, java.lang.String);
}
-keep class com.styx.host.vdisplay.VDisplayHelperMain {
    public static void main(java.lang.String[]);
}
-keep class com.styx.host.vdisplay.VDisplayHelperMain$HelperBinder { *; }
-keep class com.styx.host.vdisplay.VDisplayBinderProvider { *; }
