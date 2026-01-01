# Add project specific ProGuard rules here.

# ======================== gomobile 防 R8 优化 ========================
# 保留所有 gomobile 生成的类
-keep class core.** { *; }
-keep class go.** { *; }

# 保留 gomobile 的 JNI 入口（关键！）
-keep class go.Seq { *; }
-keep class go.Seq$Proxy { *; }
-keep class go.Seq$Ref { *; }

# 保留所有 native 方法
-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留所有实现 go.Seq$Object 的类
-keep class * implements go.Seq$Object { *; }

# 保留所有实现 go.Seq$GoObject 的类  
-keep class * implements go.Seq$GoObject { *; }

# 防止 R8 优化掉反射调用的方法
-keepclassmembers class core.** {
    public <methods>;
    public <fields>;
}

# ======================== Gson ========================
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.echworkers.android.model.** { *; }

# ======================== VPN Service ========================
-keep class com.echworkers.android.vpn.** { *; }

# ======================== 调试信息 ========================
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
