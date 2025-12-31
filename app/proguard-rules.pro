# Add project specific ProGuard rules here.

# Keep gomobile generated classes
-keep class core.** { *; }
-keep class go.** { *; }

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.echworkers.android.model.** { *; }
