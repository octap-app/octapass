# JNA and the UniFFI bindings look up classes, fields and callbacks by name.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class app.octap.core.** { *; }
-dontwarn java.awt.**
