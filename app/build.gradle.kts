plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "com.fabi.galaxymirror"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.fabi.galaxymirror"
        minSdk = 29
        targetSdk = 35
        versionCode = 8
        versionName = "0.8.0-ci"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    lint { abortOnError = true; checkReleaseBuilds = true }
    buildTypes {
        debug { isDebuggable = true }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
