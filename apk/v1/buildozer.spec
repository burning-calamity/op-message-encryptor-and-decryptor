[app]
title = All-The-Ciphers
package.name = alltheciphers
package.domain = org.opmessage

source.dir = .
source.include_exts = py,txt
source.exclude_dirs = .buildozer,bin,__pycache__

version = 0.1.0
requirements = python3,kivy
orientation = portrait
fullscreen = 0

android.permissions = INTERNET
android.api = 35
android.minapi = 23
android.archs = arm64-v8a,armeabi-v7a

[buildozer]
log_level = 2
warn_on_root = 1
