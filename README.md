# AndroidRScoop
Roblox internal offset dumper base made for android. Tested only on Arch Linux

# Usage (Windows)
1. Download [rscoopwindows.exe](https://github.com/barpyfartz/AndroidRScoop/releases/download/release/rscoopwindows.exe) and android roblox apk
2. Unzip roblox apk as archive and open /lib, then open /arm64-v8a
3. After you in arm64-v8a folder unzip libroblox.so from it in any folder with rscoop in it
4. Open CMD and start dumper with .\rscoopwindows.exe --so libroblox.so
5. done

# Usage (Linux)
1. Download [rscooplinux](https://github.com/barpyfartz/AndroidRScoop/releases/download/release/rscooplinux) and android roblox apk
2. Run it with ./rscooplinux /path/to/roblox.apk arm64-v8a
3. done
