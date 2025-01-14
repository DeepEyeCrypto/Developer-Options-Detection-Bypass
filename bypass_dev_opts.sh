#!/bin/bash
# Developer Options Detection Bypass (Non-Root)

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Ensure all dependencies are installed
echo -e "${GREEN}Installing dependencies...${NC}"
pkg update && pkg upgrade -y
pkg install -y python adb frida-tools
pip install frida frida-tools

# Check if ADB is working
if ! adb devices | grep "device"; then
  echo -e "${RED}ADB is not detecting your device. Please connect and authorize ADB.${NC}"
  exit 1
fi

# Download and configure Frida server
echo -e "${GREEN}Setting up Frida server...${NC}"
FRIDA_SERVER_URL="https://github.com/frida/frida/releases/latest/download/frida-server-16.0.8-android-arm64.xz"
FRIDA_SERVER_PATH="/data/local/tmp/frida-server"
wget -q $FRIDA_SERVER_URL -O frida-server.xz
unxz frida-server.xz
adb push frida-server $FRIDA_SERVER_PATH
adb shell "chmod +x $FRIDA_SERVER_PATH"

# Start Frida server
echo -e "${GREEN}Starting Frida server on device...${NC}"
adb shell "$FRIDA_SERVER_PATH &"
adb forward tcp:27042 tcp:27042

# Create Frida hook script for bypassing developer options
echo -e "${GREEN}Creating Frida hook script...${NC}"
cat <<EOF > bypass_dev_opts.js
Java.perform(() => {
    const Settings = Java.use("android.provider.Settings");

    // Hook getInt to bypass developer options detection
    Settings.System.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (resolver, name, defValue) {
        if (name === "development_settings_enabled") {
            console.log("[Bypass] getInt intercepted: developer options check");
            return 0; // Fake: Developer options disabled
        }
        return this.getInt(resolver, name, defValue);
    };

    // Hook getBoolean to bypass developer options detection
    Settings.Secure.getBoolean.overload('android.content.ContentResolver', 'java.lang.String', 'boolean').implementation = function (resolver, name, defValue) {
        if (name === "development_settings_enabled") {
            console.log("[Bypass] getBoolean intercepted: developer options check");
            return false; // Fake: Developer options disabled
        }
        return this.getBoolean(resolver, name, defValue);
    };

    console.log("[+] Developer Options Bypass Activated");
});
EOF

# Apply ADB environment changes to disable developer options
echo -e "${GREEN}Disabling Developer Options via ADB...${NC}"
adb shell "settings put global development_settings_enabled 0"

# Attach Frida to the target app
echo -e "${GREEN}Attaching Frida to target app...${NC}"
read -p "Enter the target app package name: " TARGET_APP
frida -U -n $TARGET_APP -s bypass_dev_opts.js &

echo -e "${GREEN}[+] All set! Developer Options Bypass applied.${NC}"
