#!/bin/bash
# Developer Options Detection Bypass (Non-Root)

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

LOG_FILE="bypass_dev_opts.log"

# Function for error handling
error_exit() {
  echo -e "${RED}$1${NC}" | tee -a $LOG_FILE
  exit 1
}

# Function to log messages
log() {
  echo -e "${GREEN}$1${NC}" | tee -a $LOG_FILE
}

# Ensure all dependencies are installed
install_dependencies() {
  log "Installing dependencies..."
  pkg update && pkg upgrade -y || error_exit "Failed to update packages."
  
  # Install Python and pip
  pkg install -y python || error_exit "Failed to install Python."
  
  # Install Frida and frida-tools via pip with error handling
  pip install frida frida-tools
  if [ $? -ne 0 ]; then
    log "Failed to install frida and frida-tools via pip. Attempting installation via alternative method..."
    pip install --pre frida || error_exit "Failed to install frida via alternative method."
  fi
  
  # Install ADB
  log "Installing ADB..."
  wget -q https://dl.google.com/android/repository/platform-tools-latest-linux.zip -O platform-tools.zip || error_exit "Failed to download ADB."
  unzip -q platform-tools.zip -d platform-tools || error_exit "Failed to extract ADB."
  export PATH=$PATH:`pwd`/platform-tools/platform-tools || error_exit "Failed to set PATH for ADB."
}

# Check if ADB is working
check_adb() {
  log "Checking ADB..."
  adb devices | grep "device" >/dev/null 2>&1 || error_exit "ADB is not detecting your device. Please connect and authorize ADB."
}

# Download and configure Frida server
setup_frida_server() {
  log "Setting up Frida server..."
  local FRIDA_SERVER_URL="https://github.com/frida/frida/releases/latest/download/frida-server-16.0.8-android-arm64.xz"
  local FRIDA_SERVER_PATH="/data/local/tmp/frida-server"
  wget -q $FRIDA_SERVER_URL -O frida-server.xz || error_exit "Failed to download Frida server."
  unxz frida-server.xz || error_exit "Failed to extract Frida server."
  adb push frida-server $FRIDA_SERVER_PATH || error_exit "Failed to push Frida server to device."
  adb shell "chmod +x $FRIDA_SERVER_PATH" || error_exit "Failed to set permissions for Frida server."
}

# Start Frida server
start_frida_server() {
  log "Starting Frida server on device..."
  adb shell "$FRIDA_SERVER_PATH &" || error_exit "Failed to start Frida server."
  adb forward tcp:27042 tcp:27042 || error_exit "Failed to forward port for Frida."
}

# Create Frida hook script for bypassing developer options
create_frida_hook_script() {
  log "Creating Frida hook script..."
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
}

# Apply ADB environment changes to disable developer options
disable_developer_options() {
  log "Disabling Developer Options via ADB..."
  adb shell "settings put global development_settings_enabled 0" || error_exit "Failed to disable developer options."
}

# Attach Frida to the target app
attach_frida_to_app() {
  log "Attaching Frida to target app..."
  read -p "Enter the target app package name: " TARGET_APP
  frida -U -n $TARGET_APP -s bypass_dev_opts.js || error_exit "Failed to attach Frida to target app."
}

# Clean up temporary files
cleanup() {
  log "Cleaning up..."
  rm -f frida-server.xz bypass_dev_opts.js platform-tools.zip || error_exit "Failed to clean up temporary files."
}

# Main function
main() {
  install_dependencies
  check_adb
  setup_frida_server
  start_frida_server
  create_frida_hook_script
  disable_developer_options
  attach_frida_to_app
  cleanup
  log "[+] All set! Developer Options Bypass applied."
}

# Execute main function
main
