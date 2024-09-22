# bash script

# Define variables
DOWNLOAD_URL="https://raw.githubusercontent.com/SeriousHoax/AnythingWindows/refs/heads/main/test.sh"
SCRIPT_NAME="test.sh"
TARGET_DIR="/home"

# Download the script from the specified URL
echo "Downloading script from $DOWNLOAD_URL..."
curl -o /tmp/$SCRIPT_NAME $DOWNLOAD_URL

# Make the script executable
echo "Making script executable..."
sudo chmod +x $TARGET_DIR/$SCRIPT_NAME

# Run the script
echo "Running the script..."
sudo $TARGET_DIR/$SCRIPT_NAME
