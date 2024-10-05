#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstring>
#include <fstream>
#include <sstream>

// Function to execute system commands and capture output
std::string execCommand(const std::string &cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to create and configure X authentication
void createXauth(const std::string &myxcookie) {
    std::string display = getenv("DISPLAY") ? getenv("DISPLAY") : ":0";
    std::string hostname = execCommand("uname -n");
    hostname.erase(std::remove(hostname.begin(), hostname.end(), '\n'), hostname.end());

    std::string cmd1 = "xauth add " + hostname + display + " . $(xxd -l 16 -p /dev/urandom)";
    std::string cmd2 = "xauth extract " + myxcookie + " " + hostname + display;

    system(cmd1.c_str());
    system(cmd2.c_str());

    // Add read permissions to the cookie
    std::string cmdAcl = "setfacl -m u:" + std::string(getenv("USER")) + ":r " + myxcookie;
    system(cmdAcl.c_str());

    std::cout << "[))> Xauth created and cookie extracted!" << std::endl;
}

// Function to run commands with the Xauth cookie set
void runWithXauth(const std::string &myxcookie, const std::string &command) {
    setenv("DISPLAY", ":0", 1);  // Ensure DISPLAY is set to the correct value
    std::string cmd = "xauth merge " + myxcookie + " && " + command;
    system(cmd.c_str());
}

// Function to find Wayland display
std::string findWaylandDisplay() {
    const char* runtimeDir = getenv("XDG_RUNTIME_DIR");
    if (!runtimeDir) {
        std::cerr << "Error: XDG_RUNTIME_DIR is not set!" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string findCommand = "find " + std::string(runtimeDir) + "/wayland-* | grep -v '.lock'";
    std::string waylandDisplay = execCommand(findCommand);

    if (!waylandDisplay.empty()) {
        waylandDisplay.erase(std::remove(waylandDisplay.begin(), waylandDisplay.end(), '\n'), waylandDisplay.end());
        return waylandDisplay;
    }

    return "";
}

// Main program logic
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "[))> No program specified to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];
    std::string myxcookie = std::string(getenv("HOME")) + "/my-x-cookie";

    // Set environment variables for Wayland and Qt
    setenv("QT_QPA_PLATFORMTHEME", "qt5ct", 1);
    setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);

    // Try to find Wayland display
    std::string waylandDisplay = findWaylandDisplay();
    if (!waylandDisplay.empty()) {
        setenv("WAYLAND_DISPLAY", waylandDisplay.c_str(), 1);
        std::cout << "[))> Wayland display set to: " << waylandDisplay << std::endl;
    } else {
        std::cout << "[))> No Wayland display found. Falling back to X11." << std::endl;
    }

    // Check if sudo is available
    std::string sudoCheck = execCommand("which sudo");
    if (sudoCheck.empty()) {
        std::cout << "[))> No sudo installed. Using xhost method." << std::endl;
        createXauth(myxcookie);
        runWithXauth(myxcookie, program);
    } else {
        // Run the program with sudo environment variables
        std::string sudoCommand = "sudo -E " + program;
        int result = system(sudoCommand.c_str());
        if (result != 0) {
            std::cout << "[))> Program failed with sudo. Falling back to xhost method." << std::endl;
            createXauth(myxcookie);
            runWithXauth(myxcookie, program);
        }
    }

    // Clean up sensitive data
    std::cout << "[))> Program execution finished." << std::endl;
    return 0;
}
