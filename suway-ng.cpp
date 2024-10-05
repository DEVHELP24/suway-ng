#include <iostream>
#include <cstdlib>
#include <string>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>

std::string readPassword() {
    std::string password;
    char ch;

    std::cout << "[))> Enter passphrase: ";
    while (true) {
        ch = getchar();
        if (ch == '\n' || ch == '\r') {
            break;
        } else if (ch == 127 || ch == '\b') { // Handle backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Move back, overwrite with space, move back again
            }
        } else {
            password += ch;
            std::cout << '*'; // Show asterisk for each character
        }
    }
    std::cout << std::endl; // New line after password input
    return password;
}

bool createXAuth() {
    const char* display = getenv("DISPLAY");
    std::string command;

    if (display) {
        command = "xauth add " + std::string(display) + " . $(xxd -l 16 -p /dev/urandom)";
        if (system(command.c_str()) == -1) {
            std::cerr << "[!!] Failed to create X authority." << std::endl;
            return false;
        }
    }
    return true;
}

bool xhostAccess(const std::string& user) {
    std::string command = "xhost +SI:localuser:" + user;
    if (system(command.c_str()) == -1) {
        std::cerr << "[!!] Failed to set xhost access." << std::endl;
        return false;
    }
    return true;
}

bool extractXCookie(const std::string& cookieFile) {
    std::string command = "xauth extract " + cookieFile + " $DISPLAY";
    return system(command.c_str()) == 0;
}

bool mergeXCookie(const std::string& cookieFile) {
    std::string command = "xauth merge " + cookieFile;
    return system(command.c_str()) == 0;
}

int main(int argc, char* argv[]) {
    // Check if a command was provided
    if (argc < 2) {
        std::cerr << "[!!] No command provided to run." << std::endl;
        return 1;
    }

    // Get the display variables
    const char* display = getenv("DISPLAY");
    const char* wayland_display = getenv("WAYLAND_DISPLAY");

    if (display) {
        std::cout << "[))> Using X11 display: " << display << std::endl;
    } else if (wayland_display) {
        std::cout << "[))> Using Wayland display: " << wayland_display << std::endl;
    } else {
        std::cerr << "[!!] No display server found. Exiting." << std::endl;
        return 1;
    }

    // Read password from the user
    std::string password = readPassword();

    // Create X authentication if necessary
    if (display && !createXAuth()) {
        return 1;
    }

    // Grant access to the local user for X11
    const char* user = getenv("USER");
    if (user && !xhostAccess(user)) {
        return 1;
    }

    // Extract X cookie
    std::string cookieFile = "/tmp/xauth_cookie";
    if (!extractXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to extract X cookie." << std::endl;
        return 1;
    }

    // Merge the extracted cookie back
    if (!mergeXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to merge X cookie." << std::endl;
        return 1;
    }

    // Construct the command to run
    std::string command = "echo " + password + " | " + argv[1];

    // Execute the command
    int result = system(command.c_str());
    if (result == -1) {
        std::cerr << "[!!] Command execution failed." << std::endl;
        return 1;
    }

    std::cout << "[))> Command executed successfully!" << std::endl;
    return 0;
}
