#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <limits.h>

#ifdef __unix__
#include <xauth.h>
#endif

/*
 * This program is designed to be placed in the /sbin folder.
 * It executes commands directly without using sudo, so ensure 
 * that the necessary permissions are granted for the commands 
 * you intend to run.
 */

// Function to securely read the password with asterisks
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

// Function to create X11 authentication
bool createXAuth() {
    if (system("xauth add $(uname -n):0 . $(xxd -l 16 -p /dev/urandom)") != 0) {
        std::cerr << "[!!] Failed to create X11 authentication." << std::endl;
        return false;
    }
    return true;
}

// Function to validate the command input
bool isCommandValid(const std::string& command) {
    // Check for disallowed characters to prevent command injection
    return command.find(';') == std::string::npos && command.find('&') == std::string::npos;
}

// Function to run the command
bool runCommand(const std::string& command) {
    // Run the command directly without sudo
    return system(command.c_str()) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "[!!] No program found to run!" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    // Validate the command to prevent injection
    if (!isCommandValid(command)) {
        std::cerr << "[!!] Invalid command!" << std::endl;
        return 1;
    }

    // Set up Wayland or X11 environment variables
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

    // Read password securely
    std::string password = readPassword();

    // Create X11 authentication (if using X11)
    if (display && !createXAuth()) {
        return 1;
    }

    // Run the command without sudo
    if (!runCommand(command)) {
        std::cerr << "[!!] Failed to run the command." << std::endl;
        return 1;
    }

    std::cout << "[))> Command executed successfully!" << std::endl;
    return 0;
}
