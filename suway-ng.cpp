#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef __unix__
#include <xauth.h>
#endif

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
    // Assume .Xauthority is already created
    if (system("xauth add $(uname -n):0 . $(xxd -l 16 -p /dev/urandom)") != 0) {
        std::cerr << "[!!] Failed to create X11 authentication." << std::endl;
        return false;
    }
    return true;
}

// Function to run the command with sudo
bool runWithSudo(const std::string& command, const std::string& password) {
    std::string cmd = "echo " + password + " | sudo -S " + command;
    return system(cmd.c_str()) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "[!!] No program found to run with suway!" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    // Validate the command to prevent injection
    if (command.find(';') != std::string::npos || command.find('&') != std::string::npos) {
        std::cerr << "[!!] Invalid command!" << std::endl;
        return 1;
    }

    // Read password securely
    std::string password = readPassword();

    // Create X11 authentication
    if (!createXAuth()) {
        return 1;
    }

    // Run the command with sudo
    if (!runWithSudo(command, password)) {
        std::cerr << "[!!] Failed to run the command with sudo." << std::endl;
        return 1;
    }

    std::cout << "[))> Command executed successfully!" << std::endl;
    return 0;
}
