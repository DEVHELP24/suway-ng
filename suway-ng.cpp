// SPDX-License-Identifier: MIT
// Maintainer: NAZY-OS
// This program runs a specified command with root privileges after prompting for a password.
// It utilizes X11 authentication and handles user input securely.

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <termios.h>
#include <sys/stat.h>
#include <X11/Xlib.h>
#include <X11/Xauth.h>
#include <openssl/rand.h> // Include for RAND_bytes

// Function to read password securely with asterisks for each character entered
std::string readPassword() {
    struct termios oldSettings, newSettings;
    std::string password;

    // Get the current terminal settings
    tcgetattr(STDIN_FILENO, &oldSettings);
    newSettings = oldSettings;
    newSettings.c_lflag &= ~(ECHO); // Disable echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &newSettings); // Apply new settings

    std::cout << "[))> Enter passphrase: ";

    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 127) { // Handle backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Remove the last asterisk
            }
        } else {
            password += ch;
            std::cout << '*'; // Show asterisk for each character
        }
    }
    std::cout << std::endl;

    // Restore old terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
    return password;
}

// Function to execute a command
void executeCommand(const std::vector<std::string>& cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // In child process, execute the command
        std::vector<char*> argv;
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr); // Last argument must be nullptr
        execvp(argv[0], argv.data());
        perror("execvp failed"); // If execvp fails
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        perror("fork failed"); // Fork failed
        exit(EXIT_FAILURE);
    } else {
        // In parent process, wait for the child to finish
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Command execution failed");
        }
    }
}

// Function to manage X11 authentication
void manageXAuth(const std::string& cookiePath) {
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        throw std::runtime_error("Unable to open X display");
    }

    // Get the display number
    int displayNumber = DefaultScreen(display);
    std::string displayName = ":0"; // Modify as needed

    // Generate a random X cookie
    unsigned char cookie[16];
    if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
        throw std::runtime_error("Failed to generate X cookie");
    }

    // Create and configure XAuth
    Xauth* auth = XAllocAuth();
    if (!auth) {
        throw std::runtime_error("Failed to allocate XAuth structure");
    }

    auth->family = FamilyLocal;  // Set the family (e.g., Local)
    auth->number = displayNumber; // Set display number (typically 0)
    auth->name_length = displayName.length();  // Length of display name
    auth->name = reinterpret_cast<unsigned char*>(const_cast<char*>(displayName.c_str())); // Display name
    auth->data_length = sizeof(cookie); // Length of cookie
    auth->data = cookie; // The cookie itself

    // Write the cookie to the Xauthority file
    FILE* xauthFile = fopen(cookiePath.c_str(), "a");
    if (xauthFile) {
        XauWriteAuth(xauthFile, auth); // Write the cookie to the file
        fclose(xauthFile);
    } else {
        throw std::runtime_error("Failed to open X authority file");
    }

    XFree(auth);
    XCloseDisplay(display);
}

// Function to check if a command exists in the PATH
bool commandExists(const std::string& cmd) {
    return system(("command -v " + cmd + " > /dev/null 2>&1").c_str()) == 0;
}

// Main function
int main(int argc, char* argv[]) {
    // Check if the program is executed with the correct number of arguments
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];

    // Check if the required commands exist
    if (!commandExists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Read password securely
    std::string password = readPassword();

    // Manage X11 authentication
    std::string cookiePath = std::string(getenv("HOME")) + "/.Xauthority";
    manageXAuth(cookiePath);

    // Prepare command to run with root privileges
    std::vector<std::string> command = {"sudo", program};

    // Execute the command
    try {
        executeCommand(command);
        std::cout << "[))> Execution finished with no errors!" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
