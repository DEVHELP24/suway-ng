// SPDX-License-Identifier: MIT
// Maintainer: NAZY-OS
// Description: This program securely executes a specified command with user authentication. 
// It checks the user's password against the hashed password in /etc/shadow 
// and manages X11 authentication without using sudo. The code is designed for security and simplicity.

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <shadow.h>
#include <string>
#include <vector>
#include <termios.h>
#include <fstream>
#include <openssl/rand.h>
#include <X11/Xlib.h>
#include <X11/Xauth.h>
#include <stdexcept>

// Function to read the user's password securely, masking input with asterisks
std::string read_password() {
    struct termios oldt, newt;
    std::string password;

    // Save current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Disable echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply new settings

    std::cout << "[))> Enter passphrase: ";
    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 127) { // Backspace handling
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Remove the last asterisk
            }
        } else {
            password += ch;
            std::cout << '*'; // Display an asterisk for each character
        }
    }
    std::cout << std::endl;

    // Restore old terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

// Function to verify the provided password against the stored hashed password
bool check_password(const std::string& entered_password, const std::string& username) {
    struct spwd* shadow_entry = getspnam(username.c_str());
    if (!shadow_entry) {
        std::cerr << "[))> User not found in shadow file." << std::endl;
        return false;
    }

    // Check if the entered password matches the stored hashed password
    return (crypt(entered_password.c_str(), shadow_entry->sp_pwdp) == shadow_entry->sp_pwdp);
}

// Function to execute a command
void execute_command(const std::vector<std::string>& cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // In child process, execute the command
        std::vector<char*> argv;
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr); // Last argument must be nullptr
        execvp(argv[0], argv.data());
        // If execvp fails
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Fork failed
        perror("fork failed");
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
void manage_xauth(const std::string& cookie_path) {
    // Create or update .Xauthority
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        throw std::runtime_error("Unable to open X display");
    }

    // Get the display number
    int display_num = DefaultScreen(display);
    std::string display_name = ":0"; // Modify as needed

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
    auth->number = display_num;   // Set display number (typically 0)
    auth->name_length = display_name.length();  // Length of display name
    auth->name = reinterpret_cast<unsigned char*>(const_cast<char*>(display_name.c_str()));  // Display name
    auth->data_length = sizeof(cookie);  // Length of cookie
    auth->data = cookie;  // The cookie itself

    // Write the cookie to the Xauthority file
    FILE* xauth_file = fopen(cookie_path.c_str(), "a");
    if (xauth_file) {
        XauWriteAuth(xauth_file, auth); // Write the cookie to the file
        fclose(xauth_file);
    } else {
        throw std::runtime_error("Failed to open X authority file");
    }

    XFree(auth);
    XCloseDisplay(display);
}

// Function to check if a command exists in the PATH
bool command_exists(const std::string& cmd) {
    return system(("command -v " + cmd + " > /dev/null 2>&1").c_str()) == 0;
}

// Main function
int main(int argc, char* argv[]) {
    // Check if the program is executed with the required parameters
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];
    std::string username = getlogin(); // Get the current username

    // Check if the required commands exist
    if (!command_exists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Read password securely
    std::string password = read_password();

    // Verify user password
    if (!check_password(password, username)) {
        std::cerr << "[))> Incorrect password." << std::endl;
        return EXIT_FAILURE;
    }

    // Manage X11 authentication
    std::string cookie_path = std::string(getenv("HOME")) + "/.Xauthority";
    manage_xauth(cookie_path);

    // Prepare command to run with user privileges
    std::vector<std::string> command = {program};
    // Append any additional parameters provided by the user
    for (int i = 2; i < argc; ++i) {
        command.push_back(argv[i]);
    }

    // Execute the command
    try {
        execute_command(command);
        std::cout << "[))> Execution finished with no errors!" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
