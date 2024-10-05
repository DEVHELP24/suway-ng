// SPDX-License-Identifier: MIT
// Maintainer: [NAZY-OS]
// This program is designed to run a specified command with root privileges after validating the user's password.
// It supports password validation against the /etc/shadow file and X11/Wayland authentication.

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <unistd.h>
#include <termios.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <X11/Xlib.h>
#include <X11/Xauth.h>
#include <openssl/rand.h>

// Function to read password securely with asterisks for each character entered
std::string read_password() {
    struct termios oldt, newt;
    std::string password;

    // Get the current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Disable echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply new settings

    std::cout << "[))> Enter passphrase: ";

    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 127) { // Backspace
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
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

// Function to validate the user's password against the shadow file
bool validate_password(const std::string& username, const std::string& password) {
    struct passwd* pw = getpwnam(username.c_str());
    if (!pw) {
        std::cerr << "Error: User not found." << std::endl;
        return false;
    }

    struct spwd* sp = getspnam(username.c_str());
    if (!sp) {
        std::cerr << "Error: Unable to retrieve shadow entry for user." << std::endl;
        return false;
    }

    // Hash the entered password using the salt from the shadow entry
    char* encrypted = crypt(password.c_str(), sp->sp_pwdp);
    if (!encrypted) {
        std::cerr << "Error: Password encryption failed." << std::endl;
        return false;
    }

    // Compare the hashed password with the one from the shadow file
    return strcmp(encrypted, sp->sp_pwdp) == 0;
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

// Function to manage X11 authentication (for X11 environments)
void manage_xauth(const std::string& cookie_path) {
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        throw std::runtime_error("Unable to open X display");
    }

    // Get the display number
    int display_num = DefaultScreen(display);
    std::string display_name = ":0";

    // Generate a random X cookie
    unsigned char cookie[16];
    if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
        throw std::runtime_error("Failed to generate X cookie");
    }

    // Create and configure XAuth
    Xauth* auth = XauGetAuthByAddr(0, display_name.c_str(), display_num, display_name.c_str());
    if (!auth) {
        throw std::runtime_error("Failed to allocate XAuth structure");
    }

    auth->family = FamilyLocal;
    auth->number = std::to_string(display_num).c_str();  // Set display number
    auth->name_length = display_name.length();           // Length of display name
    auth->name = reinterpret_cast<unsigned char*>(const_cast<char*>(display_name.c_str()));  // Display name
    auth->data_length = sizeof(cookie);                  // Length of cookie
    auth->data = cookie;                                 // The cookie itself

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
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string username = getlogin();  // Get the current user
    std::string program = argv[1];

    // Check if the required commands exist
    if (!command_exists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Read password securely
    std::string password = read_password();

    // Validate the password
    if (!validate_password(username, password)) {
        std::cerr << "Error: Incorrect password." << std::endl;
        return EXIT_FAILURE;
    }

    // Manage X11 authentication (if necessary)
    std::string cookie_path = std::string(getenv("HOME")) + "/.Xauthority";
    manage_xauth(cookie_path);

    // Prepare command to run with root privileges
    std::vector<std::string> command;
    command.push_back(program);
    for (int i = 2; i < argc; ++i) {
        command.push_back(argv[i]);  // Add additional parameters if provided
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
