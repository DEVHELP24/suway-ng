// SPDX-License-Identifier: MIT
// Maintainer: [NAZY-OS]
// This program validates a user's password against the system's password database 
// and executes a specified command with appropriate display access, 
// supporting both Wayland and X11 environments.

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <termios.h>
#include <pwd.h>
#include <crypt.h>
#include <fstream>
#include <X11/Xlib.h>
#include <X11/Xauth.h>
#include <wayland-client.h>

constexpr size_t MAX_PASSWORD_LENGTH = 128; // Max password length

// Function to read password securely
std::string read_password() {
    struct termios oldt, newt;
    std::string password;

    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply new settings

    std::cout << "[))> Enter passphrase: ";
    
    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 127) { // Backspace handling
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Remove last character
            }
        } else if (password.length() < MAX_PASSWORD_LENGTH) { // Prevent overflow
            password += ch;
            std::cout << '*'; // Display asterisk
        }
    }
    std::cout << std::endl;

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

// Function to validate password
bool validate_password(const std::string& username, const std::string& password) {
    struct passwd* pwd = getpwnam(username.c_str());
    if (!pwd) {
        std::cerr << "[))> User not found: " << username << std::endl;
        return false;
    }
    
    // Hash input password and compare
    std::string hashed_input = crypt(password.c_str(), pwd->pw_passwd);
    return (hashed_input == pwd->pw_passwd);
}

// Function to execute a command
void execute_command(const std::vector<std::string>& cmd) {
    pid_t pid = fork();
    if (pid == 0) { // Child process
        std::vector<char*> argv;
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str())); // Convert to char*
        }
        argv.push_back(nullptr); // Null-terminate the argument list
        
        execvp(argv[0], argv.data()); // Execute command
        perror("Execution failed"); // Handle execution error
        exit(EXIT_FAILURE);
    } else if (pid < 0) { // Fork failed
        perror("Fork failed");
        exit(EXIT_FAILURE);
    } else { // Parent process
        int status;
        waitpid(pid, &status, 0); // Wait for child to finish
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Command execution failed");
        }
    }
}

// Function to manage X11 authentication
void manage_xauth(const std::string& cookie_path) {
    Display* display = XOpenDisplay(nullptr);
    if (!display) throw std::runtime_error("Unable to open X display");

    // Create or update .Xauthority
    Xauth* auth = XauGetBestAuthByAddr(nullptr, DefaultScreen(display), nullptr, 0);
    if (!auth) {
        XCloseDisplay(display);
        throw std::runtime_error("Failed to get Xauth entry");
    }

    // Open .Xauthority in append mode
    FILE* xauth_file = fopen(cookie_path.c_str(), "ab");
    if (!xauth_file) {
        XFree(auth);
        XCloseDisplay(display);
        throw std::runtime_error("Failed to open X authority file");
    }

    // Write authentication data
    if (XauWriteAuth(xauth_file, auth) < 0) {
        fclose(xauth_file);
        XFree(auth);
        XCloseDisplay(display);
        throw std::runtime_error("Failed to write to X authority file");
    }

    fclose(xauth_file);
    XFree(auth);
    XCloseDisplay(display);
}

// Function to connect to Wayland
void connect_to_wayland() {
    struct wl_display* display = wl_display_connect(nullptr);
    if (!display) throw std::runtime_error("Failed to connect to Wayland display");
    std::cout << "[))> Successfully connected to Wayland!" << std::endl;
    
    // Placeholder for future Wayland functionalities
    wl_display_disconnect(display); // Clean up
}

// Function to check if a command exists in the PATH
bool command_exists(const std::string& cmd) {
    return system(("command -v " + cmd + " > /dev/null 2>&1").c_str()) == 0;
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 2) { // Check for command argument
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];
    char* username_env = getenv("USER"); // Get current username
    if (!username_env) {
        std::cerr << "[))> USER environment variable not set." << std::endl;
        return EXIT_FAILURE;
    }
    std::string username = username_env;

    if (!command_exists("xauth")) { // Check for xauth
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Read password securely
    std::string password = read_password();

    // Validate user password
    if (!validate_password(username, password)) {
        std::cerr << "[))> Invalid password!" << std::endl;
        return EXIT_FAILURE;
    }

    // Manage X11 authentication
    std::string cookie_path = std::string(getenv("HOME")) + "/.Xauthority";
    try {
        manage_xauth(cookie_path);
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    // Connect to Wayland
    try {
        connect_to_wayland();
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    // Prepare and execute the command
    try {
        execute_command({program});
        std::cout << "[))> Execution finished successfully!" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
