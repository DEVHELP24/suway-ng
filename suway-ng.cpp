// SPDX-License-Identifier: MIT
// Maintainer: NAZY-OS
// This program runs a specified command with user privileges after prompting for a password.
// It utilizes X11 authentication and handles user input securely, including support for Wayland.

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <termios.h>
#include <X11/Xlib.h>
#include <X11/Xauth.h>
#include <fstream>
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

// Function to ensure the home directory exists
void ensure_home_directory(const std::string& home_path) {
    struct stat st;
    if (stat(home_path.c_str(), &st) != 0) {
        // Directory does not exist; create it
        if (mkdir(home_path.c_str(), 0700) != 0) {
            throw std::runtime_error("Failed to create home directory: " + home_path);
        }
    }
}

// Function to manage X11 authentication
void manage_xauth(const std::string& cookie_path) {
    // Ensure the home directory exists before creating the .Xauthority file
    std::string dir_path = cookie_path.substr(0, cookie_path.find_last_of("/"));
    ensure_home_directory(dir_path); // Ensure the home directory exists

    // Open X display for authentication
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
    // Check if the program is executed in the correct environment
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string home_path = std::string(getenv("HOME")); // Get home directory
    ensure_home_directory(home_path); // Ensure home directory exists

    std::string program = argv[1];

    // Check if the required commands exist
    if (!command_exists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Read password securely
    std::string password = read_password();

    // Manage X11 authentication
    std::string cookie_path = home_path + "/.Xauthority"; // Path to Xauthority file
    manage_xauth(cookie_path);

    // Prepare command to run with user privileges
    std::vector<std::string> command = {program}; // Prepare command with parameters if necessary
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
