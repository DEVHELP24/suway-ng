// SPDX-License-Identifier: MIT
// Maintainer: [NAZY-OS]
// This program validates a user's password against the system's password database 
// and executes a specified command with the appropriate display access, 
// supporting both Wayland and X11 environments.

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
#include <fstream>
#include <crypt.h>
#include <pwd.h>
#include <wayland-client.h>

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

// Function to validate the provided password against the user's hashed password
bool validate_password(const std::string& username, const std::string& password) {
    struct passwd* pwd = getpwnam(username.c_str());
    if (pwd == nullptr) {
        std::cerr << "[))> User not found: " << username << std::endl;
        return false;
    }

    // Hash the input password with the stored salt and compare
    std::string hashed_input = crypt(password.c_str(), pwd->pw_passwd);
    return (hashed_input == pwd->pw_passwd);
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

    // Create XAuth entry
    Xauth* auth = XauGetAuthByAddr(0, display_name.c_str(), display_num, display_name.c_str());

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

// Function to establish a Wayland connection
void connect_to_wayland() {
    struct wl_display* display = wl_display_connect(nullptr);
    if (!display) {
        throw std::runtime_error("Failed to connect to Wayland display");
    }
    std::cout << "[))> Successfully connected to Wayland!" << std::endl;

    // Placeholder for future Wayland functionalities
    // Here you can add code to create a Wayland surface or other objects

    // Clean up
    wl_display_disconnect(display);
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

    std::string program = argv[1];
    std::string username = getenv("USER"); // Get current username

    // Check if the required commands exist
    if (!command_exists("xauth")) {
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
    manage_xauth(cookie_path);

    // Connect to Wayland
    try {
        connect_to_wayland();
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    // Prepare command to run
    std::vector<std::string> command = {program};

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
