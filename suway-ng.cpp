// SPDX-License-Identifier: MIT
// Maintainer: NAZY-OS
// 
// suway-ng: A secure command execution program with X11 authentication.
// 
// This program securely executes a specified command with elevated privileges after 
// prompting the user for a password. It utilizes X11 authentication to manage 
// access securely. The program features:
// - Secure password input without echoing characters.
// - X11 cookie management for display access.
// - Command execution in a forked process to prevent blocking the main program.
// 
// Dependencies: Ensure 'xauth' is installed on your system for X11 authentication.

#include <iostream>       // For input and output streams
#include <cstdlib>       // For general purpose functions (exit, getenv)
#include <cstring>       // For string handling
#include <unistd.h>      // For fork, execvp, and other POSIX API
#include <sys/types.h>   // For data types used in system calls
#include <sys/wait.h>    // For waiting on child processes
#include <signal.h>      // For signal handling
#include <fcntl.h>       // For file control operations
#include <stdexcept>     // For exception handling
#include <string>        // For using std::string
#include <vector>        // For using std::vector
#include <termios.h>     // For terminal I/O settings
#include <sys/stat.h>    // For file status operations
#include <X11/Xlib.h>    // For X11 library functions
#include <X11/Xauth.h>   // For X11 authentication functions
#include <fstream>       // For file stream operations
#include <openssl/rand.h> // For generating random bytes

// Function to securely read a password from the terminal without echoing the input
std::string read_password() {
    struct termios oldt, newt; // Structures to hold terminal settings
    std::string password; // String to hold the password input

    // Get the current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Disable echoing input characters
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply the new settings

    std::cout << "[))> Enter passphrase: "; // Prompt user for password

    char ch;
    while (std::cin.get(ch) && ch != '\n') { // Read input character by character
        if (ch == 127) { // Check for backspace
            if (!password.empty()) { // Remove last character if password is not empty
                password.pop_back();
                std::cout << "\b \b"; // Erase last asterisk from display
            }
        } else {
            password += ch; // Add character to password
            std::cout << '*'; // Show asterisk for each character
        }
    }
    std::cout << std::endl; // New line after password entry

    // Restore old terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password; // Return the entered password
}

// Function to execute a command in a child process
void execute_command(const std::vector<std::string>& cmd) {
    pid_t pid = fork(); // Create a new process
    if (pid == 0) { // In child process
        std::vector<char*> argv; // Vector to hold command arguments
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str())); // Convert string to char*
        }
        argv.push_back(nullptr); // Last argument must be nullptr for execvp
        execvp(argv[0], argv.data()); // Execute the command
        // If execvp fails
        perror("execvp failed"); // Print error message
        exit(EXIT_FAILURE); // Exit child process on failure
    } else if (pid < 0) { // Fork failed
        perror("fork failed"); // Print error message
        exit(EXIT_FAILURE); // Exit on fork failure
    } else { // In parent process
        int status;
        waitpid(pid, &status, 0); // Wait for the child process to finish
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Command execution failed"); // Throw exception on failure
        }
    }
}

// Function to manage X11 authentication and create/update the .Xauthority file
void manage_xauth(const std::string& cookie_path) {
    // Open the X display
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        throw std::runtime_error("Unable to open X display"); // Throw exception if display fails to open
    }

    // Get the display number
    int display_num = DefaultScreen(display);
    std::string display_name = ":0"; // Modify this as needed for your environment

    // Generate a random X cookie
    unsigned char cookie[16];
    if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
        throw std::runtime_error("Failed to generate X cookie"); // Throw exception on failure
    }

    // Create and configure the XAuth structure
    Xauth* auth = XAllocAuth();
    if (!auth) {
        throw std::runtime_error("Failed to allocate XAuth structure"); // Throw exception on failure
    }

    // Set up the XAuth fields
    auth->family = FamilyLocal; // Set the family to local
    auth->number = display_num; // Set display number (typically 0)
    auth->name_length = display_name.length(); // Set the length of the display name
    auth->name = reinterpret_cast<unsigned char*>(const_cast<char*>(display_name.c_str())); // Set the display name
    auth->data_length = sizeof(cookie); // Set the length of the cookie
    auth->data = cookie; // Set the cookie itself

    // Open the Xauthority file for writing
    FILE* xauth_file = fopen(cookie_path.c_str(), "a");
    if (xauth_file) {
        XauWriteAuth(xauth_file, auth); // Write the cookie to the file
        fclose(xauth_file); // Close the file
    } else {
        throw std::runtime_error("Failed to open X authority file"); // Throw exception on failure
    }

    XFree(auth); // Free the XAuth structure
    XCloseDisplay(display); // Close the display
}

// Function to check if a command exists in the PATH
bool command_exists(const std::string& cmd) {
    return system(("command -v " + cmd + " > /dev/null 2>&1").c_str()) == 0; // Check command existence
}

// Main function
int main(int argc, char* argv[]) {
    // Check if the program is executed with a command
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl; // Error message if no command is given
        return EXIT_FAILURE; // Exit with failure
    }

    std::string program = argv[1]; // Get the program name from arguments

    // Check if the required 'xauth' command exists
    if (!command_exists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl; // Error message for missing dependency
        return EXIT_FAILURE; // Exit with failure
    }

    // Read the password securely
    std::string password = read_password();

    // Manage X11 authentication
    std::string cookie_path = std::string(getenv("HOME")) + "/.Xauthority"; // Path to Xauthority file
    manage_xauth(cookie_path); // Call function to manage X11 authentication

    // Prepare command to run with elevated privileges using sudo
    std::vector<std::string> command = {"sudo", program};

    // Execute the command and handle errors
    try {
        execute_command(command); // Call function to execute command
        std::cout << "[))> Execution finished with no errors!" << std::endl; // Success message
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl; // Print error message if execution fails
        return EXIT_FAILURE; // Exit with failure
    }

    return EXIT_SUCCESS; // Exit successfully
}
