// SPDX-License-Identifier: MIT
// Maintainer: NAZY-OS
// This program manages X11 authentication and securely runs a command with user privileges.
// The goal is to authenticate and execute commands without using sudo, securely handling 
// user passwords and integrating Wayland where possible.

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
#include <openssl/rand.h>
#include <fstream>
#include <shadow.h>
#include <crypt.h>

// Function to securely read password with asterisks displayed on input
std::string read_password() {
    struct termios oldt, newt;
    std::string password;

    // Disable terminal echoing while reading the password
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::cout << "[))> Enter passphrase: ";

    char ch;
    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 127 || ch == '\b') {  // Handle backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Remove last asterisk
            }
        } else {
            password += ch;
            std::cout << '*';  // Print asterisk
        }
    }
    std::cout << std::endl;

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

// Function to validate the provided password with the system's /etc/shadow hashed password
bool validate_password(const std::string& username, const std::string& password) {
    struct spwd* pw = getspnam(username.c_str());
    if (!pw) {
        std::cerr << "[))> Error: User not found in shadow file." << std::endl;
        return false;
    }

    // Compare the provided password with the hashed one from the shadow file
    char* encrypted = crypt(password.c_str(), pw->sp_pwdp);
    return encrypted && strcmp(encrypted, pw->sp_pwdp) == 0;
}

// Function to execute a command passed by the user
void execute_command(const std::vector<std::string>& cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // In child process, prepare to execute the command
        std::vector<char*> argv;
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);  // Terminate the arguments list with nullptr

        execvp(argv[0], argv.data());  // Execute the command
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Handle fork failure
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else {
        // In parent process, wait for the child to finish execution
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Command execution failed");
        }
    }
}

// Function to manage X11 authentication and generate an X cookie
void manage_xauth(const std::string& cookie_path) {
    // Open X display for authentication
    Display* display = XOpenDisplay(nullptr);
    if (!display) {
        throw std::runtime_error("Unable to open X display");
    }

    // Get the display number
    int display_num = DefaultScreen(display);
    std::string display_name = ":0";  // Modify as needed

    // Generate a random X cookie using OpenSSL
    unsigned char cookie[16];
    if (RAND_bytes(cookie, sizeof(cookie)) != 1) {
        throw std::runtime_error("Failed to generate X cookie");
    }

    // Allocate Xauth manually
    Xauth* auth = (Xauth*)malloc(sizeof(Xauth));
    if (!auth) {
        throw std::runtime_error("Failed to allocate XAuth structure");
    }

    // Set authentication properties
    auth->family = FamilyLocal;  // Set the family (e.g., Local)

    // Convert display number to string
    std::string display_number_str = std::to_string(display_num);
    auth->number = strdup(display_number_str.c_str());  // Set display number as string

    auth->name_length = display_name.length();  // Set display name length
    auth->name = strdup(display_name.c_str());  // Set display name

    auth->data_length = sizeof(cookie);  // Set cookie length
    auth->data = reinterpret_cast<char*>(cookie);  // Set cookie data

    // Write the cookie to the Xauthority file
    FILE* xauth_file = fopen(cookie_path.c_str(), "a");
    if (xauth_file) {
        XauWriteAuth(xauth_file, auth);  // Write the Xauth data to the file
        fclose(xauth_file);
    } else {
        throw std::runtime_error("Failed to open X authority file");
    }

    // Free allocated memory
    if (auth->number) free(auth->number);
    if (auth->name) free(auth->name);
    free(auth);

    XCloseDisplay(display);
}

// Function to check if a command exists in the PATH
bool command_exists(const std::string& cmd) {
    return system(("command -v " + cmd + " > /dev/null 2>&1").c_str()) == 0;
}

// Main function to manage user authentication and command execution
int main(int argc, char* argv[]) {
    // Check if the program is executed with enough arguments
    if (argc < 2) {
        std::cerr << "[))> No program found to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];
    std::string username = getenv("USER");

    // Check if required command 'xauth' exists
    if (!command_exists("xauth")) {
        std::cerr << "[))> Missing dependency: xauth" << std::endl;
        return EXIT_FAILURE;
    }

    // Securely read the password from the user
    std::string password = read_password();

    // Validate the password using the shadow file
    if (!validate_password(username, password)) {
        std::cerr << "[))> Error: Incorrect password." << std::endl;
        return EXIT_FAILURE;
    }

    // Manage X11 authentication
    std::string cookie_path = std::string(getenv("HOME")) + "/.Xauthority";
    manage_xauth(cookie_path);

    // Prepare the command with user-provided parameters (if any)
    std::vector<std::string> command = { program };
    for (int i = 2; i < argc; ++i) {
        command.push_back(argv[i]);
    }

    // Execute the command securely
    try {
        execute_command(command);
        std::cout << "[))> Execution finished with no errors!" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "[))> Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
