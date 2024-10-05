#include <iostream>
#include <cstdlib>
#include <string>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <vector>
#include <cstring>

// Function to read a password securely with asterisks as feedback
std::string readPassword() {
    std::string password;
    char ch;

    std::cout << "[))> Enter passphrase: ";
    while (true) {
        ch = getchar();
        // Check for Enter key
        if (ch == '\n' || ch == '\r') {
            break;
        } 
        // Check for Backspace key
        else if (ch == 127 || ch == '\b') { 
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Move back, overwrite with space, move back again
            }
        } 
        // Capture other characters
        else {
            password += ch;
            std::cout << '*'; // Show asterisk for each character
        }
    }
    std::cout << std::endl; // New line after password input
    return password;
}

// Function to create X authentication
bool createXAuth() {
    const char* display = getenv("DISPLAY");
    std::string command;

    if (display) {
        command = "xauth add " + std::string(display) + " . $(xxd -l 16 -p /dev/urandom)";
        return system(command.c_str()) != -1; // Return success if the command executes successfully
    }
    return false; // Fail if DISPLAY is not set
}

// Function to grant access to the local user using xhost
bool xhostAccess(const std::string& user) {
    std::string command = "xhost +SI:localuser:" + user; // Limit access to local user only
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to extract X cookie to a temporary file
bool extractXCookie(const std::string& cookieFile) {
    std::string command = "xauth extract " + cookieFile + " $DISPLAY"; // Extract cookie for the current display
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to merge the extracted X cookie
bool mergeXCookie(const std::string& cookieFile) {
    std::string command = "xauth merge " + cookieFile; // Merge the extracted cookie back into X authority
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to run a command securely without system()
bool runCommand(const std::string& command) {
    std::vector<std::string> args;
    std::string::size_type pos = 0, prevPos = 0;

    // Tokenize the command string to separate the command and its arguments
    while ((pos = command.find(' ', prevPos)) != std::string::npos) {
        args.push_back(command.substr(prevPos, pos - prevPos));
        prevPos = pos + 1;
    }
    args.push_back(command.substr(prevPos)); // Push the last token

    // Prepare arguments for execvp
    std::vector<char*> cArgs;
    for (auto& arg : args) {
        cArgs.push_back(const_cast<char*>(arg.c_str()));
    }
    cArgs.push_back(nullptr); // Null-terminate the array

    pid_t pid = fork();
    if (pid == 0) {
        // Child process: Execute the command
        execvp(cArgs[0], cArgs.data());
        // If execvp returns, an error occurred
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Fork failed
        perror("fork failed");
        return false;
    } else {
        // Parent process: Wait for the child to complete
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0; // Return true if the command executed successfully
    }
}

int main(int argc, char* argv[]) {
    // Check if a command was provided
    if (argc < 2) {
        std::cerr << "[!!] No command provided to run." << std::endl;
        return 1;
    }

    // Get display environment variable
    const char* display = getenv("DISPLAY");
    const char* wayland_display = getenv("WAYLAND_DISPLAY");

    // Display which server is being used
    if (display) {
        std::cout << "[))> Using X11 display: " << display << std::endl;
    } else if (wayland_display) {
        std::cout << "[))> Using Wayland display: " << wayland_display << std::endl;
    } else {
        std::cerr << "[!!] No display server found. Exiting." << std::endl;
        return 1;
    }

    // Read password from the user
    std::string password = readPassword();

    // Create X authentication if necessary
    if (display && !createXAuth()) {
        std::cerr << "[!!] Failed to create X authority." << std::endl;
        return 1;
    }

    // Grant access to the local user for X11
    const char* user = getenv("USER");
    if (user && !xhostAccess(user)) {
        std::cerr << "[!!] Failed to set xhost access." << std::endl;
        return 1;
    }

    // Extract X cookie to a temporary file
    std::string cookieFile = "/tmp/xauth_cookie";
    if (!extractXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to extract X cookie." << std::endl;
        return 1;
    }

    // Merge the extracted cookie back
    if (!mergeXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to merge X cookie." << std::endl;
        return 1;
    }

    // Construct the command to run
    std::string command = argv[1]; // The command to execute
    std::cout << "[))> Running command: " << command << std::endl;

    // Execute the command securely
    if (!runCommand(command)) {
        std::cerr << "[!!] Command execution failed." << std::endl;
        return 1;
    }

    std::cout << "[))> Command executed successfully!" << std::endl;
    return 0;
}
#include <iostream>
#include <cstdlib>
#include <string>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <vector>
#include <cstring>

// Function to read a password securely and display asterisks for each character entered
std::string readPassword() {
    std::string password; // To store the entered password
    char ch; // Variable to capture each character

    std::cout << "[))> Enter passphrase: "; // Prompt the user for password
    while (true) {
        ch = getchar(); // Read a character
        // Check for Enter key to finish password input
        if (ch == '\n' || ch == '\r') {
            break;
        } 
        // Check for Backspace key to remove last character
        else if (ch == 127 || ch == '\b') { 
            if (!password.empty()) {
                password.pop_back(); // Remove last character from password
                std::cout << "\b \b"; // Move back, overwrite with space, move back again
            }
        } 
        // Capture other characters
        else {
            password += ch; // Add character to password
            std::cout << '*'; // Show asterisk for each character
        }
    }
    std::cout << std::endl; // New line after password input
    return password; // Return the captured password
}

// Function to create X authentication for the current user session
bool createXAuth() {
    const char* display = getenv("DISPLAY"); // Get the DISPLAY environment variable
    std::string command;

    if (display) {
        // Command to add a magic cookie for X authentication
        command = "xauth add " + std::string(display) + " . $(xxd -l 16 -p /dev/urandom)";
        return system(command.c_str()) != -1; // Return success if the command executes successfully
    }
    return false; // Fail if DISPLAY is not set
}

// Function to grant access to the local user for X11 sessions using xhost
bool xhostAccess(const std::string& user) {
    std::string command = "xhost +SI:localuser:" + user; // Allow the specified local user access
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to extract the X cookie to a temporary file for session access
bool extractXCookie(const std::string& cookieFile) {
    std::string command = "xauth extract " + cookieFile + " $DISPLAY"; // Extract cookie for the current display
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to merge the extracted X cookie back into X authority for session authentication
bool mergeXCookie(const std::string& cookieFile) {
    std::string command = "xauth merge " + cookieFile; // Merge the extracted cookie back into X authority
    return system(command.c_str()) != -1; // Return success if the command executes successfully
}

// Function to run a command securely without using system() to prevent injection attacks
bool runCommand(const std::string& command) {
    std::vector<std::string> args; // Vector to hold command and its arguments
    std::string::size_type pos = 0, prevPos = 0;

    // Tokenize the command string to separate the command and its arguments
    while ((pos = command.find(' ', prevPos)) != std::string::npos) {
        args.push_back(command.substr(prevPos, pos - prevPos)); // Push each token into args
        prevPos = pos + 1; // Update position
    }
    args.push_back(command.substr(prevPos)); // Push the last token

    // Prepare arguments for execvp
    std::vector<char*> cArgs; // Vector to hold char* for execvp
    for (auto& arg : args) {
        cArgs.push_back(const_cast<char*>(arg.c_str())); // Convert std::string to char*
    }
    cArgs.push_back(nullptr); // Null-terminate the array for execvp

    pid_t pid = fork(); // Create a new process
    if (pid == 0) {
        // Child process: Execute the command
        execvp(cArgs[0], cArgs.data()); // Execute the command
        // If execvp returns, an error occurred
        perror("execvp failed"); // Print error message
        exit(EXIT_FAILURE); // Exit child process on error
    } else if (pid < 0) {
        // Fork failed
        perror("fork failed"); // Print error message
        return false; // Return false to indicate failure
    } else {
        // Parent process: Wait for the child to complete
        int status;
        waitpid(pid, &status, 0); // Wait for the child process
        return WIFEXITED(status) && WEXITSTATUS(status) == 0; // Return true if the command executed successfully
    }
}

int main(int argc, char* argv[]) {
    // Check if a command was provided as an argument
    if (argc < 2) {
        std::cerr << "[!!] No command provided to run." << std::endl; // Error message for no command
        return 1; // Exit with an error code
    }

    // Get display environment variable
    const char* display = getenv("DISPLAY");
    const char* wayland_display = getenv("WAYLAND_DISPLAY");

    // Display which server is being used
    if (display) {
        std::cout << "[))> Using X11 display: " << display << std::endl; // Inform user of X11 usage
    } else if (wayland_display) {
        std::cout << "[))> Using Wayland display: " << wayland_display << std::endl; // Inform user of Wayland usage
    } else {
        std::cerr << "[!!] No display server found. Exiting." << std::endl; // Error if no display server is found
        return 1; // Exit with an error code
    }

    // Read password from the user
    std::string password = readPassword(); // Capture user password securely

    // Create X authentication if necessary
    if (display && !createXAuth()) {
        std::cerr << "[!!] Failed to create X authority." << std::endl; // Error creating X authority
        return 1; // Exit with an error code
    }

    // Grant access to the local user for X11
    const char* user = getenv("USER"); // Get current user
    if (user && !xhostAccess(user)) {
        std::cerr << "[!!] Failed to set xhost access." << std::endl; // Error setting xhost access
        return 1; // Exit with an error code
    }

    // Extract X cookie to a temporary file
    std::string cookieFile = "/tmp/xauth_cookie"; // Temporary file to store X cookie
    if (!extractXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to extract X cookie." << std::endl; // Error extracting X cookie
        return 1; // Exit with an error code
    }

    // Merge the extracted cookie back
    if (!mergeXCookie(cookieFile)) {
        std::cerr << "[!!] Failed to merge X cookie." << std::endl; // Error merging X cookie
        return 1; // Exit with an error code
    }

    // Construct the command to run
    std::string command = argv[1]; // The command to execute from user input
    std::cout << "[))> Running command: " << command << std::endl; // Inform user of the command being run

    // Execute the command securely
    if (!runCommand(command)) {
        std::cerr << "[!!] Command execution failed." << std::endl; // Error executing command
        return 1; // Exit with an error code
    }

    std::cout << "[))> Command executed successfully!" << std::endl; // Confirmation of successful execution
    return 0; // Exit successfully
}
