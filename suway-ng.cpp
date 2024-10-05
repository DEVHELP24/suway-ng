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
#include <sys/wait.h> // Required for waitpid

// Function to execute the user command, similar to sudo execution.
void execute_command(const std::vector<std::string>& cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process: Execute the command
        std::vector<char*> argv;
        for (const auto& arg : cmd) {
            argv.push_back(const_cast<char*>(arg.c_str())); // Convert std::string to char*
        }
        argv.push_back(nullptr); // Last argument must be nullptr for execvp
        execvp(argv[0], argv.data()); // Execute the command
        
        // If execvp fails, print the error and exit
        perror("execvp failed");
        exit(EXIT_FAILURE);
    } else if (pid < 0) {
        // Fork failed
        perror("fork failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process: Wait for the child to finish executing
        int status;
        waitpid(pid, &status, 0); // Wait for the child process to finish
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("Command execution failed");
        }
    }
}

// Function to manage X11 authentication using Xauth for X sessions.
void manage_xauth(const std::string& display_name, int display_num, const unsigned char* cookie) {
    // Fetch the Xauth structure for authentication based on display details.
    Xauth* auth = XauGetAuthByAddr(FamilyLocal, 0, nullptr, 
        static_cast<short unsigned int>(display_num), display_name.c_str(), 
        static_cast<short unsigned int>(display_name.size()), display_name.c_str());

    // If unable to retrieve the Xauth structure, throw an error.
    if (!auth) {
        throw std::runtime_error("Failed to allocate XAuth structure");
    }

    // Set the display number in the Xauth structure.
    auth->number = strdup(std::to_string(display_num).c_str());  // Convert int to string and duplicate it as char*
    
    // Set the display name.
    auth->name = strdup(display_name.c_str());                   // Duplicate the display name as char*

    // Set the authentication cookie.
    auth->data = reinterpret_cast<char*>(const_cast<unsigned char*>(cookie)); // Convert unsigned char* to char*

    // Further Xauth handling code can be added here.
    // For example, writing this auth to an Xauthority file.
}

// Function to validate the user's password against the shadow file.
bool validate_password(const std::string& username, const std::string& password) {
    // Retrieve the user's password entry from the shadow file.
    struct spwd* shadow_entry = getspnam(username.c_str());
    
    // If the username is not found in the shadow file, return false.
    if (!shadow_entry) {
        std::cerr << "User not found in shadow file" << std::endl;
        return false;
    }

    // Encrypt the provided password using the same salt and method as in the shadow file.
    const char* encrypted_password = crypt(password.c_str(), shadow_entry->sp_pwdp);

    // Compare the encrypted password with the stored hashed password.
    return encrypted_password && strcmp(encrypted_password, shadow_entry->sp_pwdp) == 0;
}

// Function to prompt the user to enter a password securely.
std::string get_password() {
    // Disable terminal echo for password input.
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Prompt the user to enter the password.
    std::cout << "Enter password: ";
    std::string password;
    std::getline(std::cin, password);

    // Restore terminal settings after password input.
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return password;
}

int main(int argc, char* argv[]) {
    // Ensure the user provided at least one argument (command to execute).
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <command> [args]" << std::endl;
        return 1;
    }

    // Retrieve the username of the current user.
    std::string username = getpwuid(getuid())->pw_name;

    // Prompt the user to enter the password.
    std::string password = get_password();

    // Validate the password against the shadow file.
    if (!validate_password(username, password)) {
        std::cerr << "Authentication failed. Incorrect password." << std::endl;
        return 1;
    }

    // If authentication succeeds, execute the provided command.
    std::vector<std::string> cmd;
    for (int i = 1; i < argc; ++i) {
        cmd.push_back(argv[i]);
    }

    try {
        execute_command(cmd);  // Execute the user command
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
