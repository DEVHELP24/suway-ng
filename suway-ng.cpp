#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <termios.h>

// Function to execute system commands and capture output
std::string execCommand(const std::string &cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// Function to create and configure X authentication (without elevated permissions)
void createXauth(const std::string &myxcookie) {
    std::string display = getenv("DISPLAY") ? getenv("DISPLAY") : ":0";
    std::string hostname = execCommand("uname -n");
    hostname.erase(std::remove(hostname.begin(), hostname.end(), '\n'), hostname.end());

    std::string cmd1 = "xauth add " + hostname + display + " . $(xxd -l 16 -p /dev/urandom)";
    std::string cmd2 = "xauth extract " + myxcookie + " " + hostname + display;

    system(cmd1.c_str());
    system(cmd2.c_str());

    std::cout << "[))> Xauth created and cookie extracted for X11!" << std::endl;
}

// Function to run commands with the Xauth cookie set
void runWithXauth(const std::string &myxcookie, const std::string &command) {
    setenv("DISPLAY", ":0", 1);  // Ensure DISPLAY is set to the correct value
    std::string cmd = "xauth merge " + myxcookie + " && " + command;
    system(cmd.c_str());
}

// Function to find Wayland display
std::string findWaylandDisplay() {
    const char* runtimeDir = getenv("XDG_RUNTIME_DIR");
    if (!runtimeDir) {
        std::cerr << "Error: XDG_RUNTIME_DIR is not set!" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string findCommand = "find " + std::string(runtimeDir) + "/wayland-* | grep -v '.lock'";
    std::string waylandDisplay = execCommand(findCommand);

    if (!waylandDisplay.empty()) {
        waylandDisplay.erase(std::remove(waylandDisplay.begin(), waylandDisplay.end(), '\n'), waylandDisplay.end());
        return waylandDisplay;
    }

    return "";
}

// Function to read password securely, showing asterisks for each character
std::string readPassword() {
    std::string password;
    char ch;
    
    std::cout << "[))> Enter password: ";
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);  // Disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127 || ch == '\b') {  // Handle backspace
            if (password.length() > 0) {
                password.pop_back();
                std::cout << "\b \b";  // Move back, overwrite with space, and move back again
            }
        } else {
            password += ch;
            std::cout << '*';  // Show an asterisk
        }
    }

    std::cout << std::endl;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);  // Restore old terminal settings
    return password;
}

// Function to run commands with sudo
void runWithSudo(const std::string &command) {
    std::string sudoCmd = "sudo " + command;
    system(sudoCmd.c_str());
}

// Main program logic
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "[))> No program specified to run!" << std::endl;
        return EXIT_FAILURE;
    }

    std::string program = argv[1];
    std::string myxcookie = std::string(getenv("HOME")) + "/my-x-cookie";

    // Set environment variables for Wayland and Qt
    setenv("QT_QPA_PLATFORMTHEME", "qt5ct", 1);
    setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);

    // Try to find Wayland display
    std::string waylandDisplay = findWaylandDisplay();
    if (!waylandDisplay.empty()) {
        setenv("WAYLAND_DISPLAY", waylandDisplay.c_str(), 1);
        std::cout << "[))> Wayland display set to: " << waylandDisplay << std::endl;
    } else {
        std::cout << "[))> No Wayland display found. Falling back to X11." << std::endl;
        createXauth(myxcookie);  // Create X11 Xauth cookie
        runWithXauth(myxcookie, program);  // Run with Xauth for X11
    }

    // Prompt for password and run the program with sudo for root privileges
    std::string password = readPassword();
    std::string command = program;  // The command to run with sudo
    runWithSudo(command);  // Run the program with sudo

    // Clear sensitive data
    std::cout << "[))> Program execution finished." << std::endl;
    return 0;
}
