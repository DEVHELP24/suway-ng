#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <termios.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <fstream>

using namespace std;

// Function to display help message
void displayHelp() {
    cout << "Usage: suway-ng <program-name> [program-args...]" << endl;
    cout << "Run a specified program with the appropriate permissions." << endl;
    cout << "Options:" << endl;
    cout << "  -h, --help    Show this help message and exit." << endl;
    cout << endl;
    cout << "Example:" << endl;
    cout << "  suway-ng my_program -arg1 -arg2" << endl;
}

// Function to securely read password with asterisks
string readPassword() {
    struct termios oldt, newt;
    int ch;
    string password;

    // Turn echoing off
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    cout << "[))> Enter passphrase: ";
    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch == 127) {  // Handle backspace
            if (!password.empty()) {
                cout << "\b \b";
                password.pop_back();
            }
        } else {
            password.push_back(ch);
            cout << '*';  // Display asterisks
        }
    }

    cout << endl;

    // Restore echoing
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}

// Function to set environment variables
void setEnvironmentVariables(const string& display) {
    setenv("DISPLAY", display.c_str(), 1);

    // Set QT environment variables only if DISPLAY is set
    if (!display.empty()) {
        setenv("QT_QPA_PLATFORMTHEME", "qt5ct", 1);
        setenv("QT_QPA_PLATFORM", "wayland;xcb", 1);
    }
}

// Function to create X authority using xauth
bool createXauthCookie(const string& myxcookie) {
    string cmd = "xauth add $(uname -n)${DISPLAY} . $(xxd -l 16 -p /dev/urandom)";
    string cmd_extract = "xauth extract " + myxcookie + " $(uname -n)${DISPLAY}";

    if (system(cmd.c_str()) != 0 || system(cmd_extract.c_str()) != 0) {
        cerr << "[))> Error creating xauth cookie!" << endl;
        return false;
    }

    string cmd_setfacl = "setfacl -m u:" + string(getenv("USER")) + ":r " + myxcookie;
    if (system(cmd_setfacl.c_str()) != 0) {
        cerr << "[))> Error setting file permissions for xcookie!" << endl;
        return false;
    }

    string cmd_merge = "xauth merge " + myxcookie;
    if (system(cmd_merge.c_str()) != 0) {
        cerr << "[))> Error merging xauth cookie!" << endl;
        return false;
    }

    return true;
}

// Function to run a command using sudo
bool runWithSudo(const string& command, const string& password) {
    string sudoCommand = "echo " + password + " | sudo -E -S bash -c '" + command + "'";
    return system(sudoCommand.c_str()) == 0;
}

// Function to run a command using xhost method
bool runWithXhost(const string& command, const string& myxcookie, const string& password) {
    if (!createXauthCookie(myxcookie)) {
        return false;
    }

    string suCommand = "echo " + password + " | su -c '" + command + "'";
    return system(suCommand.c_str()) == 0;
}

// Function to clean up environment and sensitive data
void cleanUp(const string& myxcookie) {
    unsetenv("DISPLAY");
    unsetenv("QT_QPA_PLATFORMTHEME");
    unsetenv("QT_QPA_PLATFORM");

    remove(myxcookie.c_str());  // Remove the X cookie file
}

// Function to kill processes with a matching name
void killProcesses(const string& processName) {
    string killCmd = "ps -ef | grep -E \"" + processName + "\" | grep -v grep | awk '{print $2}' | xargs kill -9";
    system(killCmd.c_str());
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "[))> No program name provided!" << endl;
        displayHelp();
        return 1;
    }

    // Display help if requested
    string firstArg = argv[1];
    if (firstArg == "-h" || firstArg == "--help") {
        displayHelp();
        return 0;
    }

    string main_program = firstArg;
    string myxcookie = string(getenv("HOME")) + "/my-x-cookie";

    // Set environment variables
    setEnvironmentVariables(string(getenv("DISPLAY")));

    // Read the password from the user
    string password = readPassword();

    // Prepare command to run
    string command = main_program;
    for (int i = 2; i < argc; ++i) {
        command += " ";
        command += argv[i];
    }

    // First try to run with sudo
    if (!runWithSudo(command, password)) {
        cerr << "[))> Failed to run with sudo, trying xhost method!" << endl;
        if (!runWithXhost(command, myxcookie, password)) {
            cerr << "[))> Both sudo and xhost methods failed!" << endl;
            cleanUp(myxcookie);
            return 1;
        }
    }

    // Kill matching processes
    killProcesses(main_program);

    // Clean up and remove sensitive data
    cleanUp(myxcookie);
    password.clear();  // Clear password from memory

    cout << "[))> Program executed successfully!" << endl;
    return 0;
}
