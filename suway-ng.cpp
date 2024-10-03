#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#define COMMAND_LENGTH 256

// SPDX-License-Identifier: MIT
// Maintainer: [NAZY-OS]
// This program kills all processes that match the given program names.
// Usage: suway-ng <program-name>

std::string getPID(const std::string& program) {
    std::string command = "ps -ef | grep -E 'suway " + program + "' | grep -v grep | awk '{print $2}'";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return "";
    
    char buffer[COMMAND_LENGTH];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

void handleSignal(int signal) {
    std::cout << "\nsuway closed!!" << std::endl;
    exit(0);
}

void runCommand(const std::string& cmd) {
    system(cmd.c_str());
}

std::string readPassword() {
    std::string password;
    char ch;
    std::cout << "[))> Enter passphrase: ";
    while ((ch = getchar()) != '\n') {
        if (ch == 127) { // Handle backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Erase character
            }
        } else {
            password += ch;
            std::cout << '*'; // Mask input
        }
    }
    std::cout << std::endl;
    return password;
}

bool xauthCreate(const std::string& myxcookie) {
    std::string command = "xauth add \"$(uname -n)\" . \"$(xxd -l 16 -p /dev/urandom)\"";
    runCommand(command);
    command = "xauth extract " + myxcookie + " \"$(uname -n)\"";
    runCommand(command);
    command = "setfacl -m u:" + std::string(getpwuid(getuid())->pw_name) + ":r " + myxcookie;
    runCommand(command);
    return true;
}

bool runWithSudo(const std::string& command) {
    std::string fullCommand = "sudo -E " + command;
    return system(fullCommand.c_str()) == 0;
}

bool runWithXauth(const std::string& command, const std::string& myxcookie) {
    if (!xauthCreate(myxcookie)) return false;
    return runWithSudo(command);
}

bool checkDependencies() {
    return system("which xauth &> /dev/null") == 0;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handleSignal);

    if (argc < 2) {
        std::cerr << "[))> No program found to run with suway!" << std::endl;
        return 1;
    }

    std::string mainProgram = argv[1];
    std::string myxcookie = std::string(getpwuid(getuid())->pw_dir) + "/my-x-cookie";

    // Check for dependencies
    if (!checkDependencies()) {
        std::cerr << "To use suway, please install xorg-xauth!" << std::endl;
        return 1;
    }

    // Get the PID of the process
    std::string pid = getPID(mainProgram);
    std::cout << "suway PID: " << pid << std::endl;

    // Read the password
    std::string password = readPassword();

    // Attempt to run the program with xauth
    if (runWithXauth(mainProgram, myxcookie)) {
        std::cout << "[))> suway execution finished with no errors!" << std::endl;
    } else {
        std::cerr << "[))> suway execution encountered an issue!" << std::endl;
        return 1;
    }

    // Clear sensitive variables
    password.clear();
    return 0;
}
