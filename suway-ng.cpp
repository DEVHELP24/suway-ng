#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>
#include <cstring>
#include <sys/stat.h>

// Function to handle and display errors
void handleError(const std::string &message) {
    std::cerr << "[))> Error: " << message << std::endl;
    exit(EXIT_FAILURE);
}

// Function to check if the program name contains only valid characters
bool isValidProgramName(const std::string& name) {
    for (char c : name) {
        if (!isalnum(c) && c != '-' && c != '_' && c != '.') {
            return false;
        }
    }
    return true;
}

// Function to get the current user's home directory
std::string getUserHomeDirectory() {
    const char *homeDir = getenv("HOME");
    if (!homeDir) {
        struct passwd *pw = getpwuid(getuid());
        homeDir = pw->pw_dir;
    }
    return std::string(homeDir);
}

// Function to securely capture the password
void securePasswordInput(std::string &password) {
    password.clear();
    char ch;
    std::cout << "[))> Enter passphrase: ";
    while ((ch = getchar()) != '\n' && ch != EOF) {
        password.push_back(ch);
        std::cout << "*";
    }
    std::cout << std::endl;
}

// Function to kill processes by their PID
void killProcesses(const std::string &processName) {
    std::string command = "pgrep " + processName;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        handleError("Failed to execute pgrep command.");
    }

    char buffer[128];
    std::vector<pid_t> pids;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        pid_t pid = std::stoi(buffer);
        pids.push_back(pid);
    }
    pclose(pipe);

    uid_t currentUser = getuid();
    for (pid_t pid : pids) {
        struct stat processStat;
        std::string statPath = "/proc/" + std::to_string(pid);
        if (stat(statPath.c_str(), &processStat) == 0 && processStat.st_uid == currentUser) {
            if (kill(pid, SIGKILL) == 0) {
                std::cout << "[))> Process " << pid << " killed successfully." << std::endl;
            } else {
                std::cerr << "[))> Failed to kill process with PID " << pid << std::endl;
            }
        } else {
            std::cerr << "[))> Skipping process " << pid << " (not owned by current user)." << std::endl;
        }
    }
}

// Function to run a command with sudo
void runWithSudo(const std::string &command) {
    std::string password;
    securePasswordInput(password);

    pid_t pid = fork();
    if (pid < 0) {
        handleError("Fork failed.");
    } else if (pid == 0) {
        // Child process to execute the command
        char *args[] = { (char *)"/bin/bash", (char *)"-c", (char *)command.c_str(), nullptr };
        execvp(args[0], args);
        handleError("Failed to execute command.");
    } else {
        // Parent process waits for child
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            std::cout << "[))> Command executed successfully." << std::endl;
        } else {
            handleError("Command failed.");
        }
    }

    // Clear sensitive password data after use
    std::fill(password.begin(), password.end(), '\0');
}

// Signal handler to clean up on interrupt (Ctrl+C)
void handleSignal(int signal) {
    std::cout << "\n[))> suway-ng interrupted!" << std::endl;
    // Clear sensitive data
    unsetenv("PASSWORD");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    // Register signal handlers for clean exit on Ctrl+C or termination
    signal(SIGINT, handleSignal);
    signal(SIGTERM, handleSignal);

    if (argc < 2) {
        handleError("No program found to run with suway!");
    }

    std::string programName = argv[1];

    // Validate the program name input
    if (!isValidProgramName(programName)) {
        handleError("Invalid characters in program name.");
    }

    // Check if the program exists in the system using access()
    if (access(("/usr/bin/" + programName).c_str(), X_OK) != 0) {
        handleError("Command " + programName + " not found!");
    }

    std::cout << "suway-ng for program: " << programName << std::endl;

    // Kill processes matching the given program name
    killProcesses(programName);

    // Run the program with sudo privileges
    runWithSudo(programName);

    // Clear environment variables holding sensitive data
    unsetenv("PASSWORD");

    return 0;
}
