#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <string>

std::string get_current_date_time() {
    auto current_time = std::chrono::system_clock::now();
    auto time_t_format = std::chrono::system_clock::to_time_t(current_time);
    auto tm_format = *std::localtime(&time_t_format);
    std::ostringstream date_time_stream;
    date_time_stream << std::put_time(&tm_format, "%Y-%m-%d %H:%M");
    return date_time_stream.str();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path_to_log_file>" << std::endl;
        return 1;
    }

    std::string path_to_log_file = argv[1];
    std::ofstream logFile(path_to_log_file, std::ios::app);

    if (!logFile) {
        std::cerr << "Error opening file." << std::endl;
        return 1;
    }

    std::string line;
    bool bQuit = false;

    while (!bQuit && std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string action, message;

        // Extract the action (the first sequence of non-whitespace characters)
        iss >> action;

        // Get the rest of the line as the message
        std::getline(iss, message);

        if (action == "QUIT") {
            logFile << get_current_date_time() << " [" << action << "]" << message << std::endl;
            bQuit = true;
            continue;
        }
        // Write to the log file with the specified format
        logFile << get_current_date_time() << " [" << action << "]" << message << std::endl;
    }

    return 0;
}
