#include <iostream>
#include <sys/wait.h>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <vector>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <poll.h>


void set_up_logger(int &logger_fd, const char* log_file_path)
{
    int pipefd[2];
    pipe(pipefd);
    pid_t child_pid = fork();

    if (child_pid == 0)
    {
        close(pipefd[1]); // close the write end of the pipe for the logger
        dup2(pipefd[0], STDIN_FILENO); // redirect STDIN to the read end of the pipe
        execl("./logger", "./logger", log_file_path, (char *)NULL); // WHAT DOES THIS DO ?
        exit(EXIT_FAILURE); // WHAT DOES THIS DO ?
    }
    // Parent Process
    else
    {
        close (pipefd[0]); // close the read end of the pipe
        logger_fd  = pipefd[1]; // save the write end of the pipe for logging
    }
}

void set_up_encryption(int &encryption_input_fd, int &encryption_output_fd)
{
    int pipefdIn[2], pipefdOut[2];
    pipe(pipefdIn);
    pipe(pipefdOut);
    pid_t child_pid = fork();

    if (child_pid == 0)
    {
        close(pipefdIn[1]); // Closing the write end of the input pipe
        dup2(pipefdIn[0], STDIN_FILENO); // redirect STDIN to the read end of the input pipe

        close(pipefdOut[0]); // Closing the read end of the output pipe
        dup2(pipefdOut[1], STDOUT_FILENO); // redirect STDOUT to the write end of the output file
        execl("./encryption", "encryption", (char *)NULL);
        exit(EXIT_FAILURE);
    }
    else
    {
        close (pipefdIn[0]); // close the read end of the input pipe
        encryption_input_fd = pipefdIn[1]; // save the write end for sending input to the encryption program

        close(pipefdOut[1]); // close the write end of the output file
        encryption_output_fd = pipefdOut[0]; // save the read end for receiving output of the encryption program
    }
}



std::pair<std::string, bool> read_from_encryption(int fd) {
    char buffer[1024] = {0};
    std::string output;
    bool isError = false;

    ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1); // Perform a blocking read
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Ensure null-termination
        output = std::string(buffer);

        if (output.find("ERROR") == 0) {
            // If the output starts with "ERROR", it's an error message.
            isError = true;
            output.erase(0, 6); // Remove "ERROR " prefix, if you decide to keep it consistent like "RESULT "
        } else if (output.find("RESULT") == 0) {
            // If the output starts with "RESULT", check if there's additional data.
            if (output.length() > 7) { // "RESULT " is 7 characters, check if there's more
                output.erase(0, 7); // Remove "RESULT " prefix to get the actual result/message
            } else {
                // If there's nothing beyond "RESULT", adjust output to indicate a successful operation without additional data.
                output = "Operation completed successfully.";
            }
        }
    }
    return std::make_pair(output, isError);
}





void write_to_logger(int fd, const std::string &message) {
    write(fd, message.c_str(), message.length());
}

void write_to_encryption(int fd, const std::string &command) {
    write(fd, command.c_str(), command.length());
}


void send_to_logger(int logger_fd, const std::string &action, const std::string &message) {
    std::string rawMessage = action + " " + message + "\n"; // No need for additional formatting
    write_to_logger(logger_fd, rawMessage);
}

void send_to_encryption(int encryption_in_fd, const std::string& command, const std::string& argument)
{
    std::string rawMessage;
    if (command == "QUIT")
    {
        rawMessage = command + "\n";
    }
    else
    {
        rawMessage = command + " " + argument + "\n";
    }
    write_to_encryption(encryption_in_fd, rawMessage);
}


void show_main_menu()
{
    std::cout << "Enter a command: \n";
    std::cout << "1. Set Password\n";
    std::cout << "2. Encrypt a message \n";
    std::cout << "3. Decrypt a message \n";
    std::cout << "4. Show history \n";
    std::cout << "5. Quit \n";
}

void encrypt_decrypt_menu ()
{
    std::cout << "What message do you want to encrypt/decrypt: \n";
    std::cout << "1. Enter a new message:\n";
    std::cout << "2. Choose from history:\n";
}

void password_menu ()
{
    std::cout << "How do you want to set the password: \n";
    std::cout << "1. Enter a new password:\n";
    std::cout << "2. Choose a password from history:\n";
}

void show_history_menu(const std::vector<std::string>& history)
{
    std::cout << "Choose a message from the history:\n";
    std::cout << "1. Enter a new message\n";
    for (int i = 0; i < history.size(); i++)
    {
        std::cout << std::to_string(i+2) << ". " << history[i] << "\n";
    }
}

void show_history (const std::vector<std::string>& history)
{
    std::cout <<"History: \n";
    for (int i = 0; i < history.size(); i++)
    {
        std::cout << std::to_string(i+1) << ". " << history[i] << "\n";
    }

}

void process_user_commands(int logger_fd, int encryption_input_fd, int encryption_output_fd, const std::string& path_to_log_file) {
    std::vector<std::string> history; // To store history of strings
    std::string userInput, action, argument;
    int userChoice;
    bool running = true;

    while (running) {
        show_main_menu();
        std::getline(std::cin, userInput);
        userChoice = std::stoi(userInput);

        switch (userChoice) {
            case 1: { // Set Password
                password_menu();
                std::getline(std::cin, userInput);
                int choice;
                try
                {
                    choice = std::stoi(userInput);
                }
                catch (std::exception e)
                {
                    continue;
                }

                if (choice == 1) { // Enter a new password
                    std::cout << "Enter the new password: ";
                    std::getline(std::cin, argument);
                    send_to_encryption(encryption_input_fd, "PASSKEY", argument);
                    // Note: Passwords are not logged for security
                } else if (choice == 2) { // Choose from history
                    show_history_menu(history);
                    std::getline(std::cin, userInput);
                    int historyChoice = std::stoi(userInput);
                    if (historyChoice == 1)
                    {
                        std::cout << "Enter the new message: ";
                        std::getline(std::cin, argument);
                        send_to_encryption(encryption_input_fd, "PASSKEY", argument);
                    }
                    else
                    {
                        historyChoice -= 2;
                        if (historyChoice >= 0 && historyChoice < history.size()) {
                            send_to_encryption(encryption_input_fd, "PASSKEY", history[historyChoice]);
                        }
                    }
                }

                std::pair<std::string, bool> resultPair = read_from_encryption(encryption_output_fd);
                std::string result = resultPair.first;
                bool isError = resultPair.second;

                if (!result.empty()) {
                    if (isError) {
                        // Log the error
                        send_to_logger(logger_fd, "ERROR", result);
                        std::cout << "Encryption error: " << result << std::endl;
                    } else {

                        std::cout << "RESULT " << std::endl;
                    }
                }
                break;
            }
            case 2: // Encrypt a message
            case 3: { // Decrypt a message
                encrypt_decrypt_menu();
                std::getline(std::cin, userInput);
                int choice;
                try
                {
                    choice = std::stoi(userInput);
                }
                catch (std::exception e)
                {
                    continue;
                }

                std::string command = (userChoice == 2) ? "ENCRYPT" : "DECRYPT";

                if (choice == 1) { // Enter a new message directly
                    std::cout << "Enter the new message: ";
                    std::getline(std::cin, argument);
                    history.push_back(argument); // Save to history
                    send_to_encryption(encryption_input_fd, command, argument);
                } else if (choice == 2) { // Show history to choose from or enter a new message
                    show_history_menu(history);
                    std::getline(std::cin, userInput);
                    int historyChoice = std::stoi(userInput);

                    if (historyChoice == 1) { // User chooses to enter a new message after seeing history
                        std::cout << "Enter the new message: ";
                        std::getline(std::cin, argument);
                        history.push_back(argument); // Save to history
                        send_to_encryption(encryption_input_fd, command, argument);
                    } else if (historyChoice > 1 && historyChoice <= history.size() + 1) { // Choose from history
                        argument = history[historyChoice -2]; // Adjust for zero-based index and the "Enter a new message" option
                        send_to_encryption(encryption_input_fd, command, argument);
                    } else {
                        std::cout << "Invalid choice, please try again.\n";
                        continue; // Invalid choice, prompt again
                    }
                }

                // After sending the request, read the encryption or decryption result.
                // Replace this part of the code in case 2 and case 3 where you read and handle the encryption output
                std::pair<std::string, bool> resultPair = read_from_encryption(encryption_output_fd);
                std::string result = resultPair.first;
                bool isError = resultPair.second;

                if (!result.empty()) {
                    if (isError) {
                        // Log the error
                        send_to_logger(logger_fd, "ERROR", result);
                        std::cout << "Encryption error: " << result << std::endl;
                    } else {
                        // Process and log the successful encryption/decryption result
                        std::cout << "RESULT " << result << std::endl;
                        send_to_logger(logger_fd, (userChoice == 2) ? "ENCRYPT" : "DECRYPT",
                                       argument);
                    }
                }
                break;
            }
            case 4: { // Show history
                show_history(history);
                std::getline(std::cin, userInput); // Just to pause
                break;
            }
            case 5: { // Quit
                send_to_encryption(encryption_input_fd, "QUIT", "");
                send_to_logger(logger_fd, "QUIT", "Quitting program.");
                running = false;
                break;
            }
            default:
                std::cout << "Invalid choice. Please try again.\n";
                break;
        }
    }
}



int main(int argc, char* argv[]) {

    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <path_to_log_file>" << std::endl;
        return 1;
    }

    std::string path_to_log_file = argv[1];

    int logger_fd, encryption_input_fd, encryption_output_fd;
    set_up_logger(logger_fd, argv[1]);
    set_up_encryption(encryption_input_fd, encryption_output_fd);

    send_to_logger(logger_fd, "START", "Logging Started.");

    process_user_commands(logger_fd, encryption_input_fd, encryption_output_fd, path_to_log_file);

    // Cleanup and exit
    close(logger_fd);
    close(encryption_input_fd);
    close(encryption_output_fd);
    wait(NULL); // Wait for the logger process to terminate
    wait(NULL); // Wait for the encryption process to terminate

    return 0;
}


