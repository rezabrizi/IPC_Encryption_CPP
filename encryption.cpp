#include <iostream>
#include <sstream>
#include <string>


std::string encrypt(const std::string &text, const std::string &key) {
    std::string encryptedText;
    for (size_t i = 0, j = 0; i < text.length(); ++i) {
        char letter = text[i];
        if (letter >= 'a' && letter <= 'z') {
            letter = (letter - 'a' + (key[j % key.length()] - 'a')) % 26 + 'a';
            j++;
        } else if (letter >= 'A' && letter <= 'Z') {
            letter = (letter - 'A' + (key[j % key.length()] - 'A')) % 26 + 'A';
            j++;
        }
        encryptedText += letter;
    }
    return encryptedText;
}

std::string decrypt(const std::string &text, const std::string &key) {
    std::string decryptedText;
    for (size_t i = 0, j = 0; i < text.length(); ++i) {
        char letter = text[i];
        if (letter >= 'a' && letter <= 'z') {
            letter = (letter - 'a' - (key[j % key.length()] - 'a') + 26) % 26 + 'a';
            j++;
        } else if (letter >= 'A' && letter <= 'Z') {
            letter = (letter - 'A' - (key[j % key.length()] - 'A') + 26) % 26 + 'A';
            j++;
        }
        decryptedText += letter;
    }
    return decryptedText;
}

// Add trim function to remove leading spaces
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// Encryption and decryption functions remain the same

int main() {

    bool bQuit = false;
    std::string line;
    std::string pass_key;

    while (!bQuit && std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string action, argument;

        iss >> action;

        if (action == "QUIT")
        {
            bQuit = true;
            std::cout << "RESULT\n";
        }
        else if (action == "PASSKEY")
        {
            std::getline(iss, argument);
            pass_key = trim(argument);
            std::cout << "RESULT\n";
        }
        else if (action == "ENCRYPT" || action == "DECRYPT")
        {
            std::getline(iss, argument);
            argument = trim(argument);
            if (pass_key.empty()) {
                std::cout << "ERROR Password not set.";
            } else {
                std::string result = (action == "ENCRYPT") ? encrypt(argument, pass_key) : decrypt(argument, pass_key);
                std::cout << "RESULT " << result;
            }
        }
        else
        {
            std::cout << "ERROR incorrect command.";
        }
    }

    return 0;
}