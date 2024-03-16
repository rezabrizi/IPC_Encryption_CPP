# IPC Encryption CPP
Interprocess Communication to encrypt message using the Vigenere Cypher

## Files
* `logger.cpp`: The source file of the logger program
* `encryption.cpp`: The source file of the encryption program
* `main.cpp`: The source file of the main program (driver)
* `README.md`: About the project

## Running instructions
1. Create a directory for the sources files. 
```
mkdir reza_ipc_encryption
```
2. Move all the source files to this directory.
```commandline
mv main.cpp reza_ipc_encryption
mv logger.cpp reza_ipc_encryption
mv encryption.cpp reza_ipc_encryption
```
3. Compile the 3 source files into executables using the following commands: 
```commandline
g++ -o encryption encryption.cpp
g++ -o logger logger.cpp
g++ -o main main.cpp
```
4. Run the main executable with the path of the desired log file using: ./main <path_to_log_file>
```commandline
./main log.txt
```
5. Input your desired choices based on the menus presented
6. If you enter invalid input then the program will just go back to the main menu
* Note: The log file will only show `[Password]` and `[result]` for password logging due to privacy reasons. It will not show the password that was set. 