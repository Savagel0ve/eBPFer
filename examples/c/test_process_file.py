import os

def main():
    # 输出当前进程的 PID
    print(f"Current PID: {os.getpid()}")

    while True:
        # 等待用户输入
        user_input = input("Enter 1 to delete 1.txt, 2 to read 1.txt, 3 to write to 1.txt (or any other key to exit): ")

        if user_input == "1":
            # 删除 1.txt
            try:
                os.remove("1.txt")
                print("1.txt deleted successfully.")
            except FileNotFoundError:
                print("1.txt does not exist.")
            except Exception as e:
                print(f"Error deleting 1.txt: {e}")

        elif user_input == "2":
            # 读取 1.txt
            try:
                with open("1.txt", "r") as file:
                    content = file.read()
                    print("Content of 1.txt:")
                    print(content)
            except FileNotFoundError:
                print("1.txt does not exist.")
            except Exception as e:
                print(f"Error reading 1.txt: {e}")

        elif user_input == "3":
            # 写入 1.txt
            try:
                with open("1.txt", "w") as file:
                    file.write("This is a test content written to 1.txt")
                print("Successfully wrote to 1.txt.")
            except Exception as e:
                print(f"Error writing to 1.txt: {e}")

        else:
            print("Exiting program.")
            break

if __name__ == "__main__":
    main()