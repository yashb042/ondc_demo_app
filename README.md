This repo does 2 things

1. Generating the public-private key-pair
2. Running the demo application

1. **Generating the public-private key-pair**
   In order to run the public-private file, you should use Docker (if you have golang installed, you can run directly)

   **Using Docker**
   Go to the encryption folder, and run the following command
   ```
    docker build -t encryption .
    docker run encryption
    ```
   This will generate the public-private key pair in the console

   **Using Golang** (if you have golang installed)
   Go to the encryption folder, and run the following command
    ```
    go run public-private-key-generation.go
    ```

Once you run this, the output would be as follows

![](../../Desktop/Screenshot 2024-05-06 at 2.24.33 PM.png)

2. **Running the demo application**

    1. **Using Docker (Easier) :**
       Make sure that you have docker installed, and docker daemon running
       Go to the demo_app folder, and run the following command
         ```
         docker build -t demo_app .
         docker run -p 8080:8080 demo_app
         ```
       This will start the server at port 8080. You can access the server at http://localhost:8080
    2. **Using Golang :**
       Make sure that you have golang installed
       Go to the demo_app/cmd folder, and run the following command
         ```
         go run main.go
         ```
       This will start the server at port 8080. You can access the server at http://localhost:8080
