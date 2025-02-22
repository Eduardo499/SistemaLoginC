#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Função para ler o conteúdo do arquivo HTML
char *read_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Erro ao abrir o arquivo");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length + 1);
    if (!content) {
        perror("Erro ao alocar memória");
        fclose(file);
        return NULL;
    }

    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);

    return content;
}

int main(void) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Erro ao criar o socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Erro no bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Erro no listen");
        exit(EXIT_FAILURE);
    }

    printf("Servidor escutando na porta %d\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Erro no accept");
            exit(EXIT_FAILURE);
        }

        read(new_socket, buffer, BUFFER_SIZE);
        printf("Requisição recebida: %s\n", buffer);

        char *html_content = read_file("public/login.html");
        char response[BUFFER_SIZE];

        if (html_content) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\n"
                     "Content-Type: text/html\n"
                     "Content-Length: %ld\n"
                     "\n%s",
                     strlen(html_content), html_content);
            free(html_content);
        } else {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 404 Not Found\n"
                     "Content-Type: text/html\n"
                     "Content-Length: 87\n"
                     "\n"
                     "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
        }

        send(new_socket, response, strlen(response), 0);
        printf("Resposta enviada: %s\n", response);
        
        close(new_socket); // Fecha o socket corretamente após o envio
    }

    close(server_fd);
    return 0;
}
