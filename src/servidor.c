#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 4096

// Credenciais fixas para exemplo
const char *VALID_USER = "admin";
const char *VALID_PASS = "1234";

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

// Função para verificar se o usuário está logado
int is_logged_in(char *request) {
    // Verifica se o cookie de sessão está presente na requisição
    return strstr(request, "Cookie: session=valid") != NULL;
}

// Função para tratar requisições HTTP
void handle_request(int new_socket, char *request) {
    char response[BUFFER_SIZE];
    char *html_content;

    if (strstr(request, "POST /login") != NULL) {
        // Verifica credenciais na requisição
        if (strstr(request, "username=admin") && strstr(request, "password=1234")) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Set-Cookie: session=valid\r\n"
                     "Location: /\r\n\r\n");
        } else {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 401 Unauthorized\r\n"
                     "Content-Type: text/html\r\n\r\n"
                     "<h1>Credenciais Inválidas</h1>");
        }
    } else if (strstr(request, "GET /") != NULL) {
        // Redireciona para login se não estiver logado
        if (is_logged_in(request)) {
            html_content = read_file("public/index.html");
        } else {
            html_content = read_file("public/login.html");
        }

        if (html_content) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html\r\n"
                     "Content-Length: %ld\r\n\r\n%s",
                     strlen(html_content), html_content);
            free(html_content);
        } else {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 404 Not Found\r\n"
                     "Content-Type: text/html\r\n\r\n"
                     "<h1>Página não encontrada</h1>");
        }
    } else {
        snprintf(response, sizeof(response),
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Type: text/html\r\n\r\n"
                 "<h1>Página não encontrada</h1>");
    }

    send(new_socket, response, strlen(response), 0);
    close(new_socket);
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
        close(server_fd);  // Fechar o socket antes de sair
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Erro no listen");
        close(server_fd);  // Fechar o socket antes de sair
        exit(EXIT_FAILURE);
    }

    printf("Servidor escutando na porta %d\n", PORT);
    system("xdg-open http://localhost:8080 &");

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Erro no accept");
            close(server_fd);  // Fechar o socket antes de sair
            exit(EXIT_FAILURE);
        }

        read(new_socket, buffer, BUFFER_SIZE);
        printf("Requisição recebida:\n%s\n", buffer);

        handle_request(new_socket, buffer);
        memset(buffer, 0, BUFFER_SIZE);  // Limpar o buffer após cada requisição
    }

    close(server_fd);
    return 0;
}