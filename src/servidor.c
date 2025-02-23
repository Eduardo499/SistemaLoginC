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
    return strstr(request, "Cookie: session=valid") != NULL;
}

// Função para tratar requisições HTTP
void handle_request(int new_socket, char *request) {
    char response[BUFFER_SIZE];
    char *html_content;

    if (strstr(request, "POST /login") != NULL) {
        if (strstr(request, "username=admin") && strstr(request, "password=1234")) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Set-Cookie: session=valid; Path=/; HttpOnly\r\n"
                     "Location: /\r\n\r\n");
        } else {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 401 Unauthorized\r\n"
                     "Content-Type: text/html\r\n\r\n"
                     "<h1>Credenciais Inválidas</h1>");
        }
        send(new_socket, response, strlen(response), 0);
        close(new_socket);
        return;
    } else if (strstr(request, "POST /logout") != NULL) {
        // Realiza o logout ao limpar o cookie de sessão
        snprintf(response, sizeof(response),
         "HTTP/1.1 302 Found\r\n"
         "Set-Cookie: session=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n"
         "Location: /\r\n\r\n");
        send(new_socket, response, strlen(response), 0);
        close(new_socket);
        return;
    } else if (strstr(request, "GET /") != NULL) {
        if (is_logged_in(request)) {
            html_content = read_file("public/index.html");
            if (!html_content) {
                printf("Erro ao ler o arquivo index.html\n");
            } else {
                printf("Arquivo index.html lido com sucesso\n");
            }
        } else {
            html_content = read_file("public/login.html");
            if (!html_content) {
                printf("Erro ao ler o arquivo login.html\n");
            } else {
                printf("Arquivo login.html lido com sucesso\n");
            }
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
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Erro no listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Servidor escutando na porta %d\n", PORT);

    #ifdef __linux__
    system("xdg-open http://localhost:8080 &");
    #endif

    #ifdef __APPLE__
    system("open http://localhost:8080");
    #endif

    #ifdef _WIN32
    system("start http://localhost:8080");
    #endif

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Erro no accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        read(new_socket, buffer, BUFFER_SIZE);
        printf("Requisição recebida:\n%s\n", buffer);

        handle_request(new_socket, buffer);
        memset(buffer, 0, BUFFER_SIZE);
    }

    close(server_fd);
    return 0;
}
