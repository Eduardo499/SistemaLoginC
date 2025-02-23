#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define PORT 8080
#define BUFFER_SIZE 4096
#define DB_PATH "usuarios.db"

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

// Função para verificar credenciais no banco de dados
int check_credentials(const char *username, const char *password) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result = 0;

    // Abre o banco de dados
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Erro ao abrir o banco de dados: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Prepara a consulta SQL para verificar o usuário e a senha
    const char *sql = "SELECT 1 FROM users WHERE username = ? AND password = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Erro ao preparar a consulta: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // Vincula os parâmetros da consulta para evitar SQL Injection
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    // Executa a consulta e verifica se retornou algum resultado
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = 1; // Credenciais válidas
    }

    // Limpa os recursos
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

// Função para registrar um novo usuário no banco de dados
int register_user(const char *username, const char *password) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result = 0;

    // Abre o banco de dados
    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Erro ao abrir o banco de dados: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Prepara a consulta SQL para inserir um novo usuário com is_superuser = 0
    const char *sql = "INSERT INTO users (username, password, is_superuser) VALUES (?, ?, 0)";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Erro ao preparar a consulta: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    // Vincula os parâmetros da consulta para evitar SQL Injection
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);

    // Executa a consulta e verifica se foi bem-sucedida
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = 1; // Registro bem-sucedido
    } else {
        fprintf(stderr, "Erro ao registrar o usuário: %s\n", sqlite3_errmsg(db));
    }

    // Limpa os recursos
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

// Função auxiliar para substituir o marcador de posição pelo nome do usuário e mensagem de super usuário
char *replace_placeholder(const char *html, const char *username, int is_superuser) {
    const char *placeholder = "{{username}}";
    const char *superuser_message = "<p>Você é um super usuário :)</p>";
    char *result;
    int len_html = strlen(html);
    int len_placeholder = strlen(placeholder);
    int len_username = strlen(username);
    int len_superuser_message = is_superuser ? strlen(superuser_message) : 0;

    result = malloc(len_html - len_placeholder + len_username + len_superuser_message + 1);
    if (!result) {
        perror("Erro ao alocar memória");
        return NULL;
    }

    char *pos = strstr(html, placeholder);
    if (pos) {
        int prefix_len = pos - html;
        strncpy(result, html, prefix_len);
        strcpy(result + prefix_len, username);
        strcpy(result + prefix_len + len_username, pos + len_placeholder);
        if (is_superuser) {
            strcat(result, superuser_message);
        }
    } else {
        strcpy(result, html);
    }

    return result;
}

// Função para buscar o nome do usuário no banco de dados
char *get_username_from_db(const char *username) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *result = NULL;

    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Erro ao abrir o banco de dados: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    const char *sql = "SELECT username FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Erro ao preparar a consulta: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *db_username = sqlite3_column_text(stmt, 0);
        result = strdup((const char *)db_username);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

// Função para buscar o nome do usuário e se é super usuário no banco de dados
int get_user_info_from_db(const char *username, char *db_username, int *is_superuser) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result = 0;

    if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
        fprintf(stderr, "Erro ao abrir o banco de dados: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    const char *sql = "SELECT username, is_superuser FROM users WHERE username = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Erro ao preparar a consulta: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *db_username_text = sqlite3_column_text(stmt, 0);
        *is_superuser = sqlite3_column_int(stmt, 1);
        strcpy(db_username, (const char *)db_username_text);
        result = 1;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return result;
}

// Função para tratar requisições HTTP
void handle_request(int new_socket, char *request) {
    char response[BUFFER_SIZE];
    char *html_content;
    char username[50], password[50];
    char db_username[50];
    int is_superuser = 0;

    if (strstr(request, "POST /login") != NULL) {
        // Extrai o username e password da requisição
        char *body = strstr(request, "\r\n\r\n");
        if (body) {
            body += 4; // Skip the "\r\n\r\n"
            sscanf(body, "username=%49[^&]&password=%49s", username, password);
        }

        if (check_credentials(username, password)) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Set-Cookie: session=valid; Path=/; HttpOnly\r\n"
                     "Location: /\r\n\r\n");
        } else {
            html_content = read_file("public/login.html");
            if (!html_content) {
                snprintf(response, sizeof(response),
                         "HTTP/1.1 500 Internal Server Error\r\n"
                         "Content-Type: text/html\r\n\r\n"
                         "<h1>Erro ao carregar a página de login</h1>");
            } else {
                char error_message[] = "<p style='color:red;'>Credenciais Inválidas</p>";
                char *error_page = malloc(strlen(html_content) + strlen(error_message) + 1);
                if (error_page) {
                    strcpy(error_page, html_content);
                    strcat(error_page, error_message);
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 401 Unauthorized\r\n"
                             "Content-Type: text/html\r\n\r\n%s",
                             error_page);
                    free(error_page);
                } else {
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: text/html\r\n\r\n"
                             "<h1>Erro ao alocar memória</h1>");
                }
                free(html_content);
            }
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
    } else if (strstr(request, "POST /registrar_usuario") != NULL) {
        // Extrai o username e password da requisição
        char *body = strstr(request, "\r\n\r\n");
        if (body) {
            body += 4; // Skip the "\r\n\r\n"
            sscanf(body, "username=%49[^&]&password=%49s", username, password);
        }

        if (register_user(username, password)) {
            snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Location: /login\r\n\r\n");
        } else {
            html_content = read_file("public/registrar.html");
            if (!html_content) {
                snprintf(response, sizeof(response),
                         "HTTP/1.1 500 Internal Server Error\r\n"
                         "Content-Type: text/html\r\n\r\n"
                         "<h1>Erro ao carregar a página de registro</h1>");
            } else {
                char error_message[] = "<p style='color:red;'>Erro ao registrar o usuário</p>";
                char *error_page = malloc(strlen(html_content) + strlen(error_message) + 1);
                if (error_page) {
                    strcpy(error_page, html_content);
                    strcat(error_page, error_message);
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 400 Bad Request\r\n"
                             "Content-Type: text/html\r\n\r\n%s",
                             error_page);
                    free(error_page);
                } else {
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: text/html\r\n\r\n"
                             "<h1>Erro ao alocar memória</h1>");
                }
                free(html_content);
            }
        }
        send(new_socket, response, strlen(response), 0);
        close(new_socket);
        return;
    } else if (strstr(request, "POST /registrar") != NULL) {
        // Tenta ler o arquivo HTML
        html_content = read_file("public/registrar.html");
        
        if (!html_content) {
            // Se falhar ao ler o arquivo, responde com erro 500
            snprintf(response, sizeof(response),
                     "HTTP/1.1 500 Internal Server Error\r\n"
                     "Content-Type: text/html\r\n\r\n"
                     "<h1>Erro ao carregar a página de registro</h1>");
        } else {
            // Se o arquivo for lido corretamente, responde com o conteúdo
            snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/html\r\n"
                     "Content-Length: %ld\r\n\r\n%s",
                     strlen(html_content), html_content);
            free(html_content); // Libera o conteúdo do HTML após o envio
        }
    
        // Envia a resposta para o cliente
        send(new_socket, response, strlen(response), 0);
    
        // Fecha a conexão após o envio
        close(new_socket);
        return;
    } else if (strstr(request, "GET /") != NULL) {
        if (is_logged_in(request)) {
            html_content = read_file("public/index.html");
            if (!html_content) {
                printf("Erro ao ler o arquivo index.html\n");
            } else {
                printf("Arquivo index.html lido com sucesso\n");
                // Busca o nome do usuário e se é super usuário no banco de dados
                if (get_user_info_from_db(username, db_username, &is_superuser)) {
                    // Substitui o marcador de posição pelo nome do usuário e mensagem de super usuário
                    char *final_content = replace_placeholder(html_content, db_username, is_superuser);
                    free(html_content);
                    html_content = final_content;
                }
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
