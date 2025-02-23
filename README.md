# Servidor HTTP com Autenticação e Registro de Usuários

Este projeto implementa um servidor HTTP simples com funcionalidades de autenticação e registro de usuários. As credenciais dos usuários são armazenadas em um banco de dados SQLite.

## Funcionalidades

- **Login**: Autenticação de usuários.
- **Logout**: Encerrar a sessão do usuário.
- **Registrar**: Registrar novos usuários.
- **Página Inicial**: Página acessível apenas para usuários autenticados, com uma mensagem de boas-vindas.

## Estrutura do Código

O código está estruturado em várias funções para facilitar a leitura e manutenção. Abaixo está uma descrição detalhada de cada função:

### Funções Auxiliares

#### `read_file`

```c
char *read_file(const char *filename);
```

Lê o conteúdo de um arquivo HTML e retorna uma string dinâmica contendo o conteúdo do arquivo.

#### `is_logged_in`

```c
int is_logged_in(char *request);
```

Verifica se o usuário está logado, procurando por um cookie de sessão válido na requisição HTTP.

#### `check_credentials`

```c
int check_credentials(const char *username, const char *password);
```

Verifica as credenciais do usuário no banco de dados SQLite. Retorna 1 se as credenciais forem válidas, caso contrário, retorna 0.

#### `register_user`

```c
int register_user(const char *username, const char *password);
```

Registra um novo usuário no banco de dados SQLite com `is_superuser` definido como 0. Retorna 1 se o registro for bem-sucedido, caso contrário, retorna 0.

#### `replace_placeholder`

```c
char *replace_placeholder(const char *html, const char *username, int is_superuser);
```

Substitui o marcador de posição `{{username}}` pelo nome do usuário e adiciona uma mensagem de super usuário se aplicável.

#### `get_username_from_db`

```c
char *get_username_from_db(const char *username);
```

Busca o nome do usuário no banco de dados SQLite.

#### `get_user_info_from_db`

```c
int get_user_info_from_db(const char *username, char *db_username, int *is_superuser);
```

Busca o nome do usuário e se ele é um super usuário no banco de dados SQLite. Retorna 1 se for bem-sucedido, caso contrário, retorna 0.

### Função Principal

#### `handle_request`

```c
void handle_request(int new_socket, char *request);
```

Trata as requisições HTTP recebidas. Dependendo do tipo de requisição (login, logout, registrar usuário etc.), a função executa diferentes ações e responde ao cliente adequadamente.

### `main`

```c
int main(void);
```

Função principal que inicializa o servidor, configura o socket e escuta por conexões. Quando uma requisição é recebida, delega o tratamento para a função `handle_request`.

## Executando o Servidor

1. Compile o código com um compilador C:
   ```sh
   gcc -o servidor servidor.c -lsqlite3
   ```

2. Execute o servidor:
   ```sh
   ./servidor
   ```

O servidor irá escutar na porta 8080 e abrirá automaticamente o navegador padrão para acessar a aplicação.

## Estrutura do Banco de Dados

O banco de dados `usuarios.db` deve conter uma tabela `users` com o seguinte esquema:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    is_superuser INTEGER NOT NULL
);
```

## Segurança

- **Evitar SQL Injection**: As consultas SQL utilizam `sqlite3_prepare_v2` e `sqlite3_bind_text` para evitar SQL Injection.
- **Cookies HTTPOnly**: Os cookies de sessão são marcados como HTTPOnly para melhorar a segurança.

## Dependências

- **SQLite3**: O banco de dados utilizado é o SQLite3.
- **Bibliotecas Padrão**: `stdio.h`, `stdlib.h`, `string.h`, `unistd.h`, `arpa/inet.h`, `sqlite3.h`.

## Licença

Este projeto é licenciado sob a [MIT License](LICENSE).
