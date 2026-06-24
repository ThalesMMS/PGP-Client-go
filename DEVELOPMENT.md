# Desenvolvimento

## Comandos principais

```bash
go mod download
go fmt ./...
go vet -tags ci ./...
go test -tags ci ./...
go test -race -tags ci ./...
```

A tag `ci` substitui o driver gráfico do Fyne por um driver em memória. Para executar a aplicação real, instale as dependências nativas do sistema e use:

```bash
go run ./cmd/pgp-client
```

## Convenções

- Regras criptográficas ficam em `internal/pgp`, nunca em callbacks da UI.
- Escritas que produzem artefatos finais devem usar `internal/fileutil`.
- Não registre plaintext, frases secretas, chaves privadas ou conteúdo de backup.
- Novos caminhos de rede devem ter timeout, limite de resposta e política explícita de TLS/redirecionamento.
- Erros de assinatura devem ser distinguidos de erros de parsing, I/O e ausência de chave.
- Testes não devem acessar keyservers reais nem o cofre real do sistema.

## Dependências

Atualize versões deliberadamente e execute a suíte completa. Para alterações em Fyne, valide pelo menos:

- renderização headless com `-tags ci`;
- build nativo no sistema de destino;
- diálogos de arquivos;
- arrastar e soltar;
- pacote produzido por `fyne package`.
