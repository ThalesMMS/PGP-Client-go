# Validação da entrega

Ambiente usado em 2026-06-24: Linux x86_64, Go 1.23.2.

Executado com sucesso:

```bash
go mod tidy
go fmt ./...
go vet -tags ci ./...
go test -tags ci ./...
go test -race -tags ci ./...
go build -trimpath -tags ci ./cmd/pgp-client
go build -trimpath ./cmd/pgp-client-cli
go run fyne.io/tools/cmd/fyne@v1.7.2 package --tags ci --src ./cmd/pgp-client
```

Também foi executado um smoke test do CLI com diretório de configuração isolado:

1. geração de duas chaves RSA 2048;
2. listagem JSON e seleção por fingerprint;
3. criptografia para Bob com assinatura de Alice;
4. descriptografia e validação da assinatura embutida;
5. assinatura destacada e verificação;
6. criação de backup;
7. restauração em chaveiro vazio e conferência de duas chaves.

A suíte também cobre seleção do destinatário correto durante descriptografia streaming, arquivos simétricos sem tentativas de desbloqueio de chaves não relacionadas, fallback após segredo obsoleto no cofre, rollback de geração quando o cofre falha e roteamento de arquivos recebidos pela GUI.

O link nativo da GUI Linux não foi executado neste container porque os headers de desenvolvimento OpenGL/X11 não estavam disponíveis. A tag `ci` do Fyne valida toda a composição da UI com driver em memória, inclusive renderização das cinco páginas. Para distribuição, execute `make build` e `make package` em um sistema com as dependências nativas descritas no README.
