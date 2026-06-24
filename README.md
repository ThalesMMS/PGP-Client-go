# PGP Client Go

Cliente OpenPGP desktop multiplataforma escrito em Go e Fyne. O projeto é uma implementação independente inspirada nos fluxos e na organização visual do MacPGP: barra lateral de operações, chaveiro pesquisável e painel de detalhes, usando uma interface escura com destaque em laranja.

## Funcionalidades

- Chaveiro local com pesquisa, filtros, ordenação, detalhes, confiança local e comparação de fingerprint.
- Geração de chaves RSA 2048, 3072 ou 4096 bits, com validade opcional e frase secreta.
- Importação de chave pública ou privada, exportação, exclusão e revogação.
- Criptografia para múltiplos destinatários ou por senha, com ASCII armor, compressão e assinatura embutida opcional.
- Descriptografia de texto e arquivos, incluindo identificação e verificação de assinatura embutida.
- Assinaturas destacadas, inline e cleartext; verificação de texto e arquivos.
- Cofre de credenciais do sistema e cache temporário de frases secretas em memória.
- Backup autenticado e criptografado com Argon2id e AES-256-GCM.
- Pesquisa, importação e publicação em servidores HKP/HKPS.
- Arrastar e soltar, abertura de arquivos recebidos pelo sistema operacional e CLI para automações.
- Interface em português, com preferências persistentes.

## Início rápido

Requisitos gerais:

- Go 1.23 ou superior.
- Compilador C e bibliotecas nativas exigidas pelo Fyne para o sistema operacional.
- macOS: Xcode Command Line Tools.
- Linux: OpenGL, X11 e os respectivos pacotes de desenvolvimento.
- Windows: toolchain GCC compatível, normalmente via MSYS2/MinGW-w64.

```bash
git clone <seu-repositório>
cd PGP-Client-go
go mod download
make test
make run
```

O alvo `test` usa a tag `ci` do Fyne e, portanto, não abre uma janela nem exige um servidor gráfico.

## Compilação

```bash
# GUI e CLI nativos
make build

# Somente o CLI
make build-cli

# Compilação headless da GUI para validar código em CI
make build-ci

# Pacote nativo do sistema atual
make package
```

Os binários produzidos por `make build` são gravados em `bin/`.

Também estão disponíveis:

```bash
./scripts/build.sh
./scripts/package.sh          # sistema atual
./scripts/package.sh darwin   # solicita target explícito ao fyne package
```

A compilação cruzada de aplicações Fyne pode exigir SDKs e toolchains do sistema de destino; empacotar no próprio macOS, Linux ou Windows costuma ser a opção mais previsível.

## Uso da interface

1. Abra **Chaveiro** e gere ou importe uma chave.
2. Revise o fingerprint em um canal independente antes de marcar a chave como verificada.
3. Em **Criptografar**, selecione um ou mais destinatários, ou use o modo por senha.
4. Em **Descriptografar**, forneça a frase secreta quando solicitada. A saída só é confirmada depois de a operação terminar sem erro.
5. Use **Assinar** e **Verificar** para assinaturas destacadas, inline ou cleartext.
6. Acesse **Arquivo → Criar backup criptografado** para proteger o chaveiro e as preferências.

Arquivos também podem ser arrastados para a janela. O roteamento considera conteúdo e extensão: chaves são encaminhadas à importação; mensagens PGP, à descriptografia; assinaturas `.sig`, ASCII-armored ou cleartext, à verificação; os demais arquivos, à criptografia.

## CLI

```text
pgp-client-cli list [--json]
pgp-client-cli generate --name NOME --email EMAIL [--bits 3072] [--expires 730]
pgp-client-cli import ARQUIVO [ARQUIVO...]
pgp-client-cli export-public  --key FINGERPRINT --out ARQUIVO
pgp-client-cli export-private --key FINGERPRINT --out ARQUIVO
pgp-client-cli encrypt --recipient FINGERPRINT [--recipient ...] [--sign FINGERPRINT] ENTRADA SAIDA
pgp-client-cli decrypt ENTRADA SAIDA
pgp-client-cli sign --key FINGERPRINT [--mode detached|inline|cleartext] ENTRADA SAIDA
pgp-client-cli verify --mode detached|inline|cleartext --signature ASSINATURA [--data DADOS] [--out SAIDA]
pgp-client-cli backup SAIDA.pgpbackup
pgp-client-cli restore [--settings] BACKUP.pgpbackup
pgp-client-cli keyserver-search CONSULTA
pgp-client-cli keyserver-import FINGERPRINT_OU_KEYID
pgp-client-cli keyserver-upload FINGERPRINT
pgp-client-cli lock
```

Quando há um terminal interativo, segredos são solicitados sem eco. Para automações, o CLI aceita `PGP_CLIENT_PASSPHRASE` e `PGP_CLIENT_PASSWORD`; variáveis de ambiente podem ser observadas por processos privilegiados ou ferramentas de diagnóstico, portanto devem ser usadas apenas em ambientes controlados.

## Armazenamento

O diretório é derivado de `os.UserConfigDir()` e recebe a subpasta `pgp-client-go`:

- macOS: normalmente `~/Library/Application Support/pgp-client-go`
- Linux: normalmente `~/.config/pgp-client-go`
- Windows: normalmente `%AppData%\pgp-client-go`

Chaves privadas são gravadas com permissão `0600` em sistemas POSIX. Uma chave sem frase secreta permanece desprotegida no disco; o aplicativo permite esse modo para compatibilidade, mas recomenda proteção por frase secreta.

## Segurança

- Operações de arquivo do núcleo e a persistência local usam temporários no mesmo diretório e só substituem o destino após fechamento e sincronização bem-sucedidos; os diálogos nativos da GUI validam escrita e fechamento do fluxo fornecido pelo Fyne.
- Conteúdo inline só é salvo como verificado depois da validação criptográfica.
- Respostas de keyserver têm limite de tamanho, timeout e exigem HTTPS, exceto `localhost`/`127.0.0.1` para testes.
- Backups têm envelope autenticado e limites defensivos para parâmetros Argon2id.
- Frases secretas persistentes usam o cofre nativo por meio de `go-keyring`; o cache de sessão permanece apenas em memória e pode ser limpo por **Bloquear agora**.

Consulte [SECURITY.md](SECURITY.md) para o modelo de ameaça e as limitações.

## Paridade com o MacPGP

Os fluxos OpenPGP e a estrutura visual principal foram reproduzidos em Go/Fyne. Extensões nativas do macOS — Finder Sync, Quick Look, Thumbnail e Share Extension — exigem targets de App Extension, assinatura e empacotamento próprios do ecossistema Xcode. Elas não são implementáveis como componentes Fyne puros. O projeto oferece abertura de arquivos, arrastar e soltar, MIME metadata, CLI e instruções de Automator como alternativa prática.

A matriz detalhada está em [docs/FEATURE_MATRIX.md](docs/FEATURE_MATRIX.md), e a integração macOS em [docs/MACOS_INTEGRATION.md](docs/MACOS_INTEGRATION.md).

## Arquitetura

```text
cmd/pgp-client/       executável gráfico
cmd/pgp-client-cli/   interface de linha de comando
internal/ui/           composição Fyne e estado de apresentação
internal/pgp/          casos de uso OpenPGP, backup e keyserver
internal/storage/      chaveiro, preferências e cofres de segredo
internal/fileutil/     gravações transacionais de arquivos
internal/model/        contratos e modelos compartilhados
```

A camada gráfica não manipula primitivas criptográficas diretamente. UI e CLI dependem do mesmo `pgp.Service`, o que reduz divergência de comportamento e permite testes determinísticos com armazenamento e cofre em memória.

Detalhes adicionais: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testes

```bash
go test -tags ci ./...
go test -race -tags ci ./...
go vet -tags ci ./...
```

A suíte cobre criptografia para múltiplos destinatários, assinatura embutida, três formatos de assinatura, seleção do destinatário correto em streaming, erros e fallback de frase secreta, backup e adulteração, importação sem rebaixar chave privada, rollback de geração, gravação atômica, parser HKP, roteamento de arquivos e renderização das páginas Fyne. O registro da validação desta entrega está em [docs/VALIDATION.md](docs/VALIDATION.md).

## Licença

Apache License 2.0. Consulte [LICENSE](LICENSE), [NOTICE](NOTICE) e [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
