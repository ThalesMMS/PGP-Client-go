# Arquitetura

## Objetivos

A estrutura separa apresentação, casos de uso criptográficos e persistência. Isso evita que callbacks Fyne implementem regras de segurança e permite que GUI, CLI e testes usem a mesma semântica.

## Camadas

### `internal/model`

Contém DTOs, enums e erros compartilhados: projeção de chave, preferências, solicitações de criptografia, descriptografia, assinatura, verificação e resultados.

### `internal/storage`

Responsável por:

- diretório de configuração;
- certificados públicos e privados ASCII-armored;
- metadados locais de confiança/verificação;
- preferências;
- abstração do cofre nativo;
- cache temporário de frases secretas.

A abstração `SecretStore` permite substituir o cofre do sistema por uma implementação em memória nos testes.

### `internal/pgp`

`Service` é a fachada de casos de uso. Ele coordena:

- geração, importação, exportação, revogação e remoção de chaves;
- desbloqueio e obtenção de frases secretas;
- criptografia/descriptografia em memória ou streaming;
- assinatura/verificação em memória ou streaming;
- backup e restauração;
- HKP/HKPS.

A camada usa GopenPGP e ProtonMail `go-crypto`, mas não conhece widgets, diálogos ou estado de janela.

### `internal/ui`

`Desktop` mantém apenas estado de apresentação: página atual, chave selecionada, arquivo recebido e referências Fyne. Operações potencialmente lentas são executadas fora da thread de UI e seus resultados retornam por `fyne.Do`.

### `internal/fileutil`

Centraliza a escrita transacional. `PendingFile` permite adiar a confirmação até depois de validações, como a verificação de uma assinatura inline.

### `cmd`

- `pgp-client` cria o serviço padrão, encaminha argumentos de arquivos e inicia a GUI.
- `pgp-client-cli` expõe os mesmos casos de uso para scripts, CI e integrações do sistema.

## Fluxo de dependências

```text
cmd/pgp-client     ─┐
                    ├─> internal/pgp ─> internal/storage ─> filesystem/keyring
internal/ui        ─┘        │
                             ├─> internal/model
                             └─> internal/fileutil

cmd/pgp-client-cli ──────────┘
```

`storage` não depende de `pgp` ou `ui`; `pgp` não depende de `ui`. Esse sentido reduz ciclos e permite substituir infraestrutura em testes.

## Concorrência

- `Service` protege preferências com `RWMutex`.
- `Store` serializa mutações do chaveiro e dos JSONs.
- `SecretCache` protege seu mapa e sobrescreve buffers removidos.
- A UI executa casos de uso em goroutines e faz mutações visuais na thread Fyne.
- Operações de arquivos observam `context.Context` em blocos de 128 KiB.

## Persistência

Arquivos são gravados no mesmo diretório do destino e confirmados por rename. Isso evita arquivos finais parciais em falhas de escrita, cancelamento ou validação. O formato do chaveiro é deliberadamente simples e auditável:

```text
pgp-client-go/
  keys/
    <FINGERPRINT>.public.asc
    <FINGERPRINT>.secret.asc
  metadata.json
  settings.json
```

Ao importar uma versão pública de uma chave que já possui material privado local, o armazenamento preserva a versão privada.
