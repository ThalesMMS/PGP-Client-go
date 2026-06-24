# Integração com macOS

## Aplicativo

Empacote no macOS para produzir `PGP Client.app`:

```bash
make package
```

Mova o bundle para `/Applications` e abra-o uma vez para o Launch Services registrar metadata e associação de tipos declarada no pacote.

## Abrir arquivos no PGP Client

O executável gráfico interpreta caminhos recebidos na linha de comando:

- chaves com extensão `.key`/`.pub` ou conteúdo ASCII-armored: importação;
- mensagens PGP: descriptografia;
- assinaturas `.sig`, ASCII-armored ou cleartext: verificação;
- outros arquivos: criptografia.

No Finder, **Abrir com → PGP Client** usa esse fluxo quando a associação estiver disponível. Também é possível arrastar o arquivo para a janela.

## Quick Action pelo Automator

1. Abra o Automator e crie uma **Ação Rápida**.
2. Configure para receber **arquivos ou pastas** no Finder.
3. Adicione **Executar Script do Shell**.
4. Selecione `/bin/zsh` e passe a entrada **como argumentos**.
5. Cole:

```zsh
for file in "$@"; do
  open -a "PGP Client" -- "$file"
done
```

O script equivalente está em `scripts/macos/open-with-pgp-client.sh`.

## Automação direta por CLI

Instale `pgp-client-cli` em um diretório presente no `PATH` e use fingerprints completos:

```bash
pgp-client-cli encrypt \
  --recipient FINGERPRINT_DO_DESTINATARIO \
  documento.pdf documento.pdf.gpg
```

Para uma Quick Action de criptografia sem uso de chave secreta, configure `PGP_CLIENT_RECIPIENT` e use `scripts/macos/encrypt-selected.sh`. Não grave frases secretas dentro de scripts do Automator.

## Extensões nativas

Finder Sync, Quick Look, Thumbnail e Share Extension são bundles separados carregados pelo macOS. Eles exigem targets de App Extension, Info.plist específicos, sandbox/entitlements, assinatura e, em alguns casos, App Groups. A GUI Fyne e um binário Go não geram esses targets automaticamente.

Uma expansão futura pode manter o motor OpenPGP em Go e adicionar um workspace Xcode mínimo que invoque o CLI ou uma biblioteca C compartilhada. Isso aumenta consideravelmente a superfície de distribuição e deve incluir testes de sandbox, revisão de caminhos e proteção contra vazamento de plaintext em previews.
