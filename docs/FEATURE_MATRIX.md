# Matriz de funcionalidades

| Área | Situação | Observações |
|---|---|---|
| Chaveiro pesquisável e filtrável | Implementado | Pública/secreta, validade, revogação, confiança e verificação local |
| Geração RSA 2048/3072/4096 | Implementado | Validade e frase secreta opcionais |
| Importar/exportar/excluir | Implementado | Binário e ASCII armor; exportação privada com modo restritivo |
| Revogação local | Implementado | A chave revogada pode ser exportada/publicada |
| Fingerprint copiar/comparar | Implementado | Marcação de verificação é metadado local |
| Criptografia de texto | Implementado | Múltiplos destinatários, senha, armor, compressão, assinatura |
| Criptografia de arquivo | Implementado | Streaming e confirmação transacional |
| Descriptografia | Implementado | Chave privada ou senha; assinatura embutida |
| Assinatura/verificação | Implementado | Detached, inline e cleartext; texto e arquivo |
| Cofre nativo de credenciais | Implementado | macOS Keychain, Secret Service/KWallet e Windows Credential Manager via `go-keyring` |
| Cache/bloqueio de sessão | Implementado | TTL configurável e bloqueio manual |
| Backup criptografado | Implementado | Chaves, metadados e preferências opcionais na restauração |
| HKP/HKPS | Implementado | Pesquisa, download e upload |
| Drag and drop | Implementado | Roteamento por conteúdo/extensão |
| Abertura de arquivo pela aplicação | Implementado | Argumentos de processo e metadata MIME |
| CLI para automação | Implementado | Mesma camada de serviço da GUI |
| Finder Sync Extension | Não incluído | Requer target nativo App Extension em Xcode/Swift/Obj-C |
| Quick Look Extension | Não incluído | Requer target e assinatura nativos do macOS |
| Thumbnail Extension | Não incluído | Requer target nativo do macOS |
| Share Extension | Não incluído | Requer target App Extension e entitlements |

## Interpretação

A paridade funcional cobre os fluxos OpenPGP e a experiência principal do aplicativo. Recursos que vivem dentro do Finder ou do sistema de extensões da Apple não pertencem ao runtime Fyne; a alternativa entregue é a combinação de abertura de arquivos, drag and drop, CLI e Quick Actions do Automator.
