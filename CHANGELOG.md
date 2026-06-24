# Changelog

## 1.0.0 — 2026-06-24

- Implementação inicial independente em Go/Fyne.
- Chaveiro, geração RSA, importação, exportação, revogação e confiança local.
- Criptografia/descriptografia de texto e arquivos, múltiplos destinatários e senha.
- Assinatura/verificação detached, inline e cleartext.
- Cofre nativo, cache de sessão, backup autenticado e HKP/HKPS.
- CLI, drag and drop, abertura de arquivos, metadata de pacote e documentação de integração macOS.
- Alertas de confiança, preferência de Key ID completo/curto e lembrete persistente de backup.
- Roteamento por conteúdo para chaves, mensagens e assinaturas abertas pelo sistema operacional.
- Seleção precisa do destinatário na descriptografia streaming e fallback seguro para segredos obsoletos no cofre.
- Testes criptográficos, de persistência, streaming, backup, gravação transacional e renderização Fyne.
