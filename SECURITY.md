# Segurança

## Modelo de ameaça

O PGP Client protege conteúdo contra leitura ou alteração por terceiros quando as chaves, frases secretas, algoritmos e endpoints usados são confiáveis. Ele não protege um computador já comprometido, um usuário logado com privilégios equivalentes, malware com acesso ao processo, captura de teclado/tela ou substituição maliciosa do binário.

## Proteção das chaves

- Chaves privadas podem ser armazenadas criptografadas por frase secreta; esse é o modo recomendado.
- O arquivo local de uma chave privada recebe permissão `0600` em sistemas POSIX.
- Frases secretas lembradas são delegadas ao cofre nativo do sistema operacional.
- O cache de sessão mantém cópias em memória por tempo limitado e sobrescreve os buffers ao expirar, substituir ou bloquear a sessão. A linguagem Go e o coletor de lixo não permitem garantir eliminação física de todas as cópias transitórias.
- Exportações privadas e backups devem ser tratados como material altamente sensível.

## Integridade de arquivos

As operações de arquivo do núcleo — criptografia, descriptografia, assinatura, verificação inline e exportação usada pela CLI — além da persistência do chaveiro, gravam em arquivo temporário no diretório de destino e só confirmam o resultado após concluir e sincronizar a escrita. Em Windows, onde a renomeação sobre um destino existente não é suportada da mesma forma, a implementação tenta a renomeação e só remove o destino após essa falha específica de plataforma. Salvamentos iniciados pelos diálogos nativos da GUI usam o fluxo fornecido pelo Fyne; a aplicação valida escrita/fechamento e aplica permissões restritivas quando o destino é um arquivo local privado.

Conteúdo extraído de uma assinatura inline não substitui o destino enquanto a assinatura não for válida. Em descriptografia, o OpenPGP assegura a autenticação do ciphertext antes da confirmação do temporário; uma assinatura embutida inválida é informada separadamente da integridade criptográfica da mensagem.

## Backup

O formato `.pgpbackup` usa:

- Argon2id para derivação de chave;
- salt aleatório de 128 bits;
- AES-256-GCM;
- nonce aleatório;
- autenticação do cabeçalho de formato como associated data;
- limites de tamanho e de custo Argon2id durante a restauração.

Uma senha fraca continua vulnerável a tentativa offline. Use uma frase longa e exclusiva e mantenha cópias offline testadas.

## Rede e keyservers

- O cliente aceita HKPS/HTTPS; HTTP é restrito a `localhost` e `127.0.0.1` para testes.
- Redirecionamentos inseguros e cadeias excessivas são bloqueados.
- Requisições têm timeout e respostas são limitadas a 16 MiB.
- Publicar uma chave pode divulgar identidades e endereços de e-mail. Alguns keyservers não permitem remoção completa posterior.
- Uma chave baixada não se torna confiável automaticamente; valide o fingerprint por canal independente.

## Limitações criptográficas

- A geração local usa RSA 2048/3072/4096 para manter paridade com o aplicativo de referência.
- O cliente importa outros algoritmos suportados pela biblioteca, mas nem toda combinação histórica ou extensão OpenPGP é garantida.
- Confiança e marcação de fingerprint verificado são metadados locais; não implementam uma Web of Trust completa.
- Revogação altera a chave local. Para avisar terceiros, exporte/publique a versão revogada em canais adequados.

## Relato de vulnerabilidade

Não publique dados sensíveis, chaves privadas, frases secretas ou backups em uma issue. Ao manter este projeto em um repositório, configure um canal privado de segurança e inclua versão, sistema operacional, passos mínimos e impacto observado.
