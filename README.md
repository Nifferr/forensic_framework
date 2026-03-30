# Forensic Framework - Linux Acquisition

Este repositório inclui um script principal para aquisição forense em Linux com foco em:

- coleta estruturada de informações de cadeia de custódia,
- imagem E01 com FTK Imager,
- destino primário (Target) e opcional Backup,
- suporte a volumes criptografados VeraCrypt,
- geração de logs/audit/sumário e metalogs para rastreabilidade.

## Arquivo principal

- `acquire_linux.sh`
- `acquire_linux_tui.sh`
- `ESTRUCTURE.md`

## Principais melhorias implementadas

- Variáveis refatoradas para padrão Bash seguro (`snake_case`, sem espaços).
- Modo estrito habilitado: `set -euo pipefail` + `IFS` seguro.
- `trap` de cleanup para desmontagem segura e limpeza de diretórios temporários.
- Sanitização de entrada com regex para:
  - devices (`sd[a-z]+`)
  - IDs (`[A-Za-z0-9._-]+`)
  - compressão FTK (`0-9`)
- Senhas com `read -s`.
- Opção para registrar ou não segredos em logs (`--allow-secret-logging`).
- Checagem de pré-requisitos com abort claro.
- Opções para cadeia de custódia aprimorada:
  - SHA-256 adicional (`--no-sha256` para desabilitar)
  - assinatura por `hashchain` (padrão), `gpg` ou desabilitada
  - registro de `uname -a`, versão de ferramentas e UTC
- Modo de descoberta de disco:
  - `legacy` (dmesg/fdisk)
  - `modern` (lsblk/blkid/udevadm)
  - `both`
- Modularização em funções para manutenção/testabilidade.
- Modo `--dry-run` para checklist sem captura efetiva.
- TUI simples (menu `select`) sem dependências externas (`--no-tui` para desativar).

## Uso rápido

```bash
./acquire_linux.sh
```

### Opções

```bash
./acquire_linux.sh --dry-run
./acquire_linux.sh --disk-mode=both
./acquire_linux.sh --sign-mode=gpg
./acquire_linux.sh --allow-secret-logging
./acquire_linux.sh --no-sha256
./acquire_linux.sh --no-tui
```

## Dependências esperadasDocument acquire_linux file with analysis
30 de mar. · forensic_framework · master ·
+808-1440
Leia meu arquivo acquire_linux e explique por sessoes o que ele faz formatado em markdown e analise os possiveis gaps e indique melhorias

Perfeito — li o acquire_linux.sh e abaixo está uma análise por seções, com os gaps e melhorias recomendadas.
Comandos que usei para analisar

    pwd && rg --files | rg 'acquire_linux|AGENTS.md'

    nl -ba acquire_linux.sh | sed -n '1,260p'

    nl -ba acquire_linux.sh | sed -n '261,520p'

    nl -ba acquire_linux.sh | sed -n '521,900p'

    nl -ba acquire_linux.sh | sed -n '901,1280p'

    nl -ba acquire_linux.sh | sed -n '1281,1600p'

Visão geral do que o script faz

O script é um fluxo interativo de aquisição forense em Linux com foco em:

    coletar dados de contexto (examinador, custódia, local, data/hora),

    identificar disco de evidência e disco(s) de destino,

    montar/rotular alvo (e opcional backup) com VeraCrypt,

    gerar imagem E01 via FTK Imager,

    validar por hash/contagem de arquivos,

    gerar relatórios/audit logs/metalog para cadeia de custódia.

Seções do script (explicação)
1) Introdução e pré-requisitos

Mostra orientações operacionais (dados necessários, discos, VeraCrypt etc.) e força confirmação manual (y) para continuar.
2) Coleta de dados da aquisição

Captura informações do examinador, custodiante, projeto, código, localização e tag de host.
3) Validação de data/hora local

Pergunta se data/hora do sistema estão corretas; se não, solicita entrada manual. Isso é útil para consistência de relatório forense.
4) Descoberta de discos e seleção da evidência

Exibe dispositivos via dmesg/fdisk e pede o device da evidência. Em seguida solicita ID da evidência.
5) Conexão e preparação do Target

Pede conexão do target, reexibe mapeamento de discos, coleta device/ID do target, rotula partição NTFS, monta volume VeraCrypt e cria pasta para armazenar artefatos.
6) Criação de trilhas de auditoria iniciais

Cria auditfile, arquivo de info completa do host e arquivo de discos; registra dados de aquisição e host (dmidecode/lshw).
7) Coleta técnica do disco de evidência

Obtém modelo/serial/firmware, coloca read-only (hdparm -r1), calcula setores/bytes e escolhe blocksize com base em divisibilidade de LBA.
8) Partições e offsets para validação

Extrai tabela de partições e calcula offsets (partição 1/2) para montar imagem depois e comparar contagens de arquivos.
9) Configuração de compressão e confirmação final

Solicita taxa de compressão (0-9) e confirmação antes de iniciar imagem.
10) Inventário detalhado do Target

Coleta metadata do target (model/serial/scsi/mount/table/free space), inclusive confirmação manual de serial.
11) Fluxo sem backup (backup_drive == n)

    Gera imagem E01 com FTK Imager.

    Coleta hash, bytes/setores.

    Monta evidência e imagem para comparar contagem de arquivos.

    Gera file list, contagem por tipo, resumo TSV e finaliza audit log.

12) Fluxo com backup (backup_drive == y)

    Conecta/mapeia backup, monta VeraCrypt.

    Faz imagem no target, copia E01 ao backup com rsync.

    Calcula hash para evidência/target/backup.

    Repete validações de contagem e resumo.

    Copia logs entre mídias.

13) Geração de metalogs e encerramento

Extrai estatísticas por extensão (PST/OST/PDF etc.), grava metadados em formatos log/TSV/pipe, copia para backup (se existir), alerta sonoro e aguarda comando “Close”.
Principais gaps (riscos) identificados
1) Script tem erros de sintaxe/variáveis inválidas

Há variáveis com espaço no nome (evid_Evidence ID, tgt_Evidence ID, etc.), o que quebra Bash em múltiplos pontos.

Também há atribuição com espaços ao redor de = (inválido), ex.: tgt_dev_serialOld = ....
2) Comandos e variáveis possivelmente inexistentes/inconsistentes

    Uso de variável não definida ($evid_Evidence em vez de $evid_Evidence ID).

    Referências inconsistentes a caminhos/mountpoints (/media/barget_raw, typo).

    String solta mma no meio do fluxo.

3) Falta de hardening e tratamento de erro

Não há set -euo pipefail, nem checagens robustas de falha de comandos críticos (ftkimager, veracrypt, mount, rsync). Se falhar, pode seguir adiante e produzir relatório inconsistente.
4) Segurança operacional

Senhas de VeraCrypt são lidas sem mascaramento (read simples) e ainda persistidas no metalog (tgt_pw, bkup_pw) — risco grave de exposição.
5) Dependências antigas / obsoletas

O script fixa versão FTK 3.1.1 de 2012 em log, e depende fortemente de utilitários/saídas legadas (fdisk, dmesg, /proc/scsi/scsi) vulneráveis a variação entre distros modernas.
6) Confiabilidade forense parcial

Ainda que faça hash e file count, não há evidência de controles mais robustos (ex.: assinatura digital dos relatórios, hash SHA-256 obrigatório, verificação explícita de write-blocker físico/estado real de somente leitura além de hdparm).
Melhorias recomendadas (priorizadas)

    Refatorar nomes de variáveis para padrão seguro Bash (snake_case, sem espaços) e corrigir todas as referências quebradas.

    Adicionar modo estrito: set -euo pipefail, IFS seguro, trap para cleanup e desmontagem.

    Sanitizar entradas do usuário (regex para device, IDs, compressão 0-9) e quote consistente ("$var").

    Não registrar segredos: usar read -s para senha e remover senhas de qualquer log/metalog.

    Checar pré-requisitos no início (command -v ftkimager veracrypt xmount smartctl ...) com abort claro.

    Melhorar cadeia de custódia:

        gerar SHA-256 além de MD5,

        assinar logs/summary (GPG ou hash encadeado),

        salvar uname -a, versão exata de tools e timezone UTC.

    Substituir parsing frágil de dmesg/fdisk por lsblk -J, blkid, udevadm (mais estáveis).

    Modularizar em funções (collect_host_info, mount_target, image_e01, verify_counts, etc.) para manutenção/testabilidade.

    Corrigir bugs lógicos no ramo backup (mountpoints e contagens) e remover resíduos (mma).

    Dry-run/checklist mode para validar ambiente sem iniciar aquisição (bom para operação em campo).

Se quiser, no próximo passo eu posso te devolver uma versão “v2 hardening” desse script com essas correções aplicadas e organizada em funções, mantendo a mesma lógica operacional.
Refatorar nomes de variáveis para padrão seguro Bash (snake_case, sem espaços) e corrigir todas as referências quebradas. Mas mantenha referencias e comandos que sao exportados em logs.

    Adicionar modo estrito: set -euo pipefail, IFS seguro, trap para cleanup e desmontagem segura.

    Sanitizar entradas do usuário (regex para device, IDs, compressão 0-9) e quote consistente ("$var").

    Fornecer opcao para registrar segredos: usar read -s para senha e apenas registrar senhas se permitido.

    Checar pré-requisitos no início (command -v ftkimager veracrypt xmount smartctl ...) com abort claro.

    Melhorar cadeia de custódia:

        opcao de gerar SHA-256 além de MD5,

        assinar logs/summary (GPG ou hash encadeado),

        salvar uname -a, versão exata de tools e timezone UTC.

    Nao substituir parsing frágil de dmesg/fdisk, mas adicionar tambem opcao por lsblk -J, blkid, udevadm (mais estáveis).

    Modularizar em funções (collect_host_info, mount_target, image_e01, verify_counts, etc.) para manutenção/testabilidade e eficiencia.

    Corrigir bugs lógicos no ramo backup (mountpoints e contagens) e remover resíduos (mma).

    Dry-run/checklist mode para validar ambiente sem iniciar aquisição (bom para operação em campo).

    Deixar o script mais proficional e se possivel deixar um TUI (terminal ui) com poucas ou nenhuma dependencia, para evitar muitos erros de typo. o ideal e que seja so este arquivo executado para captura de informacoes e imagem forense em bacups criptografados em veracrypt

Criar um arquivo README

Concluído — refatorei o script e criei o README conforme solicitado.
✅ O que foi feito

    Refatorei acquire_linux.sh com variáveis em snake_case (sem espaços) e corrigi referências quebradas.

    Adicionei modo estrito:

        set -euo pipefail

        IFS seguro

        trap com cleanup de mounts/diretórios.

    Adicionei validação de entradas com regex para:

        device (sd[a-z]+)

        IDs ([A-Za-z0-9._-]+)

        compressão (0-9)

    Padronizei quoting ("$var").

    Senhas agora usam read -s.

    Incluí opção para logar segredos apenas quando permitido:

        --allow-secret-logging

    Adicionei checagem de pré-requisitos no início (command -v ...) com abort claro.

    Melhorei cadeia de custódia com:

        hash SHA-256 opcional (além de MD5),

        assinatura por hashchain (default), gpg ou none,

        registro de uname -a, versões de ferramentas e UTC.

    Mantive parsing legado (dmesg/fdisk) e adicionei opção moderna (lsblk -J, blkid, udevadm) via --disk-mode.

    Modularizei em funções (collect_host_info, mount_veracrypt_volume, image_e01, verify_hashes, etc.).

    Corrigi problemas lógicos no ramo de backup e removi resíduos.

    Adicionei modo --dry-run.

    Adicionei TUI simples sem dependências externas (menu select), com opção --no-tui.

    Criei README.md com uso, opções, dependências e boas práticas.

Arquivos alterados

    acquire_linux.sh

    README.md

Commit

    736f886 — Refactor Linux acquisition script with safety, modularization, and README

PR

Usei a ferramenta make_pr com título e corpo descritivos, conforme solicitado.
Testing

    ✅ bash -n acquire_linux.sh

    ✅ git status --short

    ✅ git add acquire_linux.sh README.md && git commit -m "Refactor Linux acquisition script with safety, modularization, and README"

Notes

    O script foi modernizado e profissionalizado, mas é uma refatoração grande: recomendo executar primeiro com --dry-run no seu ambiente real antes de coleta efetiva.

    Mantive referências/comandos principais nos logs, porém a estrutura interna foi simplificada e reorganizada para robustez e manutenção.

ajuste criar um acquire_linux_tui.sh com as alteracoes, crie um ESTRUCTURE.md pra explicar cada script sh na pasta
Summary

    Criei um novo script dedicado acquire_linux_tui.sh com fluxo TUI (menu select) para reduzir erros de digitação, incluindo modo estrito (set -euo pipefail), validação por regex, entrada de segredo com read -s, dry-run, assinatura (hashchain/gpg/none), hash SHA-256 opcional e suporte a backup criptografado com VeraCrypt.

    Mantive as chaves de referência esperadas em logs (evid_Evidence ID, tgt_Evidence ID, bkup_Evidence ID) no metalog do TUI, com opção de mascarar ou registrar segredos conforme flag.

    Criei ESTRUCTURE.md explicando cada script .sh da pasta e o fluxo recomendado de operação (incluindo uso de --dry-run e execução via TUI).

    Atualizei o README.md para incluir referências ao novo acquire_linux_tui.sh e ao documento ESTRUCTURE.md.

Commit realizado: ab73d26 (Add dedicated TUI acquisition script and script structure guide).

PR criado via ferramenta make_pr com título: Add acquire_linux_tui.sh and ESTRUCTURE.md documentation.

Testing

    ✅ bash -n acquire_linux.sh

    ✅ bash -n acquire_linux_tui.sh

    ✅ git status --short

    ✅ git add acquire_linux_tui.sh ESTRUCTURE.md README.md && git commit -m "Add dedicated TUI acquisition script and script structure guide"


# Forensic Framework - Linux Acquisition

Este repositório inclui um script principal para aquisição forense em Linux com foco em:

- coleta estruturada de informações de cadeia de custódia,
- imagem E01 com FTK Imager,
- destino primário (Target) e opcional Backup,
- suporte a volumes criptografados VeraCrypt,
- geração de logs/audit/sumário e metalogs para rastreabilidade.


- Base: `bash`, `awk`, `sed`, `grep`, `fdisk`, `dmesg`, `hdparm`, `mount`, `umount`, `find`, `column`
- Forense: `ftkimager`, `veracrypt`, `xmount`, `smartctl`, `dmidecode`, `lshw`, `rsync`, `ntfslabel`
- Hash: `md5sum`, `sha256sum`
- Opcional assinatura: `gpg` (quando `--sign-mode=gpg`)
- Descoberta moderna: `lsblk`, `blkid`, `udevadm` (quando `--disk-mode=modern|both`)

## Observações operacionais

- Execute como usuário com privilégios compatíveis com montagem/imagem de disco.
- Sempre valide o mapeamento de discos antes de iniciar.
- Prefira usar `--dry-run` em ambientes novos antes da coleta real.
- Se for exigência de compliance, mantenha `--sign-mode=hashchain` ou `--sign-mode=gpg`.

## Licença
Veja o arquivo `LICENSE`.
