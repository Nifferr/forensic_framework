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

## Dependências esperadas

Document acquire_linux file with analysis

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
