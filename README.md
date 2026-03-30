Aqui está o README em **RAW (Markdown puro, pronto para salvar como `README.md`)**:

```markdown
# 🧪 Forensic Framework – Linux Acquisition

Framework em Bash para **aquisição forense em ambientes Linux**, com foco em **integridade, rastreabilidade e cadeia de custódia**.

---

## 📌 Visão Geral

Este projeto fornece scripts para aquisição de evidências digitais com:

- 📁 Coleta estruturada de dados de cadeia de custódia  
- 💽 Geração de imagens forenses no formato **E01 (FTK Imager)**  
- 🎯 Suporte a destino primário (**Target**) e opcional **Backup**  
- 🔐 Integração com volumes criptografados **VeraCrypt**  
- 📊 Geração completa de **logs, auditoria e metalogs**  

---

## 🗂️ Estrutura do Projeto

```

.
├── acquire_linux.sh        # Script principal
├── acquire_linux_tui.sh    # Interface interativa (TUI)
├── LICENSE
└── README.md

````

---

## ⚙️ Funcionalidades

### 🔒 Segurança e Confiabilidade
- Modo estrito: `set -euo pipefail`
- Sanitização de entradas com regex
- Proteção de senhas (`read -s`)
- Controle de logging de segredos

### 🧾 Cadeia de Custódia
- Hash adicional SHA-256
- Assinatura:
  - `hashchain` (padrão)
  - `gpg` (opcional)
- Registro de:
  - `uname -a`
  - versões de ferramentas
  - timestamp em UTC

### 💾 Aquisição Forense
- Imagem E01 via `ftkimager`
- Validação por:
  - hash
  - contagem de arquivos
- Suporte a:
  - Target único
  - Target + Backup com sincronização

### 🔍 Descoberta de Discos
- `legacy`: `dmesg`, `fdisk`
- `modern`: `lsblk`, `blkid`, `udevadm`
- `both`

### 🧩 Arquitetura
- Modularização em funções
- Cleanup automático (`trap`)
- Modo simulação (`--dry-run`)
- Interface interativa opcional (TUI)

---

## 🚀 Uso

### Execução básica

```bash
./acquire_linux.sh
````

### Opções disponíveis

```bash
./acquire_linux.sh --dry-run
./acquire_linux.sh --disk-mode=both
./acquire_linux.sh --sign-mode=gpg
./acquire_linux.sh --allow-secret-logging
./acquire_linux.sh --no-sha256
./acquire_linux.sh --no-tui
```

---

## 🔄 Fluxo de Aquisição

O processo segue etapas controladas:

1. Introdução e validação de pré-requisitos
2. Coleta de dados (examinador, caso, local etc.)
3. Verificação de data/hora
4. Descoberta e seleção do disco de evidência
5. Preparação do Target (e Backup opcional)
6. Criação de trilhas de auditoria
7. Coleta técnica do disco (modelo, serial, RO mode)
8. Análise de partições e offsets
9. Configuração e confirmação final
10. Aquisição da imagem E01
11. Validação (hash + arquivos)
12. Geração de relatórios e logs
13. Encerramento com metalogs

---

## 🔁 Modos de Execução

### Sem Backup

* Aquisição direta para o Target
* Validação local

### Com Backup

* Aquisição no Target
* Replicação via `rsync`
* Validação em múltiplos destinos

---

## 📦 Dependências

### Base

* `bash`, `awk`, `sed`, `grep`
* `fdisk`, `dmesg`, `hdparm`
* `mount`, `umount`, `find`, `column`

### Forense

* `ftkimager`
* `veracrypt`
* `xmount`
* `smartctl`
* `dmidecode`
* `lshw`
* `rsync`
* `ntfslabel`

### Hash

* `md5sum`, `sha256sum`

### Opcionais

* `gpg` (assinatura)
* `lsblk`, `blkid`, `udevadm` (modo moderno)

---

## ⚠️ Boas Práticas

* Execute como **root** ou usuário com privilégios equivalentes
* Sempre valide o **mapeamento de discos** antes da aquisição
* Utilize `--dry-run` em novos ambientes
* Para compliance:

  * `--sign-mode=hashchain`
  * ou `--sign-mode=gpg`

---

## ⚠️ Riscos Conhecidos

* Possíveis inconsistências em variáveis ou sintaxe (dependendo da versão do script)
* Necessidade de validação prévia em ambiente controlado

---

## 📊 Saídas Geradas

* 📄 Audit logs
* 📄 Relatórios de aquisição
* 📄 Inventário de discos
* 📄 File listings e estatísticas
* 📄 Metalogs (TSV / estruturados)

---

## 🔐 Compliance & Forense

Este framework foi projetado considerando boas práticas alinhadas a:

* Cadeia de custódia
* Integridade de evidência
* Reprodutibilidade
* Auditoria completa

---

## 📜 Licença

Consulte o arquivo `LICENSE`.

```
```
