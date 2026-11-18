# Sistema de Votação Eletrônica Seguro

Trabalho de criptografia: eleição com ElGamal exponencial, chave conjunta das
autoridades, quadro público encadeado por hash, assinaturas RSA e auditor
independente.

**Integrantes:**  
Bianca Tavares da Silveira - 241022325  
Isabela de Almeida Pantaleão - 242040346    
Letícia Souza Santana Marinho - 241022399  
Maria Vitória Matos Mourão - 221039227  
Natalie Santos Tanoff - 241004588    


## Requisitos

- Python 3.11 ou superior
- Biblioteca `cryptography` (usada apenas para assinaturas RSA)

Todo o restante (ElGamal, chave conjunta, apuração homomórfica, encadeamento
por hash) é implementado com aritmética modular, `hashlib` e `secrets`.

## Instalação

```bash
# 1. Criar o ambiente virtual
python3 -m venv venv

# 2. Ativar
source venv/bin/activate          # Linux / macOS
venv\Scripts\Activate.ps1         # Windows (PowerShell)
venv\Scripts\activate.bat         # Windows (cmd)

# 3. Instalar dependências
pip install -r requirements.txt
```

Se o PowerShell bloquear a ativação, execute antes:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## Estrutura do projeto

```
main.py             CLI unificada
crypto/             ElGamal exponencial, parâmetros do grupo, apuração homomórfica
autoridades/        geração de chaves, chave conjunta, decifração parcial e conjunta
eleitor/            cadastro, cliente do eleitor, assinatura, verificação do recibo
servidor/           fluxo de votação, quadro público, recibos
auditor/            auditor independente (lê somente dados_publicos/)
dados_publicos/     configuração, eleitores, quadro, resultado (tudo auditável)
dados_privados/     chaves privadas (autoridades, eleitores, servidor)
testes/             testes unitários
demo/               scripts da demonstração
relatorio/          relatório técnico
```

## Fluxo de contribuição

Para manter a organização e a integridade do projeto, todas as alterações devem ser realizadas em branches próprias. Não são permitidos commits ou pushes diretamente na branch `main`.

O fluxo de trabalho deve seguir as seguintes etapas:

1. Atualizar a branch principal:
   ```bash
   git checkout main
   git pull origin main

2. Criar uma nova branch:
    ```bash
    git checkout -b tipo/nome-da-alteracao

3. Realizar as alterações e criar os commits:
    ```bash
    git add .
    git commit -m "tipo(escopo): descrição"

4. Enviar a branch para o GitHub:
    ```bash
    git push -u origin tipo/nome-da-alteracao

5. Abrir um Pull Request: 
    ```bash
    Criar um Pull Request direcionado à branch main para incorporar as alterações realizadas.

6. Realizar o merge: 
    ```bash
    Após abrir o Pull Request, realizar o merge para incorporar as alterações à branch main.

## Execução

Todos os comandos são executados na raiz do projeto, com o venv ativo.

```bash
python main.py --help
```

Fluxo completo de uma eleição (ajustar nomes e argumentos conforme a CLI final):

```bash
# 1. Configuração: candidatos, parâmetros do grupo e autoridades
python main.py config

# 2. Cadastro dos eleitores (gera pares RSA e registra as chaves públicas)
python main.py cadastrar

# 3. Votação
python main.py votar

# 4. Encerramento da votação
python main.py encerrar

# 5. Apuração (exige a participação de TODAS as autoridades)
python main.py apurar

# 6. Auditoria independente
python main.py auditar
```

## Demonstração

Os scripts em `demo/` cobrem os cenários obrigatórios:

| Cenário | Script |
|---|---|
| Eleição completa (3+ eleitores, 3+ autoridades) | `demo/demo_completa` |
| Tentativa de voto duplicado (rejeitada) | `demo/tenta_voto_duplo` |
| Adulteração de cédula no quadro e detecção pelo auditor | `demo/adultera_quadro` |
| Apuração sem todas as autoridades (falha) | `demo/tenta_apurar_sem_autoridade` |

## Testes

```bash
python -m pytest testes/
```

(Adicionar `pytest` ao `requirements.txt` se for usado.)

## Parâmetros criptográficos

- Grupo: MODP de 2048 bits (RFC 3526, grupo 14), conferir com o `CONTRATO.md`
- Hash: SHA-256
- Assinaturas: RSA (tamanho de chave: preencher)

Detalhes e justificativas estão no relatório técnico (`relatorio/`).