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

- Python 3.9 ou superior (testado com 3.9.6)
- Biblioteca `cryptography` (usada apenas para assinaturas RSA)
- `pytest` (somente para os testes)

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

## Estrutura do projeto (arquitetura em camadas)

```
main.py             CAMADA 4  apresentação: CLI unificada
eleitor/            CAMADA 3  cliente do eleitor: cadastro, voto, recibo, verificação
servidor/           CAMADA 3  servidor de votação e quadro público encadeado
autoridades/        CAMADA 3  chaves das autoridades, decifração parcial e apuração
armazenamento/      CAMADA 2  persistência: leitura e gravação dos JSON
crypto/             CAMADA 1  grupo, hash canônico, ElGamal, provas, RSA
auditor/            programa separado: usa só crypto/ e lê só dados_publicos/
dados_publicos/     configuração, eleitores, quadro, resultado (tudo auditável)
dados_privados/     chaves privadas (autoridades, eleitores, servidor)
testes/             um arquivo de testes por integrante
demo/               roteiro e cenários da demonstração
exemplos/           exemplos reais de cada JSON
relatorio/          relatório técnico
```

A explicação das camadas, a divisão entre as integrantes e o passo a passo de
cada etapa estão em [`ARQUITETURA.md`](ARQUITETURA.md). Os formatos dos arquivos
estão em [`CONTRATO.md`](CONTRATO.md).

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

Fluxo completo de uma eleição:

```bash
python main.py resetar                                       # apaga a eleição anterior
python main.py config --candidatos Ana Bruno Carla --autoridades 3
python main.py cadastrar eleitor1 eleitor2 eleitor3          # antes da abertura
python main.py abrir
python main.py votar eleitor1 0                              # candidato pelo número
python main.py votar eleitor2 2
python main.py votar eleitor3 0
python main.py verificar eleitor1                            # confere o recibo no quadro
python main.py encerrar
python main.py apurar                                        # exige TODAS as autoridades
python main.py auditar                                       # auditor independente
```

O auditor também roda como programa separado, apontando para qualquer pasta pública:

```bash
python -m auditor dados_publicos
```

## Demonstração

Roteiro completo da apresentação (cobre os 4 itens obrigatórios, na ordem):

```bash
python demo/roteiro.py --pausar
```

`--pausar` espera um Enter entre as etapas. Os cenários também rodam separados:

| Cenário | Comando | Pré-condição |
|---|---|---|
| Eleição completa (3 eleitores, 3 autoridades) | `python demo/demo_completa.py` | nenhuma |
| Voto duplo e eleitor não cadastrado (rejeitados) | `python demo/tenta_voto_duplo.py` | votação aberta, eleitor1 já votou |
| Apuração sem uma autoridade (falha) | `python demo/tenta_apurar_sem_autoridade.py A3` | votação encerrada |
| Adulteração de cédula e detecção pelo auditor | `python demo/adultera_quadro.py [--recalcula]` | eleição apurada |
| Desfazer a adulteração | `python demo/adultera_quadro.py --restaurar` | — |

## Testes

```bash
python -m pytest testes/ -v
```

## Parâmetros criptográficos

- Grupo: MODP de 2048 bits (RFC 3526, grupo 14), `g = 2`, subgrupo de ordem `q = (p-1)/2`
- Hash: SHA-256
- Assinaturas: RSA de 2048 bits, PSS com SHA-256
- Provas: Schnorr (chaves das autoridades) e Chaum-Pedersen (decifração parcial), com Fiat-Shamir

Detalhes e justificativas estão no relatório técnico (`relatorio/`).