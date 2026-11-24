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
demo/               simulação da demonstração ao vivo
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

## Demonstração (eleição interativa)

A demonstração é um programa com menu. Vocês escolhem a ação, quem faz e em que
ordem; o sistema mostra a criptografia de cada passo e barra o que for indevido.

```bash
python demo/simulacao.py
```

| Papel | Quem | Guarda em segredo | Envia |
|---|---|---|---|
| Autoridade | Maria, Leticia, Natalie | a própria chave `x_i` | `h_i` (início) e a decifração parcial `D_i` (apuração) |
| Eleitora | Bianca, Isabela, Ana | a própria chave privada RSA | a chave pública (cadastro) e a cédula assinada (voto) |
| Administrador | quem narrar | a chave do servidor | recibos e o encerramento |

Os arquivos da demonstração ficam em `demo/`, um por etapa do menu:

| Arquivo | Conteúdo |
|---|---|
| `preparacao.py` | opções 1 a 4: primo, chave conjunta, cadastro, abertura |
| `votacao.py` | opções 5 a 7: voto, conferência do recibo, encerramento |
| `resultado.py` | opções 8 a 10: apuração, auditoria, quadro público |
| `ataques.py` | opções 11 e 12: votar em nome de outra, adulterar o quadro |
| `tela.py`, `menu.py` | exibição na tela e o menu |
| `simulacao.py` | o sistema guarda as chaves privadas |
| `interacao.py` | cada pessoa guarda e entrega a própria chave |

### Roteiro sugerido (cobre os 4 itens obrigatórios)

| # | Opção do menu | O que acontece |
|---|---|---|
| 1 | `R` e depois `1` | recomeça; mostra o primo de 2048 bits e confere os parâmetros do grupo |
| 2 | `2` | Maria, Leticia e Natalie sorteiam suas chaves; o servidor monta a chave conjunta |
| 3 | `3` | Bianca, Isabela e Ana geram seus pares RSA e enviam a chave pública |
| 4 | `4` | abre a votação |
| 5 | `5` (três vezes) | cada eleitora escolhe o candidato; aparecem `r`, `c1`, `c2`, assinatura, quadro e recibo |
| 6 | `10` | quadro público: cada cédula com eleitora, cifras, assinatura e hashes encadeados |
| 7 | `5` com Bianca de novo | **[obrigatório]** voto duplo: bloqueado |
| 8 | `8` | Leticia tenta ver o resultado antes do fim: bloqueado |
| 9 | `6` | Bianca confere o próprio recibo no quadro |
| 10 | `7` | encerra a votação |
| 11 | `8` digitando `Maria, Leticia` | **[obrigatório]** apuração sem a Natalie: falha |
| 12 | `8` com todas | apuração: cada autoridade envia seu `D`, e a busca acha os totais |
| 13 | `9` | auditoria: ELEIÇÃO VÁLIDA |
| 14 | `12` com Isabela, depois `9` e `6` | **[obrigatório]** adulteração: o auditor e a Isabela detectam |

Os itens obrigatórios "eleição completa com 3 eleitores e 3 autoridades" e os três
marcados acima estão cobertos. Outros ataques disponíveis no menu: votar sem
estar cadastrada (opção `5` com um nome novo), votar em nome de outra (`11`) e
cadastrar depois da abertura (`3`). Depois da adulteração, use `R` para recomeçar.

### Interação: cada uma guarda a própria chave

```bash
python demo/interacao.py
```

O mesmo menu, com uma diferença: **o sistema não guarda nenhuma chave privada.**
Quando uma pessoa gera a chave, ela recebe um arquivo na pasta `chaveiro/`
(`Maria.chave`, `Bianca.pem`...). Esse arquivo é dela: pode movê-lo para um pen
drive ou outra pasta. Quando precisar da chave (votar, conferir o recibo,
apurar), ela **arrasta o arquivo para o terminal** e aperta Enter.

Ataques que só aparecem aqui: entregar a chave de outra pessoa. Por exemplo, a
Isabela vota arrastando a chave da Bianca (assinatura inválida), ou a Maria
apura com a chave da Leticia ("essa chave não é a de Maria").

As chaves **públicas** continuam com o sistema, porque servem para todos
conferirem assinaturas e provas. A chave do **servidor** também, porque é do
próprio servidor. A pasta `chaveiro/` não vai para o git.

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