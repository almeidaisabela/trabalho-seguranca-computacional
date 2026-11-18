# CONTRATO.md: decisões e formatos combinados

Este documento é a referência única entre os módulos. Se algo aqui mudar, avisar o
grupo e atualizar este arquivo **antes** de alterar o código.

Itens marcados com **[A DECIDIR]** ainda precisam de confirmação do grupo.

---

## 1. Decisões gerais

| Item | Decisão |
|---|---|
| Linguagem | Python 3.11+ |
| Dependências | `cryptography` (somente RSA). Todo o resto usa `hashlib`, `secrets` e aritmética modular nativa |
| Grupo | MODP de 2048 bits, RFC 3526 grupo 14 (`p` primo seguro, `q = (p-1)/2`, `g = 2`) |
| Subgrupo | `g = 2` gera o subgrupo de ordem `q`. Conferir no código: `pow(2, q, p) == 1` |
| Hash | SHA-256 |
| Assinatura | RSA 2048 bits, esquema PSS com SHA-256 |
| Aleatoriedade | Somente `secrets` (nunca `random`) |
| Expoentes | `r` e `x_i` sorteados em `[1, q-1]` com `secrets.randbelow(q - 1) + 1` |

### Inteiros grandes em JSON

JSON não representa inteiros de 2048 bits com segurança. **Todo inteiro grande é
gravado como string hexadecimal**, minúscula, sem prefixo `0x`.

```python
def int_para_hex(n: int) -> str:  return format(n, "x")
def hex_para_int(s: str) -> int:  return int(s, 16)
```

Bytes (assinaturas, hashes) também são gravados em hexadecimal minúsculo.

### Serialização canônica (o ponto que mais quebra a integração)

Tudo que é **assinado** ou **passa por hash** deve virar exatamente a mesma
sequência de bytes em qualquer módulo. Regra única:

```python
import json

def canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
```

```python
import hashlib

def sha256_hex(dados: bytes) -> str:
    return hashlib.sha256(dados).hexdigest()
```

Essas duas funções ficam em `crypto/serial.py`, e **ninguém reimplementa**. Todos
importam de lá.

---

## 2. Estrutura de pastas

```
main.py                 CLI unificada
CONTRATO.md             este arquivo
README.md               instruções de execução
requirements.txt
crypto/                 ElGamal, grupo, serialização
autoridades/            chaves das autoridades, chave conjunta, decifração
eleitor/                cadastro, voto, verificação de recibo
servidor/               fluxo de votação, quadro, recibos
auditor/                auditor independente
dados_publicos/         tudo que o auditor pode ler (gerado em execução)
dados_privados/         chaves privadas (nunca versionar, nunca ler no auditor)
testes/
demo/
relatorio/
exemplos/               exemplos de JSON versionados
```

### Regra de ouro

- O **auditor só lê `dados_publicos/`**. Nunca abre `dados_privados/` e nunca
  importa código de `servidor/`.
- `dados_publicos/` e `dados_privados/` são criados pelo código (`os.makedirs(..., exist_ok=True)`)
  caso não existam.

---

## 3. Arquivos públicos (`dados_publicos/`)

### 3.1 `config.json`

Gerado pelo comando `config`. **Imutável** depois da abertura da votação.

```json
{
  "eleicao_id": "eleicao-2026-01",
  "titulo": "Eleição de teste",
  "candidatos": [
    {"id": 0, "nome": "Candidato A"},
    {"id": 1, "nome": "Candidato B"}
  ],
  "grupo": {
    "nome": "RFC3526-MODP-2048",
    "p": "<hex>",
    "q": "<hex>",
    "g": "2"
  },
  "hash": "SHA-256",
  "autoridades": [
    {"id": "A1", "h_i": "<hex>"},
    {"id": "A2", "h_i": "<hex>"},
    {"id": "A3", "h_i": "<hex>"}
  ],
  "h": "<hex: produto dos h_i mod p>"
}
```

- Mínimo de 2 candidatos e 3 autoridades.
- `h = ∏ h_i mod p`. O auditor recalcula e confere.
- A ordem de `candidatos` define a ordem das cifras em cada cédula.

### 3.2 `eleitores.json`

Gerado pelo comando `cadastrar`, **antes** da abertura da votação.

```json
[
  {"id": "eleitor1", "chave_publica_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"},
  {"id": "eleitor2", "chave_publica_pem": "..."}
]
```

### 3.3 `servidor_pub.json`

```json
{"chave_publica_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}
```

Usada pelo eleitor e pelo auditor para verificar recibos e o registro de encerramento.

### 3.4 `quadro.json`

Lista de registros, somente de acréscimo, encadeados por hash.

```json
{
  "eleicao_id": "eleicao-2026-01",
  "registros": [
    {
      "indice": 0,
      "tipo": "cedula",
      "eleitor_id": "eleitor1",
      "cifras": [
        {"c1": "<hex>", "c2": "<hex>"},
        {"c1": "<hex>", "c2": "<hex>"}
      ],
      "assinatura_eleitor": "<hex>",
      "hash_anterior": "<hex>",
      "hash": "<hex>"
    }
  ]
}
```

**Encadeamento:**

```
hash_anterior do registro 0  =  sha256_hex(canonico(config))      # liga o quadro à configuração
hash_anterior do registro i  =  hash do registro i-1

hash do registro i = sha256_hex(canonico({
    "indice": i,
    "tipo": ...,
    "eleitor_id": ...,
    "cifras": ...,
    "assinatura_eleitor": ...,
    "hash_anterior": ...
}))
```

O campo `hash` não entra no cálculo do próprio hash.

**Sigilo pela ordem e pelo momento:** os registros **não têm timestamp**. A ordem de
chegada é pública, mas como as cédulas são cifradas, ela não revela o voto.

**Registro de encerramento (recomendado):** ao encerrar, o servidor acrescenta um
último registro, assim qualquer cédula inserida depois é detectada.

```json
{
  "indice": 3,
  "tipo": "encerramento",
  "assinatura_servidor": "<hex>",
  "hash_anterior": "<hex>",
  "hash": "<hex>"
}
```

A assinatura é sobre `canonico({"eleicao_id": ..., "tipo": "encerramento", "hash_anterior": ...})`.

### 3.5 `resultado.json`

**Só existe depois do encerramento e da apuração.** Nenhum total parcial pode
aparecer antes disso (propriedade de justiça).

```json
{
  "eleicao_id": "eleicao-2026-01",
  "num_cedulas": 3,
  "produtos": [
    {"candidato": 0, "C1": "<hex>", "C2": "<hex>"},
    {"candidato": 1, "C1": "<hex>", "C2": "<hex>"}
  ],
  "parciais": [
    {"autoridade_id": "A1", "D": ["<hex>", "<hex>"]},
    {"autoridade_id": "A2", "D": ["<hex>", "<hex>"]},
    {"autoridade_id": "A3", "D": ["<hex>", "<hex>"]}
  ],
  "totais": [
    {"candidato": 0, "votos": 2},
    {"candidato": 1, "votos": 1}
  ]
}
```

- `C1_j = ∏ c1` e `C2_j = ∏ c2` de todas as cédulas, para o candidato `j`.
- `D[j]` da autoridade `i` é `C1_j ^ x_i mod p` (decifração parcial).
- Verificação (auditor): `g^votos * ∏_i D_i[j]  ==  C2_j  (mod p)`.

---

## 4. Arquivos privados (`dados_privados/`)

Nunca versionados, nunca lidos pelo auditor.

```
dados_privados/
├── autoridades/
│   ├── A1.json          {"id": "A1", "x_i": "<hex>"}
│   ├── A2.json
│   └── A3.json
├── eleitores/
│   ├── eleitor1.pem     chave privada RSA
│   └── eleitor2.pem
└── servidor/
    ├── servidor_priv.pem
    └── estado.json      {"estado": "configurada|aberta|encerrada|apurada"}
```

Cada autoridade lê **somente o próprio arquivo**. Nenhum código pode reunir os `x_i`
em um único lugar nem somá-los.

---

## 5. Cédula, assinatura e recibo

### 5.1 Cédula

Uma cifra ElGamal exponencial por candidato, na ordem de `candidatos`:

- candidato escolhido: cifra de `m = 1`
- demais candidatos: cifra de `m = 0`

```
cifra(m) = (c1, c2) = (g^r mod p,  g^m * h^r mod p)     com r novo a cada cifra
```

**O valor `r` é descartado depois da cifragem** e nunca é gravado em disco nem
enviado. Isso é o que impede o recibo de servir como prova de voto (ver seção 8).

### 5.2 O que o eleitor assina

```python
a_assinar = canonico({
    "eleicao_id": ...,
    "eleitor_id": ...,
    "cifras": [{"c1": ..., "c2": ...}, ...]
})
assinatura_eleitor = RSA_PSS_SHA256_sign(chave_privada_eleitor, a_assinar)
```

O servidor verifica com a chave pública de `eleitores.json`, usando os mesmos bytes.

### 5.3 Recibo (assinado pelo servidor)

```json
{
  "eleicao_id": "eleicao-2026-01",
  "eleitor_id": "eleitor1",
  "indice": 0,
  "hash_registro": "<hex>",
  "assinatura_servidor": "<hex>"
}
```

A assinatura é sobre `canonico({"eleicao_id", "eleitor_id", "indice", "hash_registro"})`.
O recibo **não contém** `r`, o voto nem nenhuma informação que permita decifrar.

O eleitor guarda o recibo em `dados_privados/eleitores/<id>_recibo.json` (ou o
mostra na tela) e depois confere no quadro que o registro `indice` tem aquele
`hash_registro`.

---

## 6. Regras do servidor

Ao receber uma cédula, nesta ordem:

1. A votação está **aberta**? Senão, rejeitar.
2. O `eleitor_id` está em `eleitores.json`? Senão, rejeitar (elegibilidade).
3. A assinatura é válida? Senão, rejeitar.
4. O `eleitor_id` já tem registro no quadro? Se sim, rejeitar (unicidade).
5. Número de cifras igual ao número de candidatos? Senão, rejeitar.
6. Acrescentar ao quadro, calcular o hash encadeado e emitir o recibo.

Estados da eleição: `configurada → aberta → encerrada → apurada`. Nenhuma
transição volta atrás.

---

## 7. Regras do auditor

Lê apenas `dados_publicos/` e verifica:

1. `h == ∏ h_i` e os parâmetros do grupo conferem.
2. Cadeia de hashes do quadro (incluindo o primeiro elo com o `config`).
3. Cada assinatura de eleitor, com a chave de `eleitores.json`.
4. Todo `eleitor_id` do quadro está cadastrado (elegibilidade).
5. Nenhum `eleitor_id` aparece duas vezes (unicidade).
6. Registro de encerramento presente e nenhuma cédula depois dele.
7. Recalcula o produto homomórfico e compara com `produtos` de `resultado.json`.
8. Confere `g^votos * ∏ D_i[j] == C2_j` para cada candidato.
9. Saída final: **ELEIÇÃO VÁLIDA** ou **ELEIÇÃO ADULTERADA**, com a lista de falhas.

---

## 8. Decisões de segurança que o relatório precisa explicar

| Tema | Decisão atual |
|---|---|
| Eleitor cifra valor diferente de 0 ou 1 | Sem prova de 0/1 (OR-proof) o servidor não detecta. Documentar como limitação. **[A DECIDIR]** implementar a prova como extra |
| Todas as autoridades conspiram | Reconstroem `x = Σ x_i` e decifram cédulas individuais. Limitação do esquema |
| Autoridade ausente | Sem `D_i` de todas, o resultado não é decifrável, e a apuração falha (comportamento exigido) |
| Recibo prova o voto a terceiros? | Não, porque não contém `r` e o eleitor o descarta. Mas se o eleitor guardar `r`, pode provar. Documentar |
| Sigilo por ordem/momento | Sem timestamps, e cédulas cifradas com `r` novo |
| Prova de decifração parcial correta | **[A DECIDIR]** Chaum-Pedersen como extra |
| Auditor importa de `crypto/`? | **[A DECIDIR]** reaproveitar `crypto/serial.py` e a aritmética, ou ter cópia própria mínima (mais independente) |

---

## 9. Interfaces entre módulos (sugestão)

Os nomes abaixo servem para os integrantes trabalharem em paralelo com stubs.
Ajustem se necessário, mas atualizem este arquivo.

**`crypto/`** (Integrante 1)

```python
# crypto/params.py
P: int; Q: int; G: int

# crypto/serial.py
def canonico(obj) -> bytes
def sha256_hex(dados: bytes) -> str
def int_para_hex(n: int) -> str
def hex_para_int(s: str) -> int

# crypto/elgamal.py
def cifrar(m: int, h: int) -> tuple[int, int]
def cifrar_cedula(escolha: int, n_candidatos: int, h: int) -> list[tuple[int, int]]
def multiplicar(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]
def agregar(cedulas: list[list[tuple[int, int]]]) -> list[tuple[int, int]]
def log_discreto(alvo: int, max_m: int) -> int      # busca de 0 até max_m
```

**`autoridades/`** (Integrante 2)

```python
def gerar_chave(id_autoridade: str) -> int                      # salva x_i, devolve h_i
def chave_conjunta(hs: list[int]) -> int
def decifracao_parcial(id_autoridade: str, c1s: list[int]) -> list[int]
def decifrar_resultado(produtos, parciais, num_cedulas) -> list[int]   # falha se faltar autoridade
```

**`eleitor/`** (Integrante 3)

```python
def cadastrar(id_eleitor: str) -> None
def votar(id_eleitor: str, escolha: int) -> dict                # devolve o recibo
def verificar_recibo(recibo: dict) -> bool
def conferir_no_quadro(recibo: dict) -> bool
```

**`servidor/`** (Integrante 4)

```python
def abrir() -> None
def receber_cedula(cedula: dict) -> dict                        # devolve o recibo ou lança erro
def encerrar() -> None
```

**`auditor/`** (Integrante 5)

```python
def auditar() -> bool                                           # imprime o relatório
```

---

## 10. Comandos da CLI

```
python main.py config                       gera grupo, autoridades, chave conjunta, chave do servidor
python main.py cadastrar <id> [<id> ...]    gera pares RSA e registra eleitores
python main.py abrir                        abre a votação
python main.py votar <id> <candidato>       eleitor vota e recebe o recibo
python main.py verificar <id>               eleitor confere o recibo no quadro
python main.py encerrar                     fecha a votação
python main.py apurar [--sem <autoridade>]  decifração conjunta (falha se faltar alguma)
python main.py auditar                      auditor independente
```

---

## 11. Combinados de trabalho

- Commits no padrão `tipo(escopo): descrição` (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`).
- Cada integrante mantém testes do próprio módulo em `testes/`.
- Exemplos de JSON de cada arquivo da seção 3 ficam em `exemplos/` (com sufixo `.exemplo.json`).
- Ninguém altera um formato deste contrato sem avisar o grupo.