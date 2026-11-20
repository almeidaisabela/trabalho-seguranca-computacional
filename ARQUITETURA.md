# ARQUITETURA.md: camadas, divisão do trabalho e passo a passo

Este documento explica **como o sistema está organizado**, **quem é responsável
por cada parte** e **o que acontece em cada etapa da eleição**. Ele é a base para
o relatório e para a arguição. Cada integrante deve ser capaz de explicar,
linha a linha, os arquivos da sua parte.

---

## 1. Arquitetura em camadas

```
┌──────────────────────────────────────────────────────────────────────┐
│ CAMADA 4 · APRESENTAÇÃO          main.py (CLI)          demo/        │
│   lê argumentos, chama a camada 3, mostra o resultado                │
├──────────────────────────────────────────────────────────────────────┤
│ CAMADA 3 · APLICAÇÃO (entidades do sistema)                          │
│   eleitor/cliente.py   servidor/servidor.py   autoridades/autoridade │
│                        servidor/quadro.py     autoridades/apuracao   │
├──────────────────────────────────────────────────────────────────────┤
│ CAMADA 2 · PERSISTÊNCIA          armazenamento/arquivos.py           │
│   única que sabe onde ficam dados_publicos/ e dados_privados/        │
├──────────────────────────────────────────────────────────────────────┤
│ CAMADA 1 · CRIPTOGRAFIA          crypto/                             │
│   params (grupo) · serial (hash) · elgamal · provas · assinatura     │
└──────────────────────────────────────────────────────────────────────┘

        AUDITOR (programa separado): auditor/  ──usa só──▶  CAMADA 1
                                     lê só dados_publicos/
```

**Regra de dependência:** cada camada só chama a camada de baixo. A camada 1
não conhece eleição nenhuma (só matemática); a camada 2 não conhece criptografia
(só arquivos); a camada 4 não tem nenhuma regra de segurança.

Por que isso ajuda na segurança:

- As regras de segurança ficam concentradas na camada 3. Para conferir a
  unicidade, por exemplo, basta ler `servidor.receber_cedula`.
- A matemática fica isolada na camada 1 e é testada sozinha (`testes/test_crypto.py`).
- O **auditor não importa o servidor**, só as primitivas. Ele recalcula hashes,
  produtos e verificações por conta própria, a partir dos arquivos públicos.
  Se o servidor tiver um bug ou for malicioso, o auditor não "herda" o problema.

### Entidades e responsabilidades

| Entidade | Código | O que faz | O que **não** tem |
|---|---|---|---|
| Eleitor | `eleitor/cliente.py` | gera par RSA, cifra e assina a cédula, confere o recibo e o quadro | a chave de decifração |
| Servidor de votação (administrador) | `servidor/servidor.py` | publica a config, cadastra eleitores, valida e publica cédulas, emite recibos, encerra | nenhum `x_i` (não decifra nada) |
| Autoridades eleitorais (≥ 3) | `autoridades/` | cada uma gera seu `x_i`; após o encerramento, decifra **só o total** | os `x_j` das outras |
| Quadro público | `servidor/quadro.py` + `dados_publicos/quadro.json` | lista somente de acréscimo, encadeada por SHA-256 | — |
| Auditor | `auditor/` | refaz todas as conferências a partir dos dados públicos | acesso a `dados_privados/` |

---

## 2. Divisão entre as 5 integrantes

Cada integrante é dona de uma parte do código, do teste correspondente, de
seções do relatório e de um trecho da demonstração. O peso na nota do código
está entre parênteses.

| Integrante | Parte | Arquivos | Testes | Critério do código | Seções do relatório | Na demo |
|---|---|---|---|---|---|---|
| **1** | Camada 1: Criptografia | `crypto/params.py`, `serial.py`, `elgamal.py`, `provas.py`, `assinatura.py` | `test_crypto.py` | Cifragem e apuração homomórfica (1,0) | Esquema de cifragem; parâmetros e algoritmos | explica a cifra e a multiplicação das cédulas |
| **2** | Autoridades | `autoridades/autoridade.py`, `apuracao.py` | `test_autoridades.py` | Chave conjunta e decifração (0,75) | Chave conjunta e decifração; perguntas (ii) e (iii) | `config` e apuração **sem A3** (falha) |
| **3** | Eleitor + CLI | `eleitor/cliente.py`, `main.py` | `test_eleitor.py` | Assinaturas e recibo (0,5) | Autenticação; verificação individual; pergunta (iv) | cadastro, votos, `verificar` |
| **4** | Servidor + Quadro + Persistência | `servidor/servidor.py`, `servidor/quadro.py`, `armazenamento/arquivos.py` | `test_servidor.py` | Quadro encadeado (0,75) + elegibilidade e unicidade | Arquitetura; integridade do quadro | voto duplo e intruso (rejeitados) |
| **5** | Auditor + Demonstração | `auditor/`, `demo/` | `test_auditor.py` | Auditor independente (0,5) | Auditoria; modelo de ameaças; pergunta (i) | adulteração do quadro e detecção |

Seções compartilhadas do relatório (cada uma escreve um pedaço): análise de
segurança e dificuldades/aprendizados.

---

## 3. Passo a passo de uma eleição

Notação: `p` primo de 2048 bits, `q = (p-1)/2`, `g = 2`. Tudo é calculado mod `p`.

### Etapa 1 · Configuração (`python main.py config`)

1. Cada autoridade `i` (função `autoridade.gerar_chave`):
   - sorteia `x_i` em `[1, q-1]` com `secrets` e grava **só** em
     `dados_privados/autoridades/Ai.json`;
   - calcula `h_i = g^x_i` e uma **prova de Schnorr** de que conhece `x_i`;
   - entrega ao servidor apenas `h_i` e a prova.
2. O servidor (`servidor.configurar`):
   - confere que cada `h_i` está no grupo e que cada prova é válida;
   - calcula a chave conjunta `h = h_1 · h_2 · h_3 = g^(x_1+x_2+x_3)`;
   - gera seu par RSA (para assinar recibos, abertura e encerramento);
   - publica `config.json`, `servidor_pub.json`, `eleitores.json` vazio e o quadro vazio.

Ninguém calcula `x = x_1 + x_2 + x_3`. Para decifrar é preciso a ajuda das três.

> Por que a prova de Schnorr? Sem ela, a última autoridade poderia escolher
> `h_3 = g^y / (h_1 · h_2)`. Aí `h = g^y` e ela conheceria sozinha a chave
> completa `y`. Com a prova, ela teria de saber o log de `h_3`, que não sabe.

### Etapa 2 · Cadastro (`python main.py cadastrar eleitor1 eleitor2 eleitor3`)

O eleitor gera seu par RSA-2048 (`cliente.cadastrar`). A chave privada fica em
`dados_privados/eleitores/<id>.pem`. A pública é registrada no servidor
(`servidor.registrar_eleitor`), que só aceita cadastros **antes** da abertura.

### Etapa 3 · Abertura (`python main.py abrir`)

O servidor muda o estado para `aberta` e grava no quadro o registro de
**abertura**, com o SHA-256 da lista de eleitores, assinado pelo servidor.
A partir daí o cadastro fica congelado: se alguém incluir um eleitor depois,
o hash não bate e o auditor acusa.

### Etapa 4 · Votação (`python main.py votar eleitor1 0`)

No eleitor (`cliente.montar_cedula`):

1. Para cada candidato `j`, cifra `m_j` (1 para o escolhido e 0 para os demais):
   `c1 = g^r`, `c2 = g^m_j · h^r`, com um `r` novo para cada cifra. O `r` é
   descartado dentro de `elgamal.cifrar`.
2. Assina com RSA-PSS os bytes `canonico({eleicao_id, eleitor_id, cifras})`.

No servidor (`servidor.receber_cedula`), nesta ordem:

1. A votação está aberta? (justiça)
2. O eleitor está cadastrado? (elegibilidade)
3. A assinatura confere com a chave cadastrada? (autenticação)
4. O eleitor já tem cédula no quadro? (unicidade)
5. Há uma cifra por candidato e todas pertencem ao grupo?
6. Acrescenta ao quadro (`quadro.acrescentar`) e devolve um **recibo**
   `{eleicao_id, eleitor_id, indice, hash_registro}` assinado pelo servidor.

O eleitor confere a assinatura do recibo e o guarda.

### Etapa 5 · Verificação individual (`python main.py verificar eleitor1`)

O eleitor (`cliente.conferir_no_quadro`) confere que:

- o recibo foi assinado pelo servidor;
- o registro de número `indice` é dele;
- o hash recalculado do registro é igual ao do recibo;
- a assinatura no quadro confere com a **sua própria** chave, ou seja, as
  cifras publicadas são exatamente as que ele assinou.

### Etapa 6 · Encerramento (`python main.py encerrar`)

O servidor muda o estado para `encerrada` e grava o registro de **encerramento**
assinado. Nada entra depois dele.

### Etapa 7 · Apuração (`python main.py apurar`)

1. Cada autoridade (`autoridade.decifracao_parcial`), sozinha:
   - confere a cadeia do quadro e a assinatura do encerramento. Se a votação
     não acabou, **recusa** (ninguém vê resultado parcial);
   - calcula ela mesma o produto de todas as cédulas, para cada candidato `j`:
     `C1_j = ∏ c1`, `C2_j = ∏ c2`. Isso é uma cifra de `total_j`, porque os
     expoentes somam: `(g^R, g^total · h^R)`;
   - publica `D_ij = C1_j^x_i` e uma **prova de Chaum-Pedersen** de que usou o
     mesmo `x_i` de `h_i`.
2. A combinação (`apuracao.decifrar_resultado`):
   - confere as provas de Chaum-Pedersen;
   - calcula `C2_j / (D_1j · D_2j · D_3j) = g^total_j`, pois `∏ D_ij = h^R`;
   - acha `total_j` testando `g^0, g^1, …, g^num_cedulas`.
3. Publica `resultado.json` (produtos, decifrações parciais com provas e totais).

**Sem uma autoridade** (`apurar --sem A3`), a divisão deixa sobrar `h_3^R`,
que é um número "aleatório" do grupo. A busca não acha nenhum `g^k` e a
apuração falha, como exigido.

As autoridades nunca decifram uma cédula individual, só o produto.

### Etapa 8 · Auditoria (`python main.py auditar` ou `python -m auditor`)

O auditor lê apenas `dados_publicos/` e confere:

1. grupo padrão, ≥ 2 candidatos, ≥ 3 autoridades, provas de Schnorr e `h = ∏ h_i`;
2. cadeia de hashes completa, a partir do hash da `config`;
3. abertura única no início (com o hash do cadastro) e encerramento único no fim, ambos assinados;
4. para cada cédula: eleitor cadastrado, primeira cédula do eleitor, assinatura válida e cifras no grupo;
5. produto homomórfico recalculado igual ao publicado, todas as autoridades presentes,
   provas de Chaum-Pedersen válidas, `g^votos · ∏ D_i = C2` e soma dos votos = nº de cédulas.

Saída: **ELEIÇÃO VÁLIDA** ou **ELEIÇÃO ADULTERADA** com a lista de falhas.

---

## 4. Como cada requisito é atendido

| Requisito | Mecanismo | Onde |
|---|---|---|
| Sigilo do voto | ElGamal com chave conjunta: nenhuma entidade isolada tem `x`. Só o produto é decifrado. Sem timestamps, e `r` novo em cada cifra (a ordem não revela nada). | `crypto/elgamal.py`, `autoridades/` |
| Integridade | Cadeia SHA-256 desde a `config` + assinaturas dos eleitores + encerramento assinado + recibos | `servidor/quadro.py`, `auditor/` |
| Elegibilidade | Só chaves cadastradas antes da abertura; cadastro congelado no registro de abertura | `servidor.receber_cedula`, `servidor.abrir` |
| Unicidade | Servidor recusa o segundo voto; o auditor confere que nenhum `eleitor_id` se repete | `servidor.receber_cedula`, `auditor` |
| Justiça | Autoridades se recusam a decifrar antes do encerramento assinado | `autoridade.decifracao_parcial` |
| Verificabilidade individual | Recibo assinado + conferência no quadro com a própria chave | `cliente.conferir_no_quadro` |
| Auditabilidade | Programa separado, só dados públicos, só a camada 1 | `auditor/` |

---

## 5. Perguntas obrigatórias do relatório (pontos de partida)

Os textos abaixo são **resumos para orientar**. O relatório deve ser escrito
pelo grupo, com as próprias palavras.

**(i) Eleitor cifra um valor diferente de 0 ou 1.** O servidor não percebe,
porque a cifra não revela `m`. Um eleitor poderia cifrar `2` (voto em dobro),
`1` para todos os candidatos, ou `-1` (`g^(q-1)`) para tirar um voto de alguém.
Defesas parciais do nosso sistema: (a) o auditor confere que a soma dos totais é
igual ao número de cédulas, o que pega votos em vários candidatos ou valores
grandes; (b) se um total ficar fora de `[0, num_cedulas]`, a busca falha e a
apuração não termina. **Limitação:** uma cédula como `(+2, -1, 0)` soma 1 e
passa. A solução completa é uma prova disjuntiva de Chaum-Pedersen ("esta cifra
é de 0 OU de 1") mais uma prova de que a soma da cédula é 1. Ela não foi
implementada.

**(ii) Todas as autoridades conspiram.** Juntas, elas podem aplicar seus `x_i`
a cada cédula individual e descobrir o voto de cada eleitor, já que o quadro
liga `eleitor_id` à cédula. O **sigilo** cai. A **integridade** continua: elas
não conseguem alterar cédulas (assinaturas e hashes) nem forjar o resultado
(provas de Chaum-Pedersen).

**(iii) Uma autoridade não participa.** O resultado não pode ser decifrado
(esquema n-de-n). Isso garante que nenhuma maioria apure sem a minoria, mas uma
única autoridade pode **impedir** a apuração (ataque de disponibilidade).
Alternativa: limiar t-de-n com compartilhamento de segredo de Shamir.

**(iv) O recibo prova o voto a terceiros?** Não. O recibo só tem índice, hash e
assinatura do servidor. Para provar o conteúdo da cifra seria preciso o `r`
(descartado) ou a chave da eleição. **Limitação:** um eleitor que use um
cliente modificado e guarde o `r` consegue provar o voto: mostra `r`, e o
terceiro confere `c1 = g^r` e `c2 / h^r = g^m`. O sistema não é resistente
a coação nesse cenário.

### Outras limitações a citar

- O administrador tem a chave RSA do servidor. Se ele **remover uma cédula
  inteira** e refizer toda a cadeia, o encerramento e a apuração, o auditor
  sozinho não percebe. Quem detecta é o eleitor, no `verificar`: o recibo
  assinado pelo servidor é a prova de que a cédula foi aceita.
- O administrador pode cadastrar eleitores falsos **antes** da abertura. A lista
  é pública e congelada, mas a conferência de quem é eleitor real fica fora do sistema.
- Quem votou (não em quem) é público, porque o quadro mostra os `eleitor_id`.
- Se todos votarem no mesmo candidato, o resultado revela o voto de todos. Isso
  vale para qualquer eleição.

---

## 6. Parâmetros criptográficos

| Item | Escolha | Justificativa |
|---|---|---|
| Grupo | RFC 3526 MODP-2048 (grupo 14), `g = 2`, subgrupo de ordem `q` | padronizado, primo seguro de 2048 bits (≈ 112 bits de segurança), sem "primo escolhido a dedo" |
| Expoentes | `secrets.randbelow(q-1) + 1` | gerador criptograficamente seguro |
| Hash | SHA-256 | resistente a colisão; usado no encadeamento e no Fiat-Shamir |
| Assinatura | RSA-2048, PSS com SHA-256 (`cryptography`) | permitido pelo enunciado; PSS é o padding recomendado |
| Provas | Schnorr e Chaum-Pedersen não interativas (Fiat-Shamir) | protegem contra autoridades desonestas |
| Serialização | JSON canônico (chaves ordenadas, sem espaços) | mesmos bytes para assinar e conferir em todos os módulos |
