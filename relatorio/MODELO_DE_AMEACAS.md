# Modelo de ameaças (em tópicos)

Base para a **seção 3** e a **seção 9.3** do relatório. Os tópicos devem ser
reescritos em texto corrido, com as palavras do grupo. Os adversários são os
citados no enunciado; cada linha aponta o código que sustenta a afirmação.

Legenda: ✅ o sistema impede · 🔎 não impede, mas detecta · ❌ limitação.

---

## 1. Premissas de confiança

1. **Pelo menos uma autoridade é honesta** e não entrega o seu `x_i` (sustenta o sigilo).
2. **A criptografia é segura:** o logaritmo discreto é difícil no grupo de
   2048 bits, o RSA-PSS não pode ser falsificado e o SHA-256 não tem colisões conhecidas.
3. **O computador do eleitor é honesto:** cifra a escolha certa e descarta o `r`.
4. **O quadro é público:** eleitores, autoridades e auditor veem o mesmo quadro.
5. **O cadastro é correto:** quem recebe um par de chaves é de fato eleitor.
6. **Nesta implementação, tudo roda na mesma máquina.** Cada entidade só lê o
   próprio arquivo em `dados_privados/`. A separação é lógica, não física.

---

## 2. Adversários

### 2.1 Administrador malicioso
Controla o servidor e a chave RSA dele, decide quando abrir e encerrar, mantém
o cadastro e escreve no quadro.

| Ataque | Resultado | Mecanismo / onde |
|---|---|---|
| Ler o voto de alguém | ✅ | não tem nenhum `x_i` (`crypto/elgamal.py`) |
| Descobrir o voto pela ordem ou pelo horário | ✅ | sem horário no quadro; `r` novo a cada cifra (`servidor/quadro.py`) |
| Alterar as cifras de uma cédula | 🔎 | a assinatura do eleitor deixa de conferir (`auditor`, `cliente.conferir_no_quadro`) |
| Inserir cédula em nome de um eleitor | ✅ | precisaria da chave privada do eleitor (`servidor.receber_cedula`) |
| Alterar, remover ou reordenar registros | 🔎 | cadeia de hashes (`auditor.verificar_quadro`) |
| Remover uma cédula **refazendo** a cadeia e o encerramento | 🔎 só pelo eleitor | o recibo assinado pelo servidor prova que a cédula foi aceita (`cliente.conferir_no_quadro`) |
| Publicar um resultado falso | 🔎 | o auditor recalcula o produto e confere a decifração (`auditor.verificar_resultado`) |
| Forjar um quadro com a cédula de uma pessoa e pedir a apuração | 🔎 mitigado | cada autoridade apura um único quadro (seção 3) |
| Cadastrar eleitores falsos | ❌ | o cadastro é público, mas conferir quem é eleitor real fica fora do sistema |
| Recusar o voto de alguém | ❌ | o eleitor percebe que ficou sem recibo, mas não tem como provar a recusa |

### 2.2 Autoridade desonesta (uma)
Conhece o próprio `x_i` e escolhe o que publica.

| Ataque | Resultado | Mecanismo / onde |
|---|---|---|
| Decifrar votos sozinha | ✅ | faltam os `x_j` das outras (chave conjunta) |
| Escolher `h_i = g^y / (h_1·h_2)` para conhecer a chave inteira | ✅ | prova de Schnorr (`servidor.configurar`, `auditor.verificar_config`) |
| Publicar decifração parcial falsa para mudar o total | ✅ | prova de Chaum-Pedersen (`apuracao.decifrar_resultado`, `auditor`) |
| Decifrar antes do encerramento | ✅ | exige encerramento assinado no quadro (`autoridade.decifracao_parcial`) |
| Não comparecer à apuração | ❌ | sem ela, o resultado não é decifrado (pergunta (iii)) |

### 2.3 Todas as autoridades juntas (pergunta (ii))
| Ataque | Resultado | Por quê |
|---|---|---|
| Descobrir o voto de cada eleitor | ❌ | juntas, aplicam os `x_i` a cada cédula |
| Alterar o resultado | ✅ | Chaum-Pedersen obriga `D_i = C1^x_i` |
| Alterar ou inserir cédulas | ✅ | não têm as chaves dos eleitores |

### 2.4 Eleitor desonesto
Tem a própria chave privada e pode modificar o seu programa.

| Ataque | Resultado | Mecanismo / onde |
|---|---|---|
| Votar duas vezes | ✅ | servidor recusa (regra 4); auditor confere a unicidade |
| Votar em nome de outro | ✅ | assinatura (regra 3) |
| Votar sem estar cadastrado | ✅ | elegibilidade (regra 2) |
| Votar depois do encerramento | ✅ | estado da eleição (regra 1) |
| Enviar cifras inválidas (ex.: `c1 = 0`, que travaria a apuração) | ✅ | regra 5: uma cifra por candidato, todas no grupo |
| Cifrar valor diferente de 0 ou 1 (pergunta (i)) | ❌ detecção parcial | auditor confere soma dos votos = nº de cédulas |
| Provar a terceiros em quem votou (pergunta (iv)) | ✅ com programa honesto / ❌ se guardar o `r` | o recibo não tem `r` nem o voto |

### 2.5 Observador da rede
Nesta implementação o envio é uma chamada de função; os tópicos valem para uma
versão em rede.

| Ataque | Resultado | Por quê |
|---|---|---|
| Ler o voto em trânsito | ✅ | só trafegam cifras, que também ficam públicas |
| Modificar a cédula em trânsito | ✅ | a assinatura do eleitor deixa de conferir |
| Reenviar uma cédula capturada | ✅ | unicidade |
| Forjar um recibo | ✅ | assinatura do servidor |
| Bloquear a comunicação | ❌ | negação de serviço; o eleitor fica sem recibo |

---

## 3. A fraqueza encontrada nos testes: quadro falso

**O ataque:** o administrador tem a chave do servidor. Ele monta um quadro só
com a cédula de uma pessoa, refaz a cadeia de hashes, assina um encerramento
falso e pede a apuração. As autoridades conferem a cadeia e a assinatura, que
estão corretas, e decifram o "total". Como há uma cédula só, o total **é o
voto dessa pessoa**. Isso fere o requisito obrigatório de sigilo: "nenhuma
entidade isolada, incluindo o administrador".

**A correção:** cada autoridade **apura um único quadro**. Na primeira apuração,
ela anota o hash do quadro no próprio arquivo privado (`quadro_decifrado`). Um
quadro diferente é recusado depois disso (`autoridade.decifracao_parcial`).
Apurar o mesmo quadro de novo é permitido: por isso a demonstração "apurar sem
A3, depois com todas" funciona.

**O que resta (limitação):** se o ataque vier **antes** da apuração verdadeira,
ele revela um voto uma única vez. Depois disso, a apuração verdadeira é recusada
por todas as autoridades, então a fraude fica evidente.

**Testes:** `test_autoridade_decifra_um_unico_quadro` e
`test_quadro_falso_bloqueia_a_apuracao_verdadeira`.

---

## 4. Lista de limitações (para a seção 9.3)

1. Não há prova de que cada cifra é de 0 ou 1; a detecção é parcial (pergunta (i)).
2. Todas as autoridades juntas quebram o sigilo (pergunta (ii)).
3. Uma autoridade ausente impede a apuração (pergunta (iii)).
4. Um programa de eleitor modificado que guarde o `r` permite provar o voto (pergunta (iv)).
5. O administrador controla o cadastro e pode recusar votos.
6. Remover uma cédula refazendo tudo só é detectado pelo eleitor que confere o recibo.
7. Quadro falso: mitigado, mas pode revelar um voto uma vez (seção 3).
8. Quem votou (não em quem) é público.
9. Na demonstração, todas as chaves ficam na mesma máquina.
