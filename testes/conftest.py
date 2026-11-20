"""Fixtures compartilhadas: cada teste roda numa pasta temporária própria."""
import pytest

from armazenamento import arquivos


@pytest.fixture
def pasta_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(arquivos, "PUBLICOS", tmp_path / "dados_publicos")
    monkeypatch.setattr(arquivos, "PRIVADOS", tmp_path / "dados_privados")
    return tmp_path


@pytest.fixture
def eleicao_aberta(pasta_tmp):
    """3 autoridades, 3 candidatos, 3 eleitores cadastrados, votação aberta."""
    from autoridades import autoridade
    from eleitor import cliente
    from servidor import servidor

    publicas = [autoridade.gerar_chave(a) for a in ("A1", "A2", "A3")]
    servidor.configurar("teste", "Teste", ["Ana", "Bruno", "Carla"], publicas)
    for e in ("e1", "e2", "e3"):
        cliente.cadastrar(e)
    servidor.abrir()
    return pasta_tmp


@pytest.fixture
def eleicao_encerrada(eleicao_aberta):
    """Votos: e1 -> 0, e2 -> 2, e3 -> 0. Votação encerrada."""
    from eleitor import cliente
    from servidor import servidor

    cliente.votar("e1", 0)
    cliente.votar("e2", 2)
    cliente.votar("e3", 0)
    servidor.encerrar()
    return eleicao_aberta
