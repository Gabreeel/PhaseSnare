from iochunter import extrair_ipv4, extrair_sha256, extrair_cves, analisar_conteudo, formatar_resultados_json
import json

def test_extrair_ipv4_valido():
    ipv4_validos, ipv4_invalidos = extrair_ipv4('192.168.0.112')

    assert ipv4_validos == ['192.168.0.112']
    assert ipv4_invalidos == []

def test_extrair_ipv4_invalido():
    ipv4_validos, ipv4_invalidos = extrair_ipv4("256.300.12.1")

    assert ipv4_validos == []
    assert ipv4_invalidos == ["256.300.12.1"]

def test_extrair_sha256_valido():
    sha256_encontrados = extrair_sha256('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    assert sha256_encontrados == ['ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad']

def test_extrair_sha256_invalido():
    sha256_encontrados = extrair_sha256('macarena')

    assert sha256_encontrados == []

def test_extrair_cve_minusculo_normalizado():
    cves = extrair_cves('cve-2024-3094')

    assert cves == ['CVE-2024-3094']

def test_analisar_conteudo():
    resultados = analisar_conteudo("""
                                    Connection from 192.168.1.10
                                    Malformed address 256.300.12.1
                                    Exploit targeting cve-2024-3094
                                    Hash: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
                                """)
    assert resultados == {
    "ipv4": ["192.168.1.10"],
    "ipv4_falsos_candidatos": ["256.300.12.1"],
    "sha256": [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    ],
    "cves": ["CVE-2024-3094"]
}

def test_formatar_resultados_json():
    resultados = {
    "ipv4": ["192.168.1.10"],
    "ipv4_falsos_candidatos": [],
    "sha256": [],
    "cves": ["CVE-2024-3094"]
}

    texto_json = formatar_resultados_json(resultados)
    resultado_reconvertido = json.loads(texto_json)

    assert resultado_reconvertido == resultados