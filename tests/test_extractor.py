from phasesnare import extrair_ipv4, extrair_sha256, extrair_cves, extrair_md5, extrair_sha1, analisar_conteudo, formatar_resultados_json
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

def test_extrair_md5_valido():
    md5_encontrado = extrair_md5('5d41402abc4b2a76b9719d911017c592')

    assert md5_encontrado == ['5d41402abc4b2a76b9719d911017c592']

def test_extrair_md5_invalido():
    md5_encontrado = extrair_md5('5d41402abc4b2a76b9719d911017c59')

    assert md5_encontrado == []

def test_extrair_sha1_valido():
    sha1_encontrado = extrair_sha1('da39a3ee5e6b4b0d3255bfef95601890afd80709')

    assert sha1_encontrado == ['da39a3ee5e6b4b0d3255bfef95601890afd80709']

def test_extrair_sha1_invalido():
    sha1_encontrado = extrair_sha1('da39a3ee5e6b4b0d3255bfef95601890afd8070')

    assert sha1_encontrado == []

def test_analisar_conteudo():
    resultados = analisar_conteudo("""
        Connection from 192.168.1.10
        Malformed address 256.300.12.1
        Exploit targeting cve-2024-3094
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    """)

    assert resultados == {
        "ipv4": ["192.168.1.10"],
        "ipv4_falsos_candidatos": ["256.300.12.1"],
        "md5": [
            "5d41402abc4b2a76b9719d911017c592"
        ],
        "sha256": [
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ],
        "sha1": [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
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