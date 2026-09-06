from phasesnare import extrair_ipv4, extrair_sha256, extrair_cves, extrair_md5, extrair_sha1, analisar_conteudo, formatar_resultados_json, extrair_ipv6, extrair_urls, extrair_emails, extrair_dominios
import json

def test_extrair_ipv4_valido():
    ipv4_validos, ipv4_invalidos = extrair_ipv4('192.168.0.112')

    assert ipv4_validos == ['192.168.0.112']
    assert ipv4_invalidos == []

def test_extrair_ipv6_invalido():
    ipv6_validos, ipv6_invalidos = extrair_ipv6("2001:db8:zzzz::1")

    assert ipv6_validos == []
    assert ipv6_invalidos == ["2001:db8:zzzz::1"]

def test_extrair_ipv6_valido():
    ipv6_validos, ipv6_invalidos = extrair_ipv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')

    assert ipv6_validos == ['2001:0db8:85a3:0000:0000:8a2e:0370:7334']
    assert ipv6_invalidos == []

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
        IPv6 connection from 2001:db8::10
        Invalid IPv6 2001:db8:zzzz::1
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        Request to https://example.com/login
        Nigerian prince phishing sent to karendoe@mail.com
    """)

    assert resultados == {
        "ipv4": ["192.168.1.10"],
        "ipv4_falsos_candidatos": ["256.300.12.1"],
        "ipv6": ["2001:db8::10"],
        "ipv6_falsos_candidatos": ["2001:db8:zzzz::1"],
        "md5": [
            "5d41402abc4b2a76b9719d911017c592"
        ],
        "sha256": [
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ],
        "sha1": [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ],
        "cves": ["CVE-2024-3094"],
        "urls": ["https://example.com/login"],
        "urls_falsos_candidatos": [],
        "emails": ["karendoe@mail.com"],
        "dominios": ["example.com", "mail.com"]
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

def test_extrair_url_valida():
    urls, urls_invalidas = extrair_urls(
        "Request to https://example.com/login"
    )

    assert urls == ["https://example.com/login"]
    assert urls_invalidas == []

def test_extrair_url_com_porta_query():
    urls, urls_invalidas = extrair_urls(
        "Request to https://example.net:8443/admin?id=42"
    )

    assert urls == [
        "https://example.net:8443/admin?id=42"
    ]
    assert urls_invalidas == []

def test_extrair_url_falsa_e_separar():
    urls, urls_invalidas = extrair_urls(
        "http://:8080/test"
    )

    assert urls == []
    assert urls_invalidas == [
        "http://:8080/test"
    ]

def test_url_ainda_nao_detectavel():
    urls, urls_invalidas = extrair_urls(
        "hxxp://example.com/payload"
    )

    assert urls == []
    assert urls_invalidas == []

def test_extrair_email_valido():
    emails = extrair_emails(
        "Hey dude, send me an e-mail at b1gp4ul@hellyeah.com"
    )

    assert emails == [
        "b1gp4ul@hellyeah.com"
    ]

def test_falhar_em_extrair_email_invalido():
    emails = extrair_emails(
        "Hey dude, sent you an e-mail from b1gp4ul@@.hellyeah.com"
    )

    assert emails == []

def test_extrair_dominio_valido():
    dominios = extrair_dominios(
        "Here's the free GTA VI download link for PC: https://veryevillink.com/downloadm4lw4r3"
    )

    assert dominios == [
        "veryevillink.com"
    ]

def test_nao_extrair_dominio_com_hifen_inicial():
    dominios = extrair_dominios("-bad.example.com")

    assert dominios == []


def test_nao_extrair_parte_de_dominio_invalido():
    dominios = extrair_dominios("bad_domain.example.com")

    assert dominios == []


def test_preservar_subdominio_www():
    dominios = extrair_dominios("www.example.com")

    assert dominios == ["www.example.com"]

def test_nao_extrair_email_com_dominio_malformado():
    emails = extrair_emails("user@example..com")

    assert emails == []