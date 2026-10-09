from phasesnare import main, extrair_ipv4, extrair_sha256, extrair_cves, extrair_md5, extrair_sha1, analisar_conteudo, formatar_resultados_json, extrair_ipv6, extrair_urls, extrair_emails, extrair_dominios, deduplicar_resultados, normalizar_hashes, normalizar_resultados, formatar_resultados_txt, comparar_valores, comparar_resultados
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

def test_deduplicar_resultados():
    resultados = {
        "ipv4": [
            "192.0.2.10",
            "192.0.2.10",
            "10.0.0.5"
        ],
        "cves": [
            "CVE-2024-3094",
            "CVE-2024-3094",
            "CVE-2021-44228"
        ]
    }

    resultados_unicos = deduplicar_resultados(resultados)

    assert resultados_unicos == {
        "ipv4": [
            "192.0.2.10",
            "10.0.0.5"
        ],
        "cves": [
            "CVE-2024-3094",
            "CVE-2021-44228"
        ]
    }

def test_deduplicar_resultados_preserva_ordem():
    resultados = {
        "dominios": [
            "first.example",
            "second.example",
            "first.example"
        ]
    }

    resultados_unicos = deduplicar_resultados(resultados)

    assert resultados_unicos["dominios"] == [
        "first.example",
        "second.example"
    ]


def test_formatar_resultados_txt():
    resultados = {
        "ipv4": ["192.0.2.10"],
        "ipv4_falsos_candidatos": [],
        "ipv6": [],
        "ipv6_falsos_candidatos": [],
        "md5": [],
        "sha256": [],
        "sha1": [],
        "cves": [],
        "urls": [],
        "urls_falsos_candidatos": [],
        "emails": [],
        "dominios": []
    }

    texto = formatar_resultados_txt(resultados)

    assert "192.0.2.10" in texto
    assert "Quantidade de endereços IPv4 válidos: 1" in texto


def test_main_nao_sobrescrevendo_entrada(tmp_path, capsys):
    arquivo = tmp_path / "entrada.txt"
    conteudo_original = "Connection from 192.0.2.10\n"
    arquivo.write_text(conteudo_original, encoding="utf-8")

    codigo = main(str(arquivo), "json", output=str(arquivo))
    capturado = capsys.readouterr()

    assert codigo == 1
    assert arquivo.read_text(encoding="utf-8") == conteudo_original
    assert capturado.out == ""
    assert "Erro: o arquivo de saída não pode ser o mesmo da entrada." in (
        capturado.err
    )



def test_main_salva_json(tmp_path, capsys):
    entrada = tmp_path / "entrada.txt"
    destino = tmp_path / "resultado.json"
    entrada.write_text("Connection from 192.0.2.10\n", encoding="utf-8")

    codigo = main(str(entrada), "json", output=str(destino))

    resultados = json.loads(destino.read_text(encoding="utf-8"))

    assert resultados["ipv4"] == ["192.0.2.10"]
    assert entrada.read_text(encoding="utf-8") == (
        "Connection from 192.0.2.10\n"
    )
    assert "Resultado salvo em:" in capsys.readouterr().out
    assert codigo == 0 


def test_main_informa_falha_de_gravacao(tmp_path, capsys):
    entrada = tmp_path / "entrada.txt"
    destino = tmp_path / "pasta_inexistente" / "resultado.json"
    entrada.write_text("Connection from 192.0.2.10\n", encoding="utf-8")

    codigo = main(str(entrada), "json", output=str(destino))
    capturado = capsys.readouterr()
    mensagem = capturado.err

    assert capturado.out == "" 
    assert "Erro ao salvar arquivo" in mensagem
    assert str(destino) in mensagem
    assert "Erro ao ler arquivo" not in mensagem
    assert "Resultado salvo em:" not in mensagem
    assert not destino.exists()
    assert codigo == 1
    

def test_main_retorna_erro_quando_entrada_nao_existe(tmp_path, capsys):
    entrada = tmp_path / "inexistente.txt"
    codigo = main(str(entrada), "json")
    capturado = capsys.readouterr()
    mensagem = capturado.err

    assert capturado.out == ""
    assert codigo == 1
    assert "Erro ao ler arquivo" in mensagem
    assert str(entrada) in mensagem


def test_extrair_urls_continua_apos_url_malformada():
    conteudo = (
        "https://example.com/antes "
        "https://[broken "
        "https://example.org/depois"
    )

    urls, invalidas = extrair_urls(conteudo)

    assert urls == [
        "https://example.com/antes",
        "https://example.org/depois",
    ]
    assert invalidas == ["https://[broken"]


def test_extrair_urls_com_esquema_em_maiusculas():
    urls, invalidas = extrair_urls(
        "HTTP://example.com/Antes HTTPS://example.org/Depois"
    )

    assert urls == [
        "HTTP://example.com/Antes",
        "HTTPS://example.org/Depois",
    ]
    assert invalidas == []


def test_extrair_urls_rejeita_portas_invalidas():
    urls, invalidas = extrair_urls(
        "https://example.com:8443/ok "
        "https://example.com:99999/fora "
        "https://example.com:abc/texto"
    )

    assert urls == ["https://example.com:8443/ok"]
    assert invalidas == [
        "https://example.com:99999/fora",
        "https://example.com:abc/texto",
    ]


def test_normalizar_hashes_preserva_entrada_e_duplicatas():
    original = [
        "5D41402ABC4B2A76B9719D911017C592",
        "5d41402abc4b2a76b9719d911017c592",
    ]
    copia = original.copy()

    normalizados = normalizar_hashes(original)

    assert normalizados == [
        "5d41402abc4b2a76b9719d911017c592",
        "5d41402abc4b2a76b9719d911017c592",
    ]
    assert original == copia
    assert normalizados is not original


def test_normalizar_hashes_lista_vazia():
    assert normalizar_hashes([]) == []


def test_normalizar_resultados():
    original = {
        "md5": ["5D41402ABC4B2A76B9719D911017C592"],
        "sha1": ["DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"],
        "sha256": [
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        ],
        "urls": ["https://example.com/Antes"],
        "ipv4": [],
    }
    copia = {tipo: valores.copy() for tipo, valores in original.items()}

    normalizados = normalizar_resultados(original)

    for tipo in ("md5", "sha1", "sha256"):
        assert normalizados[tipo] == [original[tipo][0].lower()]

    assert normalizados["urls"] == original["urls"]
    assert normalizados["ipv4"] == []
    assert original == copia
    assert normalizados is not original

    for tipo in original:
        assert normalizados[tipo] is not original[tipo]


def test_normalizar_resultados_vazios():
    assert normalizar_resultados({}) == {}


def test_comparar_valores():
    valores_a = ["b", "a", "b"]
    valores_b = ["c", "b"]

    resultado = comparar_valores(valores_a, valores_b)

    assert resultado == {
        "comuns": ["b"],
        "somente_a": ["a"],
        "somente_b": ["c"],
    }
    assert valores_a == ["b", "a", "b"]
    assert valores_b == ["c", "b"]


def test_comparar_valores_ordena_resultados():
    resultado = comparar_valores(
        ["z", "b", "a", "d"],
        ["y", "d", "b", "c"],
    )

    assert resultado == {
        "comuns": ["b", "d"],
        "somente_a": ["a", "z"],
        "somente_b": ["c", "y"],
    }


def test_comparar_valores_com_lista_vazia():
    assert comparar_valores([], ["b", "a"]) == {
        "comuns": [],
        "somente_a": [],
        "somente_b": ["a", "b"],
    }


def test_comparar_valores_ambas_vazias():
    assert comparar_valores([], []) == {
        "comuns": [],
        "somente_a": [],
        "somente_b": [],
    }


def test_comparar_resultados_normaliza_hashes():
    hash_original = "5D41402ABC4B2A76B9719D911017C592"
    resultados_a = {
        "md5": [hash_original],
        "ipv4": ["192.0.2.10"],
        "urls_falsos_candidatos": ["https://[broken"],
    }
    resultados_b = {
        "md5": [hash_original.lower()],
        "dominios": ["example.com"],
    }

    comparacao = comparar_resultados(resultados_a, resultados_b)

    assert comparacao["md5"] == {
        "comuns": [hash_original.lower()],
        "somente_a": [],
        "somente_b": [],
    }
    assert comparacao["ipv4"] == {
        "comuns": [],
        "somente_a": ["192.0.2.10"],
        "somente_b": [],
    }
    assert comparacao["dominios"] == {
        "comuns": [],
        "somente_a": [],
        "somente_b": ["example.com"],
    }
    assert comparacao["urls"] == {
        "comuns": [],
        "somente_a": [],
        "somente_b": [],
    }
    assert "urls_falsos_candidatos" not in comparacao
    assert resultados_a["md5"] == [hash_original]


def test_comparar_resultados_vazios():
    comparacao = comparar_resultados({}, {})

    assert set(comparacao) == {
        "ipv4", "ipv6", "md5", "sha1", "sha256",
        "cves", "urls", "emails", "dominios",
    }
    for resultado in comparacao.values():
        assert resultado == {
            "comuns": [],
            "somente_a": [],
            "somente_b": [],
        }


def test_comparar_resultados_normaliza_dominios():
    resultados_a = {"dominios": ["Example.COM", "Example.COM"]}
    resultados_b = {"dominios": ["example.com", "outro.example"]}

    comparacao = comparar_resultados(resultados_a, resultados_b)

    assert comparacao["dominios"] == {
        "comuns": ["example.com"],
        "somente_a": [],
        "somente_b": ["outro.example"],
    }
    assert resultados_a["dominios"] == ["Example.COM", "Example.COM"]
    assert resultados_b["dominios"] == ["example.com", "outro.example"]