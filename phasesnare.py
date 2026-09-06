import argparse
import ipaddress
import re
import json
from urllib.parse import urlparse

def extrair_ipv4(conteudo):
        # Extração de possíveis endereços IPv4 usando regex
    ipv4_candidatos = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', conteudo)
    
    ipv4_lista = []
    ipv4_falsos_candidatos = []

        # Validação dos endereços IPv4 encontrados
    for ipv4 in ipv4_candidatos:
        try:
            ipaddress.IPv4Address(ipv4)
            ipv4_lista.append(ipv4)
        except ipaddress.AddressValueError:
            ipv4_falsos_candidatos.append(ipv4)

    return ipv4_lista, ipv4_falsos_candidatos


def extrair_ipv6(conteudo):
    ipv6_candidatos = re.findall(
        r'(?<![0-9A-Za-z:])(?:[0-9A-Za-z]{0,4}:){2,7}[0-9A-Za-z]{0,4}(?![0-9A-Za-z:])',
        conteudo
    )

    ipv6_candidatos = [
        candidato
        for candidato in ipv6_candidatos
        if "::" in candidato or candidato.count(":") == 7
    ]

    ipv6_lista = []
    ipv6_falsos_candidatos = []

    for ipv6 in ipv6_candidatos:
        try:
            ipaddress.IPv6Address(ipv6)
            ipv6_lista.append(ipv6)
        except ipaddress.AddressValueError:
            ipv6_falsos_candidatos.append(ipv6)

    return ipv6_lista, ipv6_falsos_candidatos


def extrair_sha256(conteudo):
    # Extração de hashes SHA-256 usando regex
    sha256_encontrados = re.findall(r'\b[a-fA-F0-9]{64}\b', conteudo)
    return sha256_encontrados


def extrair_cves(conteudo):
    # Extração de CVEs usando regex
    cves = re.findall(r'\bCVE-\d{4}-\d{4,}\b', conteudo, re.IGNORECASE)
    cves = [cve.upper() for cve in cves]
    return cves


def extrair_md5(conteudo):
    # Extração de hashes MD5 usando regex
    md5_encontrados = re.findall(r'\b[a-fA-F0-9]{32}\b', conteudo)
    return md5_encontrados


def extrair_sha1(conteudo):
    # Extração de hashes SHA-1 usando regex
    sha1_encontrados = re.findall(r'\b[a-fA-F0-9]{40}\b', conteudo)
    return sha1_encontrados


def extrair_urls(conteudo):
    # Extração de URLs usando regex e validado usando urllib
    urls_candidatos = re.findall(r'https?://[^\s"\'<>]+', conteudo)
    urls = []
    urls_falsos_candidatos = []
    for url in urls_candidatos:
        resultado = urlparse(url)
        if resultado.scheme in ("http", "https") and resultado.hostname:
            urls.append(url)
        else:
            urls_falsos_candidatos.append(url)
    return urls, urls_falsos_candidatos


def extrair_emails(conteudo):
    # Extração de e-mails usando regex
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b', conteudo)
    return emails


def extrair_dominios(conteudo):
    dominios = re.findall(
        r'(?i)(?<![a-z0-9._-])'
        r'([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*'
        r'\.[a-z]{2,63})'
        r'(?![a-z0-9_-])',
        conteudo
    )
    return dominios

def exibir_resultados(resultados):
    print("Resultados encontrados:\n")

    for ipv4 in resultados['ipv4']:
        print(f"Endereço IPv4 válido: {ipv4}")
    quantidade_ipv4 = len(resultados['ipv4'])
    print(f"\nQuantidade de endereços IPv4 válidos: {quantidade_ipv4}\n")

    for ipv4_falso in resultados['ipv4_falsos_candidatos']:
        print(f"Falso candidato a IPv4: {ipv4_falso}")
    quantidade_ipv4_falsos = len(resultados['ipv4_falsos_candidatos'])
    print(f"\nQuantidade de falsos candidatos a IPv4: {quantidade_ipv4_falsos}\n")

    for ipv6 in resultados['ipv6']:
        print(f"Endereço IPV6 válidos: {ipv6}")
    quantidade_ipv6 = len(resultados['ipv6'])
    print(f"\nQuantidade de endereços IPV6 válidos: {quantidade_ipv6}\n")

    for ipv6_falso in resultados['ipv6_falsos_candidatos']:
        print(f"Falso candidato a IPv6: {ipv6_falso}")
    quantidade_ipv6_falsos = len(resultados['ipv6_falsos_candidatos'])
    print(f"\nQuantidade de falsos candidatos a IPv6: {quantidade_ipv6_falsos}\n")

    for md5 in resultados['md5']:
        print(f"Hash MD5 encontrado: {md5}")
    quantidade_md5 = len(resultados['md5'])
    print(f"\nQuantidade de hashes MD5 encontrados: {quantidade_md5}\n")

    for sha256 in resultados['sha256']:
        print(f"Hash SHA-256 encontrado: {sha256}")
    quantidade_sha256 = len(resultados['sha256'])
    print(f"\nQuantidade de hashes SHA-256 encontrados: {quantidade_sha256}\n")

    for sha1 in resultados['sha1']:
        print(f"Hash SHA-1 encontrado: {sha1}")
    quantidade_sha1 = len(resultados['sha1'])
    print(f"\nQuantidade de hashes SHA-1 encontrados: {quantidade_sha1}\n")

    for cve in resultados['cves']:
        print(f"CVE encontrado: {cve}")
    quantidade_cves = len(resultados['cves'])
    quantidade_cves_unicos = len(set(resultados['cves']))
    print(f"\nQuantidade de CVEs encontrados: {quantidade_cves}")
    print(f"Quantidade de CVEs únicos encontrados: {quantidade_cves_unicos}\n")

    for url in resultados['urls']:
        print(f'URL encontrada: {url}')
    quantidade_urls = len(resultados['urls'])
    print(f"\nQuantidade de URLs encontradas: {quantidade_urls}\n")

    for url_falsa in resultados['urls_falsos_candidatos']:
        print(f"Possível URL inválida encontrada: {url_falsa}")
    quantidade_urls_falsas = len(resultados['urls_falsos_candidatos'])
    print(f"\nQuantidade de URLs invalidadas encontradas e separadas: {quantidade_urls_falsas}\n")

    for email in resultados['emails']:
        print(f"E-mail encontrado: {email}")
    quantidade_emails = len(resultados['emails'])
    print(f"\nQuantidade de E-mails encontrados: {quantidade_emails}")

    for dominio in resultados['dominios']:
        print(f"Domínio encontrado: {dominio}")
    quantidade_dominios = len(resultados['dominios'])
    print(f"\nQuantidade de domínios encontrados: {quantidade_dominios}\n")


def deduplicar_resultados(resultados):
    resultados_unicos = {}

    for tipo, valores in resultados.items():
        resultados_unicos[tipo] = list(dict.fromkeys(valores))

    return resultados_unicos


def analisar_conteudo(conteudo):
    resultados = {
        "ipv4": [],
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
    
    resultados["ipv4"], resultados["ipv4_falsos_candidatos"] = extrair_ipv4(conteudo)
    resultados["ipv6"], resultados["ipv6_falsos_candidatos"] = extrair_ipv6(conteudo)
    resultados["md5"] = extrair_md5(conteudo)
    resultados["sha256"] = extrair_sha256(conteudo)    
    resultados["sha1"] = extrair_sha1(conteudo)
    resultados["cves"] = extrair_cves(conteudo)
    resultados["urls"], resultados["urls_falsos_candidatos"] = extrair_urls(conteudo)
    resultados["emails"] = extrair_emails(conteudo)
    resultados["dominios"] = extrair_dominios(conteudo)

    return resultados


def formatar_resultados_json(resultados):
    return json.dumps(resultados, indent=4, ensure_ascii=False)


def main(caminho_arquivo, formato, unique):
    try:
        with open(caminho_arquivo, 'r', encoding="utf-8") as arquivo_aberto:
            conteudo_arquivo = arquivo_aberto.read()
            caracteres = len(conteudo_arquivo)

        resultados = analisar_conteudo(conteudo_arquivo)

        if unique:
            resultados = deduplicar_resultados(resultados)

        if formato == 'json':
            print(formatar_resultados_json(resultados))
        elif formato == 'txt':
            print(f"O arquivo {caminho_arquivo} possui {caracteres} caracteres.\n")
            exibir_resultados(resultados)

    except FileNotFoundError:
        print(f"Erro: O arquivo '{caminho_arquivo}' não foi encontrado.")


def configurar_argumentos():
    parser = argparse.ArgumentParser(
        prog="phase-snare",
        description="Extrai Indicators of Compromise (IOCs) de arquivos de texto e logs."
    )

    parser.add_argument(
        "log_file",
        help="Caminho do arquivo de log a ser analisado."
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["txt", "json"],
        default="txt",
        help="Formato da saída. Padrão: txt."
    )

    parser.add_argument(
        "-u",
        "--unique",
        action="store_true",
        help="Remove indicadores duplicados da saída."
    )

    return parser.parse_args()

if __name__ == "__main__":
    args = configurar_argumentos()
    main(args.log_file, args.format, args.unique)


