from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import ssl
import socket
import time
import whois
from urllib.parse import urlparse
import datetime
import json
import os
from datetime import datetime
import feedparser
import re
import html
import threading
from playwright.sync_api import sync_playwright
from functools import lru_cache
import dns.resolver
import base64
import tempfile
import mimetypes


app = Flask(__name__)
CORS(app)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")



ARQUIVO_HISTORICO = "historico_uptime.json"




def extrair_links(texto):
    padrao = r'https?://[^\s<>"\']+'
    return re.findall(padrao, texto)

def verificar_links_suspeitos(links):
    encurtadores = ["bit.ly", "tinyurl", "t.co", "ow.ly", "goo.gl", "buff.ly", "is.gd"]
    resultados = []
    for link in links:
        try:
            r = requests.head(link, allow_redirects=True, timeout=5)
            final_url = r.url
        except:
            final_url = link  # Se não conseguir seguir, mantém o original

        dominio = urlparse(final_url).netloc
        status = "aprovado"

        if any(e in dominio for e in encurtadores):
            status = "suspeito"

        elif "://" not in final_url or len(final_url) > 200:
            status = "suspeito"

        elif not re.match(r"https?://", final_url):
            status = "reprovado"

        resultados.append({
            "link": link,
            "final_url": final_url,
            "dominio": dominio,
            "status": status
        })

    return resultados

@app.route("/api/heatmap")
def heatmap():
    if not os.path.exists(ARQUIVO_HISTORICO):
        return jsonify({})

    with open(ARQUIVO_HISTORICO, "r") as f:
        historico = json.load(f)

    dados_heatmap = {}
    for site, registros in historico.items():
        dados_heatmap[site] = [
            {"hora": r["hora"][-5:], "status": r["status"]}  # Pega só HH:MM
            for r in registros[-24:]  # últimas 24 horas
        ]

    return jsonify(dados_heatmap)


@app.route("/api/dashboard")
def dashboard():
    if not os.path.exists(ARQUIVO_HISTORICO):
        return jsonify({"labels": [], "uptime": [], "alertas": []})

    with open(ARQUIVO_HISTORICO, "r") as f:
        historico = json.load(f)

    labels = []
    uptimes = []
    alertas = []

    for site, entradas in historico.items():
        total = len(entradas)
        online = sum(1 for e in entradas if e["status"] in ["online", "estável"])
        uptime_percent = round((online / total) * 100, 2) if total else 0

        labels.append(site.capitalize())
        uptimes.append(uptime_percent)

        # Pega os 3 últimos problemas
        for e in entradas[-3:]:
            if e["status"] not in ["online", "estável"]:
                alertas.append({"site": site.capitalize(), "tipo": e["status"], "hora": e["hora"]})

    return jsonify({
        "labels": labels,
        "uptime": uptimes,
        "alertas": sorted(alertas, key=lambda x: x["hora"], reverse=True)[:5]
    })



@app.route("/api/noticias")
def noticias():
    feeds = [
        "https://g1.globo.com/rss/g1/tecnologia/",
        "https://www.tecmundo.com.br/rss",
        "https://olhardigital.com.br/feed/"
    ]

    palavras_chave = [
        "tecnologia", "segurança", "rede", "ciber", "internet", "whatsapp",
        "google", "instagram", "falha", "hacker", "cursos", "bolsas",
        "programação", "cloud", "cibersegurança", "dados", "ataque",
        "cibernético", "privacidade", "criptografia", "firewall", "vpn",
        "sinal", "5g", "computador", "notebook", "dispositivo", "android",
        "ios", "windows", "excel", "dica", "informática", "manutenção"
    ]

    palavras_proibidas = [
        "sexo", "adulto", "casamento", "pastor", "bezos", "atriz", "namoro",
        "celebridade", "relacionamento", "moda", "famoso", "fofoca", "casal",
        "apostas",

    ]

    noticias_filtradas = []
    titulos_usados = set()
    urls_usadas = set()

    for feed_url in feeds:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries:
            titulo_raw = entry.title.strip()
            titulo = titulo_raw.lower()
            resumo = html.unescape(entry.summary.lower()) if 'summary' in entry else ""
            link = entry.link.strip()

            if link in urls_usadas or titulo in titulos_usados:
                continue

            if any(p in titulo or p in resumo for p in palavras_proibidas):
                continue

            if not any(p in titulo or p in resumo for p in palavras_chave):
                continue

            imagem = "https://placehold.co/300x150?text=Noticia"
            if "media_content" in entry:
                imagem_url = entry.media_content[0].get('url', '')
                if any(x in imagem_url.lower() for x in ["adult", "nsfw", "sexy", "porn"]):
                    continue
                imagem = imagem_url

            noticias_filtradas.append({
                "titulo": titulo_raw,
                "link": link,
                "resumo": re.sub('<[^<]+?>', '', resumo)[:100] + "...",
                "imagem": imagem
            })

            titulos_usados.add(titulo)
            urls_usadas.add(link)

            if len(noticias_filtradas) >= 15:
                break
        if len(noticias_filtradas) >= 15:
            break

    return jsonify(noticias_filtradas)



def verificar_selos_visuais(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10000)

            page.wait_for_timeout(3000)  # aguarda o carregamento
            html = page.content().lower()

            # Termos relacionados a selos ou certificados comuns
            termos_chave = [
                "site seguro", "norton", "mcafee", "certificado ssl", "seguro", "ssl", "comodo",
                "certisign", "digicert", "selo de segurança", "geotrust", "security badge"
            ]

            encontrados = [t for t in termos_chave if t in html]

            browser.close()

            if encontrados:
                return "Selo de segurança visual detectado: " + ", ".join(encontrados), "aprovado"
            else:
                return "Nenhum selo visual encontrado na interface", "suspeito"

    except Exception as e:
        return f"Erro ao verificar selos visuais: {str(e)}", "suspeito"

def limpar_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url

def extrair_protocolo(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme.upper() if parsed.scheme else "DESCONHECIDO"
    except:
        return "DESCONHECIDO"

def verificar_certificado_ssl(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tipo = "Desconhecido"
                emissor = ""
                if cert:
                    assunto = dict(x[0] for x in cert.get("subject", []))
                    emissor_info = dict(x[0] for x in cert.get("issuer", []))
                    emissor = emissor_info.get("organizationName", "Desconhecido")

                    if "Let's Encrypt" in emissor:
                        tipo = "DV SSL"
                    elif "GlobalSign" in emissor:
                        tipo = "OV SSL"
                    elif "DigiCert" in emissor:
                        tipo = "EV SSL"
                    elif "Google Trust" in emissor:
                        tipo = "OV SSL"
                return f"Emitido por {emissor} ({tipo})", "aprovado" if tipo != "Desconhecido" else "suspeito"
    except:
        return "Não encontrado ou inválido", "reprovado"

def verificar_selos_visuais(url):
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=5000)
            page.wait_for_timeout(3000)
            html = page.content().lower()

            termos_chave = [
                "site seguro", "norton", "mcafee", "certificado ssl", "seguro", "ssl", "comodo",
                "certisign", "digicert", "selo de segurança", "geotrust", "security badge"
            ]
            encontrados = [t for t in termos_chave if t in html]

            browser.close()

            if encontrados:
                return "Selo de segurança visual detectado: " + ", ".join(encontrados), "aprovado"
            else:
                return "Nenhum selo visual encontrado na interface", "suspeito"
    except Exception as e:
        return f"Erro ao verificar selos visuais: {str(e)}", "suspeito"

def verificar_selos(hostname):
    try:
        url = f"https://{hostname}"
        return verificar_selos_visuais(url)
    except:
        return "Erro ao tentar verificar visualmente o site", "suspeito"

def verificar_reputacao_virustotal(hostname):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{hostname}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            reputation = data["data"]["attributes"].get("reputation", 0)
            total_votes = data["data"]["attributes"].get("total_votes", {})

            if reputation > 0 or total_votes.get("harmless", 0) > total_votes.get("malicious", 0):
                return "Alta reputação (segundo VirusTotal)", "aprovado"
            elif reputation < 0 or total_votes.get("malicious", 0) > total_votes.get("harmless", 0):
                return "Risco detectado (VirusTotal)", "reprovado"
            else:
                return "Reputação neutra/limitada", "suspeito"
        else:
            return "Erro ao consultar VirusTotal", "suspeito"
    except:
        return "Falha na análise de reputação", "suspeito"

def verificar_ameacas_virustotal(hostname):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{hostname}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            last_analysis = data["data"]["attributes"].get("last_analysis_stats", {})

            if last_analysis.get("malicious", 0) > 0:
                return f"Detectado malware ou phishing ({last_analysis['malicious']} fontes)", "reprovado"
            elif last_analysis.get("suspicious", 0) > 0:
                return f"Possível risco ({last_analysis['suspicious']} fontes)", "suspeito"
            else:
                return "Nenhuma ameaça detectada", "aprovado"
        else:
            return "Erro na checagem de ameaças", "suspeito"
    except:
        return "Falha ao verificar ameaças", "suspeito"

@app.route("/api/analisar_link", methods=["POST"])
def analisar_link():
    data = request.get_json()
    url = limpar_url(data.get("url", ""))
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    protocolo = extrair_protocolo(url)
    certificado, status_cert = verificar_certificado_ssl(hostname)
    selos, status_selos = verificar_selos(hostname)
    reputacao, status_rep = verificar_reputacao_virustotal(hostname)
    ameacas, status_ameacas = verificar_ameacas_virustotal(hostname)

    resposta = {
        "itens": [
            {"titulo": "1. Protocolo", "valor": protocolo, "status": "aprovado" if protocolo == "HTTPS" else "suspeito"},
            {"titulo": "2. Certificado SSL", "valor": certificado, "status": status_cert},
            {"titulo": "3. Selos de Segurança", "valor": selos, "status": status_selos},
            {"titulo": "4. Reputação do Site", "valor": reputacao, "status": status_rep},
            {"titulo": "5. Ameaças Possíveis", "valor": ameacas, "status": status_ameacas}
        ]
    }

    # Validação manual adicional
    sites_confiaveis = ["jw.org", "gov.br", "bcb.gov.br", "camara.leg.br","senado.leg.br", "receita.fazenda.gov.br","justica.gov.br", "caixa.gov.br","bancobrasil.com.br", "bradesco.com.br",
                        "itau.com.br","santander.com.br","nubank.com.br","picpay.com", "microsoft.com", "apple.com","cloudflare.com", "youtube.com.br","bookplay.com.br",]
    status_geral = "dinamico"

    if hostname in sites_confiaveis:
        for item in resposta["itens"]:
            item["status"] = "aprovado"
        status_geral = "aprovado"

    resposta["status_geral"] = status_geral
    return jsonify(resposta)



@app.route("/")
def raiz():
    return "API WebPulse está online."

site_map = {
    "whatsapp": {"dominio": "web.whatsapp.com", "categoria": "Redes Sociais"},
    "google": {"dominio": "google.com", "categoria": "Busca"},
    "youtube": {"dominio": "youtube.com", "categoria": "Streaming"},
    "facebook": {"dominio": "facebook.com", "categoria": "Redes Sociais"},
    "instagram": {"dominio": "instagram.com", "categoria": "Redes Sociais"},
    "itau": {"dominio": "itau.com.br", "categoria": "Bancos"},
    "nubank": {"dominio": "nubank.com.br", "categoria": "Bancos"},
    "vivo": {"dominio": "vivo.com.br", "categoria": "Provedores"},
    "claro": {"dominio": "claro.com.br", "categoria": "Provedores"},
    "caixa": {"dominio": "caixa.gov.br", "categoria": "Governamentais"},
    "amazon": {"dominio": "amazon.com.br", "categoria": "Busca"},
    "bancodobrasil": {"dominio": "bb.com.br", "categoria": "Bancos"},
    "tim": {"dominio": "tim.com.br", "categoria": "Provedores"},
    "correios": {"dominio": "correios.com.br", "categoria": "Governamentais"},
    "santander": {"dominio": "santander.com.br", "categoria": "Bancos"},
    "bancocentraldobrasil": {"dominio": "bcb.gov.br", "categoria": "Bancos"},
    "mercadolivre": {"dominio": "mercadolivre.com.br", "categoria": "Bancos"},
    "uol": {"dominio": "uol.com.br", "categoria": "Buscas"},
    "bradesco": {"dominio": "bradesco.com.br", "categoria": "Bancos"},
    "picpay": {"dominio": "picpay.com.br", "categoria": "Bancos"},
    }

status_cor = {
    "online": "green",
    "estável": "green",
    "instável": "orange",
    "lento": "purple",
    "offline": "red"
}


def coletar_dado_real(site):
    try:
        inicio = time.time()
        r = requests.get(f'https://{site}', timeout=5)
        tempo = round((time.time() - inicio) * 1000)  # em milissegundos
        return tempo
    except:
        return 0  # ou um valor que represente falha


status_historico = {}  # fora da função


def medir_latencia(host, port=443):
    try:
        inicio = time.time()
        socket.create_connection((host, port), timeout=10)
        fim = time.time()
        return round((fim - inicio) * 1000)  # latência em ms
    except:
        return None  # não respondeu

@app.route('/api/status_sites')
def status_sites():
    status = {}

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    }

    for site, dominio in site_map.items():
        try:
            inicio = time.time()
            dominio_str = dominio["dominio"]
            dominio_host = dominio_str.replace("https://", "").replace("http://", "").split("/")[0]
            latencia = medir_latencia(dominio_host)
            resp = requests.get(f'https://{dominio_str}', timeout=15, headers=headers, allow_redirects=True)
            tempo = time.time() - inicio

            if latencia is None and tempo >= 15:
                nivel = "offline"
            elif latencia is not None and latencia >= 300 and tempo >= 3.0:
                nivel = "lento"
            elif tempo >= 3:
                nivel = "lento"
            elif tempo >= 1.5:
                nivel = "estável"
            elif tempo >= 0.5:
                nivel = "online"
            else:
                nivel = "online"

        except requests.exceptions.RequestException:
            nivel = "offline"
            tempo = 0


        historico = status_historico.get(site, [])
        historico.append(nivel)
        if len(historico) > 5:
            historico.pop(0)

        # se os últimos status forem muito variados, considerar instável
        if len(set(historico)) >= 3:
            nivel = "instável"

        status_historico[site] = historico

        status[site] = {
            "status": nivel,
            "cor": status_cor.get(nivel, "green"),
            "tempo_ms": round(tempo * 1000),
            "latencia_ms": latencia if latencia is not None else -1
        }

    return jsonify(status)



@app.route('/api/dados_site/<site>')
def dados_site(site):
    dominio = site_map.get(site.lower())
    if not dominio:
        return jsonify([]), 404
    try:
        inicio = time.time()
        r = requests.get(f'https://{dominio}', timeout=5)
        tempo_ms = round((time.time() - inicio) * 1000)
        return jsonify([tempo_ms])
    except:
        return jsonify([0])
    




def salvar_historico_periodicamente():
    with app.app_context():
        client = app.test_client()
        while True:
            resposta = client.get("/api/status_sites")
            status = resposta.get_json()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
            dados = {}

            if os.path.exists(ARQUIVO_HISTORICO):
                with open(ARQUIVO_HISTORICO, "r") as f:
                    dados = json.load(f)

            for site, info in status.items():
                if site not in dados:
                    dados[site] = []
                dados[site].append({"hora": timestamp, "status": info["status"]})

            with open(ARQUIVO_HISTORICO, "w") as f:
                json.dump(dados, f, indent=2)

            time.sleep(3600)
threading.Thread(target=salvar_historico_periodicamente, daemon=True).start()

@lru_cache(maxsize=100)
def cachear_resultado(url):
    return url

@app.route("/api/analisar_email", methods=["POST"])
def analisar_email():
    dados = request.get_json()
    conteudo = dados.get("conteudo", "").lower()
    remetente = dados.get("remetente", "").lower()

    codigo_curto = re.search(r'\b(\d{4,8})\b', conteudo)
    pouco_texto = len(conteudo.strip()) < 150
    sem_links = not extrair_links(conteudo)

# ⚠️ CASO ESPECIAL DE AUTENTICAÇÃO
    if codigo_curto and pouco_texto and sem_links:
        dominio_2fa = remetente.split("@")[-1]
        confiaveis_2fa = ["fortinet.com", "fortinet.net", "notification.fortinet.net"]
        if dominio_2fa in confiaveis_2fa or dominio_2fa.endswith(".fortinet.net"):
            return jsonify({
                "itens": [
                    {
                        "titulo": "Código de Verificação",
                        "valor": f"Código detectado: {codigo_curto.group(1)}. Nenhum link ou conteúdo suspeito identificado.",
                        "status": "aprovado"
                    },
                    {
                        "titulo": "Veredito Final",
                        "valor": "E-mail legítimo de autenticação (2FA) validado.",
                        "status": "aprovado"
                    }
            ]
        })

    itens = []
    score = 0


    # Detectar palavras suspeitas
    palavras_suspeitas = [
        "ganhou", "senha", "urgente", "clique", "premio", "fatura", "cancelar", 
        "acesso bloqueado", "recompensa", "recuperar", "verificar", "confirmar", 
        "erro", "atualização obrigatória", "nova política"
    ]
    encontradas = [p for p in palavras_suspeitas if p in conteudo]
    if encontradas:
        score -= 2
        itens.append({
            "titulo": "Conteúdo Suspeito",
            "valor": f"Palavras detectadas: {', '.join(encontradas)}",
            "status": "suspeito"
        })

    # 2. Remetente confiável
    dominio = remetente.split("@")[-1]
    confiaveis = [
        "gmail.com", "outlook.com", "hotmail.com", "icloud.com", "yahoo.com", "protonmail.com",
        "jw.org", "gov.br", "vivo.com.br", "claro.com.br", "itau.com.br", "caixa.gov.br", 
        "bradesco.com.br", "santander.com.br", "bcb.gov.br", "serpro.gov.br", "fortinet.com", "fortinet.net"
    ]
    if dominio in confiaveis:
        score += 2
        itens.append({
            "titulo": "Remetente Confiável",
            "valor": f"Domínio do e-mail ({dominio}) é comum e confiável.",
            "status": "aprovado"
        })
    else:
        score -= 1
        itens.append({
            "titulo": "Remetente Desconhecido",
            "valor": f"Domínio {dominio} não é da lista confiável.",
            "status": "suspeito"
        })


    # 3. Autenticações SPF/DKIM/DMARC
    try:
        resultados_auth = verificar_spf_dkim_dmarc(dominio)
        for titulo, status in resultados_auth:
            if status == "aprovado":
                score += 1
            else:
                score -= 1
            itens.append({
                "titulo": f"Autenticação: {titulo}",
                "valor": dominio,
                "status": status
            })
    except:
        score -= 2
        itens.append({
            "titulo": "Erro na verificação SPF/DKIM/DMARC",
            "valor": remetente,
            "status": "suspeito"
        })


    # 4. Links
    links = extrair_links(conteudo)
    for i, resultado in enumerate(verificar_links_suspeitos(links), start=1):
        status = resultado["status"]
        if status == "reprovado":
            score -= 3
        elif status == "suspeito":
            score -= 1
        else:
            score += 1
        itens.append({
            "titulo": f"Link #{i}",
            "valor": f"{resultado['link']} → {resultado['final_url']}",
            "status": status
        })

        # 5. Anexos em base64 (já retorna com título, status, valor)
    for anexo in analisar_anexos_base64(conteudo):
        if anexo["status"] == "reprovado":
            score -= 3
        elif anexo["status"] == "suspeito":
            score -= 1
        else:
            score += 1
        itens.append(anexo)
    

    # Avaliação final com base nos itens analisados
    aprovado = sum(1 for item in itens if item["status"] == "aprovado")
    suspeito = sum(1 for item in itens if item["status"] == "suspeito")
    reprovado = sum(1 for item in itens if item["status"] == "reprovado")

    total = aprovado + suspeito + reprovado

    # Caso especial: e-mail com código, pouco texto e sem links — e score neutro ou positivo
    if codigo_curto and pouco_texto and sem_links and score >= 0:
        status_final = "aprovado"
        mensagem = "E-mail de autenticação simples com boas práticas. Verificação bem-sucedida."
    elif score <= -2:
        status_final = "reprovado"
        mensagem = "O e-mail apresenta riscos claros e não é confiável."
    elif score <= 0:
        status_final = "suspeito"
        mensagem = "O e-mail contém sinais de alerta. Requer atenção."
    else:
        status_final = "aprovado"
        mensagem = "O e-mail aparenta ser seguro com base nos fatores avaliados."


    itens.append({
        "titulo": "Veredito Final",
        "valor": mensagem,
        "status": status_final
    })

    

    return jsonify({"itens": itens})




def dominio_tem_mx(dominio):
    try:
        resposta = dns.resolver.resolve(dominio, 'MX')
        return True if resposta else False
    except:
        return False

def verificar_links_virus_total(links):
    resultados = []
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    for link in links[:3]:  # Limita para não sobrecarregar
        scan_url = "https://www.virustotal.com/api/v3/urls"
        encoded = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        consulta = f"https://www.virustotal.com/api/v3/urls/{encoded}"

        resp = requests.get(consulta, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats.get("malicious", 0) > 0:
                resultados.append((link, "malicioso"))
            elif stats.get("suspicious", 0) > 0:
                resultados.append((link, "suspeito"))

    return resultados    

def extrair_anexos_base64(conteudo_email):
    anexos = []
    blocos = conteudo_email.split("Content-Disposition: attachment")

    for bloco in blocos[1:]:
        try:
            nome_linha = re.search(r'filename="([^"]+)"', bloco)
            nome = nome_linha.group(1) if nome_linha else "anexo_desconhecido"

            base64_dados = re.search(r'base64\\s+(.*?)\\s*(?:\\n--|$)', bloco, re.DOTALL)
            if not base64_dados:
                continue

            conteudo_b64 = base64_dados.group(1).strip()
            arquivo_bytes = base64.b64decode(conteudo_b64)

            if len(arquivo_bytes) > 32 * 1024 * 1024:
                anexos.append({"nome": nome, "veredito": "Arquivo ignorado (excede 32MB)"})
                continue

            caminho = os.path.join(tempfile.gettempdir(), nome)
            with open(caminho, "wb") as f:
                f.write(arquivo_bytes)

            resultado = verificar_arquivo_virustotal(caminho)
            anexos.append({"nome": nome, "veredito": resultado})
        except Exception as e:
            anexos.append({"nome": "Erro ao processar anexo", "veredito": str(e)})

    
    return anexos

def verificar_arquivo_virustotal(caminho_arquivo):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        with open(caminho_arquivo, "rb") as f:
            files = {"file": (os.path.basename(caminho_arquivo), f)}
            envio = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

        if envio.status_code == 200:
            file_id = envio.json()["data"]["id"]
            resultado = requests.get(f"https://www.virustotal.com/api/v3/files/{file_id}", headers=headers)
            if resultado.status_code == 200:
                stats = resultado.json()["data"]["attributes"]["last_analysis_stats"]
                maliciosos = stats.get("malicious", 0)
                if maliciosos > 0:
                    nomes = resultado.json()["data"]["attributes"].get("popular_threat_classification", {})
                    return f"Malware detectado: {nomes.get('suggested_threat_label', 'Desconhecido')}"
                else:
                    return "Sem ameaça detectada"
        return "Erro na análise do VirusTotal"
    except Exception as e:
        return f"Erro: {str(e)}"

def verificar_reputacao_ip(remetente):
    try:
        dominio = remetente.split("@")[-1]
        ip = socket.gethostbyname(dominio)

        reversed_ip = ".".join(reversed(ip.split(".")))
        blacklist_dns = "zen.spamhaus.org"
        consulta = f"{reversed_ip}.{blacklist_dns}"

        try:
            dns.resolver.resolve(consulta, "A")
            return f"IP {ip} listado em blacklist (Spamhaus)", "reprovado"
        except dns.resolver.NXDOMAIN:
            return f"IP {ip} não listado em blacklist", "aprovado"
        except Exception:
            return f"Falha ao consultar blacklist para {ip}", "suspeito"

    except Exception as e:
        return f"Erro ao verificar IP do remetente: {str(e)}", "suspeito"


def verificar_spf_dkim_dmarc(dominio):
    resultado = []

    # SPF
    try:
        spf_txts = dns.resolver.resolve(dominio, 'TXT')
        spf_ok = any("v=spf1" in str(r) for r in spf_txts)
        if spf_ok:
            resultado.append(("SPF encontrado", "aprovado"))
        else:
            resultado.append(("SPF não encontrado", "suspeito"))
    except:
        resultado.append(("Erro ao verificar SPF", "suspeito"))

    # DKIM (checagem genérica)
    try:
        dkim_selector = "default._domainkey." + dominio
        dkim_txts = dns.resolver.resolve(dkim_selector, 'TXT')
        dkim_ok = any("v=DKIM1" in str(r) for r in dkim_txts)
        if dkim_ok:
            resultado.append(("DKIM encontrado (default)", "aprovado"))
        else:
            resultado.append(("DKIM não encontrado (default)", "suspeito"))
    except:
        resultado.append(("Erro ao verificar DKIM (default)", "suspeito"))

    # DMARC
    try:
        dmarc_txts = dns.resolver.resolve("_dmarc." + dominio, 'TXT')
        dmarc_ok = any("v=DMARC1" in str(r) for r in dmarc_txts)
        if dmarc_ok:
            resultado.append(("DMARC encontrado", "aprovado"))
        else:
            resultado.append(("DMARC não encontrado", "suspeito"))
    except:
        resultado.append(("Erro ao verificar DMARC", "suspeito"))

    return resultado

def identificar_tipo_arquivo(bin_data):
    if bin_data.startswith(b'%PDF'):
        return "PDF", "suspeito"
    elif bin_data.startswith(b'PK\x03\x04'):
        return "ZIP", "suspeito"
    elif bin_data.startswith(b'MZ'):
        return "Executável (.exe)", "reprovado"
    elif bin_data.startswith(b'\x89PNG'):
        return "Imagem PNG", "aprovado"
    elif bin_data.startswith(b'\xff\xd8\xff'):
        return "Imagem JPEG", "aprovado"
    elif bin_data.startswith(b'GIF87a') or bin_data.startswith(b'GIF89a'):
        return "Imagem GIF", "aprovado"
    else:
        return "Arquivo desconhecido", "suspeito"


def analisar_anexos_base64(conteudo):
    import re
    itens = []

    padrao_base64 = re.findall(r'([A-Za-z0-9+/=\s]{300,})', conteudo)

    for possivel in padrao_base64:
        possivel = possivel.replace("\n", "").replace(" ", "")

        try:
            bin_data = base64.b64decode(possivel, validate=True)
            if len(bin_data) < 5000:
                continue  # muito pequeno, provavelmente ícone/logo

            tipo, status = identificar_tipo_arquivo(bin_data)
            tamanho_kb = round(len(bin_data) / 1024, 1)

            itens.append({
                "titulo": f"Anexo {tipo} Detectado",
                "valor": f"Arquivo em base64 embutido. Tamanho estimado: {tamanho_kb} KB.",
                "status": status
            })

        except Exception:
            continue  # não é base64 válido, ignora

    return itens

def verificar_spf_dmarc(dominio):
    resultados = []
    try:
        # SPF
        spf_txts = dns.resolver.resolve(dominio, 'TXT')
        tem_spf = any('v=spf1' in r.to_text() for r in spf_txts)
        resultados.append(("SPF", "aprovado" if tem_spf else "suspeito"))
    except:
        resultados.append(("SPF", "suspeito"))

    try:
        # DMARC
        dmarc_domain = f"_dmarc.{dominio}"
        dmarc_txts = dns.resolver.resolve(dmarc_domain, 'TXT')
        tem_dmarc = any('v=DMARC1' in r.to_text() for r in dmarc_txts)
        resultados.append(("DMARC", "aprovado" if tem_dmarc else "suspeito"))
    except:
        resultados.append(("DMARC", "suspeito"))

    return resultados


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)